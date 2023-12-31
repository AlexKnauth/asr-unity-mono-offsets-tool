//! Support for parsing MachO files

use asr::{Process, Address, signature::Signature};

use core::mem;

use crate::binary_format::DerefType;

// Magic mach-o header constants from:
// https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
const MH_MAGIC_32: u32 = 0xfeedface;
const MH_CIGAM_32: u32 = 0xcefaedfe;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;

const HEADER_SIZE: usize = 32;

struct MachOFormatOffsets {
    number_of_commands: usize,
    load_commands: usize,
    command_size: usize,
    symbol_table_offset: usize,
    number_of_symbols: usize,
    string_table_offset: usize,
    nlist_value: usize,
    size_of_nlist_item: usize,
}

impl MachOFormatOffsets {
    const fn new() -> Self {
        // offsets taken from:
        //  - https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MachOFormatOffsets.cs
        //  - https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
        MachOFormatOffsets {
            number_of_commands: 0x10,
            load_commands: 0x20,
            command_size: 0x04,
            symbol_table_offset: 0x08,
            number_of_symbols: 0x0c,
            string_table_offset: 0x10,
            nlist_value: 0x08,
            size_of_nlist_item: 0x10,
        }
    }
}

/// Scans the range for a page that begins with MachO Magic
pub fn scan_macho_page(process: &Process, range: (Address, u64)) -> Option<Address> {
    const PAGE_SIZE: u64 = 0x1000;
    let (addr, len) = range;
    // negation mod PAGE_SIZE
    let distance_to_page = (PAGE_SIZE - (addr.value() % PAGE_SIZE)) % PAGE_SIZE;
    // round up to the next multiple of PAGE_SIZE
    let first_page = addr + distance_to_page;
    for i in 0..((len - distance_to_page) / PAGE_SIZE) {
        let a = first_page + (i * PAGE_SIZE);
        match process.read::<u32>(a) {
            Ok(MH_MAGIC_64 | MH_CIGAM_64 | MH_MAGIC_32 | MH_CIGAM_32) => {
                return Some(a);
            }
            _ => ()
        }
    }
    None
}

pub fn detect_deref_type(process: &Process, module_range: (Address, u64)) -> Option<DerefType> {
    let magic_address = scan_macho_page(process, module_range)?;
    let magic: u32 = process.read(magic_address).ok()?;
    match magic {
        MH_MAGIC_64 | MH_CIGAM_64 => Some(DerefType::Bit64),
        MH_MAGIC_32 | MH_CIGAM_32 => Some(DerefType::Bit32),
        _ => None
    }
}


/// Finds the address of a function from a MachO module range and file contents.
pub fn get_function_address(process: &Process, range: (Address, u64), macho_bytes: &[u8], function_name: &[u8]) -> Option<Address> {
    asr::print_message("macho get_function_address: before scan_macho_page");
    let page = scan_macho_page(process, range)?;
    let header: [u8; HEADER_SIZE] = process.read(page).ok()?;
    let header_offset = memchr::memmem::find(macho_bytes, &header)?;
    let macho_bytes2 = &macho_bytes[header_offset..];
    asr::print_message("macho get_function_address: before get_function_offset");
    let function_offset: u32 = get_function_offset(&macho_bytes2, function_name)?;
    asr::print_message(&format!("macho get_function_address: function_offset: 0x{:X?}", function_offset));
    asr::print_message("macho get_function_address: before scan_macho_page");
    let function_address = page + function_offset;
    asr::print_message(&format!("macho get_function_address: function_address: {}", function_address));
    let actual: [u8; 0x100] = process.read(function_address).ok()?;
    let expected: [u8; 0x100] = slice_read(&macho_bytes2, function_offset as usize).ok()?;
    asr::print_message("macho get_function_address: before actual vs expected");
    if actual != expected {
        asr::print_message("BAD: actual != expected");
        let signature: Signature<0x100> = Signature::Simple(expected);
        let function_address_2 = signature.scan_process_range(process, range)?;
        asr::print_message(&format!("macho get_function_address: function_address_2: {}", function_address_2));
        return Some(function_address_2);
    }
    Some(function_address)
}

/// Finds the offset of a function in the bytes of a MachO file.
pub fn get_function_offset(macho_bytes: &[u8], function_name: &[u8]) -> Option<u32> {
    let macho_offsets = MachOFormatOffsets::new();
    let number_of_commands: u32 = slice_read(macho_bytes, macho_offsets.number_of_commands).ok()?;
    let function_name_len = function_name.len();

    let mut offset_to_next_command: usize = macho_offsets.load_commands as usize;
    for _i in 0..number_of_commands {
        // Check if load command is LC_SYMTAB
        let next_command: i32 = slice_read(macho_bytes, offset_to_next_command).ok()?;
        if next_command == 2 {
            let symbol_table_offset: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.symbol_table_offset).ok()?;
            let number_of_symbols: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.number_of_symbols).ok()?;
            let string_table_offset: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.string_table_offset).ok()?;

            for j in 0..(number_of_symbols as usize) {
                let symbol_name_offset: u32 = slice_read(macho_bytes, symbol_table_offset as usize + (j * macho_offsets.size_of_nlist_item)).ok()?;
                let string_offset = string_table_offset as usize + symbol_name_offset as usize;
                let symbol_name: &[u8] = &macho_bytes[string_offset..(string_offset + function_name_len + 1)];

                if symbol_name[function_name_len] == 0 && symbol_name.starts_with(function_name) {
                    return Some(slice_read(macho_bytes, symbol_table_offset as usize + (j * macho_offsets.size_of_nlist_item) + macho_offsets.nlist_value).ok()?);
                }
            }

            break;
        } else {
            let command_size: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.command_size).ok()?;
            offset_to_next_command += command_size as usize;
        }
    }
    None
}

/// Reads a value of the type specified from the slice at the address
/// given.
pub fn slice_read<T: bytemuck::CheckedBitPattern>(slice: &[u8], address: usize) -> Result<T, bytemuck::checked::CheckedCastError> {
    let size = mem::size_of::<T>();
    let slice_src = &slice[address..(address + size)];
    bytemuck::checked::try_from_bytes(slice_src).cloned()
}
