//! Support for parsing MachO files

use asr::{print_message, signature::Signature, string::ArrayCString, Address, PointerSize, Process};

use core::{
    iter,
    iter::FusedIterator,
    mem,
};

const CSTR: usize = 128;

// Magic mach-o header constants from:
// https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
const MH_MAGIC_32: u32 = 0xfeedface;
const MH_CIGAM_32: u32 = 0xcefaedfe;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;

// Constants for the cmd field of load commands, the type
// https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
/// link-edit stab symbol table info
/// see also symtab_command
const LC_SYMTAB: u32 = 0x2;
/// dynamic link-edit symbol table info
/// see also dysymtab_command
const LC_DYSYMTAB: u32 = 0xb;

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

/// A symbol exported into the current module.
pub struct Symbol {
    /// The address associated with the current function
    pub address: Address,
    /// The size occupied in memory by the current function
    pub size: u64,
    /// The address storing the name of the current function
    name_addr: Address,
}

impl Symbol {
    /// Tries to retrieve the name of the current function
    pub fn get_name<const CAP: usize>(
        &self,
        process: &Process,
    ) -> Result<ArrayCString<CAP>, asr::Error> {
        process.read(self.name_addr)
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

pub fn detect_pointer_size(process: &Process, module_range: (Address, u64)) -> Option<PointerSize> {
    let magic_address = scan_macho_page(process, module_range)?;
    let magic: u32 = process.read(magic_address).ok()?;
    match magic {
        MH_MAGIC_64 | MH_CIGAM_64 => Some(PointerSize::Bit64),
        MH_MAGIC_32 | MH_CIGAM_32 => Some(PointerSize::Bit32),
        _ => None
    }
}


pub fn get_function_symbol_address(process: &Process, range: (Address, u64), macho_bytes: &[u8], function_name: &[u8]) -> Option<Address> {
    let ma = get_function_address(process, range, macho_bytes, function_name);
    let mb = symbols(process, range).and_then(|mut ss| ss.find_map(|s| -> Option<Address> {
        let n = s.get_name::<CSTR>(process).ok()?;
        if n.matches(function_name) {
            Some(s.address)
        } else {
            None
        }
    }));
    match (ma, mb) {
        (Some(a), Some(b)) => {
            if a == b {
                asr::print_message(&format!("macho::get_function_symbol_address: all good, both Some and equal"));
            } else {
                asr::print_message(&format!("macho::get_function_symbol_address: mismatch, {} != {}", a, b));
            }
            Some(a)
        }
        (Some(a), None) => {
            asr::print_message("macho::get_function_symbol_address: only get_function_address worked");
            Some(a)
        }
        (None, Some(b)) => {
            asr::print_message("macho::get_function_symbol_address: only macho::symbols worked");
            Some(b)
        }
        (None, None) => {
            asr::print_message("macho::get_function_symbol_address: both failed");
            None
        }
    }
}

/// Finds the address of a function from a MachO module range and file contents.
pub fn get_function_address(process: &Process, range: (Address, u64), macho_bytes: &[u8], function_name: &[u8]) -> Option<Address> {
    // asr::print_message("macho get_function_address: before scan_macho_page");
    // NOTE: this page address is probably ONLY good for the header, NOT the function address
    let page = scan_macho_page(process, range)?;
    let header: [u8; HEADER_SIZE] = process.read(page).ok()?;
    let header_offset = memchr::memmem::find(macho_bytes, &header)?;
    let macho_bytes2 = &macho_bytes[header_offset..];
    // asr::print_message("macho get_function_address: before get_function_offset");
    let function_offset: u32 = get_function_offset(&macho_bytes2, function_name)?;
    // asr::print_message(&format!("macho get_function_address: function_offset: 0x{:X?}", function_offset));
    // NOTE: function_address_via_page is probably NOT the right address
    let function_address_via_page = page + function_offset;
    // asr::print_message(&format!("macho get_function_address: function_address_via_page: {}", function_address_via_page));
    let bytes_via_page: [u8; 0x100] = process.read(function_address_via_page).ok()?;
    let bytes_expected: [u8; 0x100] = slice_read(&macho_bytes2, function_offset as usize).ok()?;
    if bytes_via_page != bytes_expected {
        // asr::print_message("BAD: bytes_via_page != bytes_expected");
    }
    let signature: Signature<0x100> = Signature::Simple(bytes_expected);
    let function_address_expected = signature.scan_process_range(process, range)?;
    // asr::print_message(&format!("macho get_function_address: function_address_expected: {}", function_address_expected));
    Some(function_address_expected)
}

/// Finds the offset of a function in the bytes of a MachO file.
pub fn get_function_offset(macho_bytes: &[u8], function_name: &[u8]) -> Option<u32> {
    let macho_offsets = MachOFormatOffsets::new();
    let number_of_commands: u32 = slice_read(macho_bytes, macho_offsets.number_of_commands).ok()?;
    print_message(&format!("macho::get_function_offset: number_of_commands = {}", number_of_commands));
    let function_name_len = function_name.len();

    let mut offset_to_next_command: usize = macho_offsets.load_commands as usize;
    for i in 0..number_of_commands {
        // Check if load command is LC_SYMTAB
        let next_command: u32 = slice_read(macho_bytes, offset_to_next_command).ok()?;
        // print_message(&format!("macho::get_function_offset: next_command = {}", next_command));
        if next_command == LC_SYMTAB {
            print_message(&format!("macho::get_function_offset: found LC_SYMTAB at i = {}", i));
            let symbol_table_offset: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.symbol_table_offset).ok()?;
            let number_of_symbols: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.number_of_symbols).ok()?;
            let string_table_offset: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.string_table_offset).ok()?;
            print_message(&format!("macho::get_function_offset: symbol_table_offset = {}, number_of_symbols = {}, string_table_offset = {}", symbol_table_offset, number_of_symbols, string_table_offset));

            for j in 0..(number_of_symbols as usize) {
                let symbol_name_offset: u32 = slice_read(macho_bytes, symbol_table_offset as usize + (j * macho_offsets.size_of_nlist_item)).ok()?;
                let string_offset = string_table_offset as usize + symbol_name_offset as usize;
                let symbol_name: &[u8] = &macho_bytes[string_offset..(string_offset + function_name_len + 1)];

                if symbol_name[function_name_len] == 0 && symbol_name.starts_with(function_name) {
                    return Some(slice_read(macho_bytes, symbol_table_offset as usize + (j * macho_offsets.size_of_nlist_item) + macho_offsets.nlist_value).ok()?);
                }
            }
        } else if next_command == LC_DYSYMTAB {
            print_message(&format!("macho::get_function_offset: found LC_DYSYMTAB at i = {}", i));
        }
        let command_size: u32 = slice_read(macho_bytes, offset_to_next_command + macho_offsets.command_size).ok()?;
        offset_to_next_command += command_size as usize;
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

pub fn symbols(
    process: &Process,
    range: (Address, u64),
) -> Option<impl FusedIterator<Item = Symbol> + '_> {
    // NOTE: this page address is probably ONLY good for the header, NOT the function address
    let page = scan_macho_page(process, range)?;
    let macho_offsets = MachOFormatOffsets::new();
    let number_of_commands: u32 = process.read(page + (macho_offsets.number_of_commands as u64)).ok()?;
    print_message(&format!("macho::symbols: number_of_commands = {}", number_of_commands));

    let mut offset_to_next_command: u32 = macho_offsets.load_commands as u32;
    for i in 0..number_of_commands {
        // Check if load command is LC_SYMTAB or LC_DYSYMTAB
        let next_command: u32 = process.read(page + offset_to_next_command).ok()?;
        // print_message(&format!("macho::symbols: next_command = {}", next_command));
        if next_command == LC_SYMTAB {
            print_message(&format!("macho::symbols: found LC_SYMTAB at i = {}", i));
            let symbol_table_offset: u32 = process.read(page + offset_to_next_command + macho_offsets.symbol_table_offset as u32).ok()?;
            let number_of_symbols: u32 = process.read(page + offset_to_next_command + macho_offsets.number_of_symbols as u32).ok()?;
            let string_table_offset: u32 = process.read(page + offset_to_next_command + macho_offsets.string_table_offset as u32).ok()?;
            print_message(&format!("macho::symbols: symbol_table_offset = {}, number_of_symbols = {}, string_table_offset = {}", symbol_table_offset, number_of_symbols, string_table_offset));

            let symbol_table_contents: [u8; CSTR] = process.read(page + symbol_table_offset).ok()?;
            print_message(&format!("macho::symbols: symbol table ~= {:X?}", &symbol_table_contents));

            let string_table_contents: [u8; CSTR] = process.read(page + string_table_offset).ok()?;
            print_message(&format!("macho::symbols: string table ~= {:X?}", &string_table_contents));

            // TODO: iterate through symbol table
        } else if next_command == LC_DYSYMTAB {
            print_message(&format!("macho::symbols: found LC_DYSYMTAB at i = {}", i));
        } 
        let command_size: u32 = process.read(page + offset_to_next_command + (macho_offsets.command_size as u64)).ok()?;
        offset_to_next_command += command_size;
    }

    Some(iter::from_fn(move || {
        None
    })
    .fuse())
}
