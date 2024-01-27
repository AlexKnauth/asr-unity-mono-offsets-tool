use core::mem;

use asr::{file_format::elf::Info, Address, Process};
pub use asr::file_format::elf;
use bytemuck::{Pod, Zeroable};

use crate::binary_format::DerefType;

// --------------------------------------------------------

const CSTR: usize = 128;

// Section Header Type: Symbol Table
const SHT_SYMTAB: u32 = 0x2;

// Section Header Type: Dynamic Linking Symbols
const SHT_DYNSYM: u32 = 11;

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
struct Header {
    ident: Identification,
    ty: u16,      // 1 = relocatable, 2 = executable, 3 = shared object, 4 = core
    machine: u16, // 0x3e = x86-64
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
struct Identification {
    magic: [u8; 4],  // 0x7f, 'E', 'L', 'F'
    class: u8,       // 32 or 64
    data: u8,        // little or big endian
    version: u8,     // 1
    os_abi: u8,      // 0
    abi_version: u8, // 0
    _padding: [u8; 7],
}

const HEADER_SIZE: usize = mem::size_of::<Header>();

// --------------------------------------------------------

struct ElfFormatOffsets {
    e_shoff: usize,
    e_shentsize: usize,
    e_shnum: usize,
    sh_type: usize,
    sh_offset: usize,
    sh_size: usize,
    sh_link: usize,
    sh_entsize: usize,
    st_name: usize,
    st_value: usize,
}

impl ElfFormatOffsets {
    fn new(is_64_bit: bool) -> ElfFormatOffsets {
        // offsets taken from:
        //  - https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
        //  - https://refspecs.linuxfoundation.org/elf/elf.pdf
        //  - https://refspecs.linuxbase.org/elf/gabi4+/contents.html
        //  - https://manpages.debian.org/stretch/manpages/elf.5.en.html
        match is_64_bit {
            false => ElfFormatOffsets {
                e_shoff: 0x20,
                e_shentsize: 0x2E,
                e_shnum: 0x30,
                sh_type: 0x4,
                sh_offset: 0x10,
                sh_size: 0x14,
                sh_link: 0x18,
                sh_entsize: 0x24,
                st_name: 0x0,
                st_value: 0x4, // size of Elf32_Word
            },
            true => ElfFormatOffsets {
                e_shoff: 0x28,
                e_shentsize: 0x3A,
                e_shnum: 0x3C,
                sh_type: 0x4,
                sh_offset: 0x18,
                sh_size: 0x20,
                sh_link: 0x28,
                sh_entsize: 0x38,
                st_name: 0x0,
                st_value: 0x8, // size of Elf64_Word + unsigned char + unsigned char + Elf64_Half
            },
        }
    }
}

/// Scans the range for a page that begins with ELF Magic
pub fn scan_elf_page(process: &Process, range: (Address, u64)) -> Option<Address> {
    const PAGE_SIZE: u64 = 0x1000;
    let (addr, len) = range;
    // negation mod PAGE_SIZE
    let distance_to_page = (PAGE_SIZE - (addr.value() % PAGE_SIZE)) % PAGE_SIZE;
    // round up to the next multiple of PAGE_SIZE
    let first_page = addr + distance_to_page;
    for i in 0..((len - distance_to_page) / PAGE_SIZE) {
        let a = first_page + (i * PAGE_SIZE);
        if let Ok(header_bytes) = process.read::<[u8; HEADER_SIZE]>(a) {
            if Info::parse(&header_bytes).is_some() {
                return Some(a);
            }
        }
    }
    None
}

pub fn detect_deref_type(process: &Process, module_range: (Address, u64)) -> Option<DerefType> {
    let header_address = scan_elf_page(process, module_range)?;
    let header_bytes: [u8; HEADER_SIZE] = process.read(header_address).ok()?;
    let info = Info::parse(&header_bytes)?;
    if info.bitness.is_64() {
        Some(DerefType::Bit64)
    } else if info.bitness.is_32() {
        Some(DerefType::Bit32)
    } else {
        None
    }
}


pub fn get_function_symbol_address(process: &Process, range: (Address, u64), elf_bytes: &[u8], function_name: &[u8]) -> Option<Address> {
    let ma = get_function_address(process, range, elf_bytes, function_name);
    let mb = elf::symbols(process, range.0).find_map(|s| -> Option<Address> {
        let n = s.get_name::<CSTR>(process).ok()?;
        if n.matches(function_name) {
            Some(s.address)
        } else {
            None
        }
    });
    match (ma, mb) {
        (Some(a), Some(b)) => {
            if a == b {
                asr::print_message(&format!("elf::get_function_symbol_address: all good, both Some and equal"));
            } else {
                asr::print_message(&format!("elf::get_function_symbol_address: mismatch, {} != {}", a, b));
            }
            Some(a)
        }
        (Some(a), None) => {
            asr::print_message("elf::get_function_symbol_address: only get_function_address worked");
            Some(a)
        }
        (None, Some(b)) => {
            asr::print_message("elf::get_function_symbol_address: only elf::symbols worked");
            Some(b)
        }
        (None, None) => {
            asr::print_message("elf::get_function_symbol_address: both failed");
            None
        }
    }
}


/// Finds the address of a function from an ELF module range and file contents.
pub fn get_function_address(process: &Process, range: (Address, u64), elf_bytes: &[u8], function_name: &[u8]) -> Option<Address> {
    let function_offset: u32 = get_function_offset(&elf_bytes, function_name)?;
    let page = scan_elf_page(process, range)?;
    let function_address = page + function_offset;
    let actual: [u8; 0x100] = process.read(function_address).ok()?;
    let expected: [u8; 0x100] = slice_read(&elf_bytes, function_offset as usize).ok()?;
    if actual != expected { return None; }
    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize_with(elf_bytes.len(), Default::default);
    process.read_into_buf(page, &mut buffer).unwrap_or_default();
    if elf_bytes == buffer {
        asr::print_message("GOOD: elf_bytes == buffer");
    } else {
        asr::print_message("BAD: elf_bytes != buffer");
        // let mut common_zero = 0;
        let mut same = 0;
        let mut diff = 0;
        for i in 0..elf_bytes.len() {
            if elf_bytes[i] == 0 && buffer[i] == 0  {
                // common_zero += 1;
            } else if elf_bytes[i] == buffer[i] {
                same += 1;
            } else {
                diff += 1;
            }
        }
        asr::print_message(&format!("same: {}%, diff: {}%", 
                                    (same as f64 * 100.0) / elf_bytes.len() as f64,
                                    (diff as f64 * 100.0) / elf_bytes.len() as f64));
        let other_function_offset = get_function_offset(&buffer, function_name).expect("BAD BAD BAD: other_function_offset");
        if function_offset == other_function_offset {
            asr::print_message("LUCKY: function_offset == other_function_offset");
        } else {
            asr::print_message("BAD BAD: function_offset != other_function_offset");
        }
    }
    Some(function_address)
}

/// Finds the offset of a function in the bytes of a ELF file.
fn get_function_offset(bs: &[u8], function_name: &[u8]) -> Option<u32> {
    let function_name_len = function_name.len();

    let info = Info::parse(bs)?;
    let offsets = ElfFormatOffsets::new(info.bitness.is_64());
    let shoff: u32 = slice_read(&bs, offsets.e_shoff).ok()?;
    let shentsize: u16 = slice_read(&bs, offsets.e_shentsize).ok()?;
    let shnum: u16 = slice_read(&bs, offsets.e_shnum).ok()?;
    for i in 0..shnum {
        let ent_a = shoff as usize + (i * shentsize) as usize;
        let sh_type: u32 = slice_read(&bs, ent_a + offsets.sh_type).ok()?;
        asr::print_message(&format!("i: {}, sh_type: {}", i, sh_type));
        if sh_type == SHT_SYMTAB || sh_type == SHT_DYNSYM {
            asr::print_message(&format!("found symbol table at i: {}", i));
            let symbol_table_a: u32 = slice_read(&bs, ent_a + offsets.sh_offset).ok()?;
            let sh_size: u32 = slice_read(&bs, ent_a + offsets.sh_size).ok()?;
            let string_table_i: u32 = slice_read(&bs, ent_a + offsets.sh_link).ok()?;
            let sh_entsize: u32 = slice_read(&bs, ent_a + offsets.sh_entsize).ok()?;
            let string_table_ent_a = shoff as usize + (string_table_i as usize * shentsize as usize);
            let string_table_a: u32 = slice_read(&bs, string_table_ent_a + offsets.sh_offset).ok()?;
            let number_of_symbols = sh_size / sh_entsize;
            for j in 0..number_of_symbols {
                let sym_ent_a = symbol_table_a as usize + (j * sh_entsize) as usize;
                let symbol_name_offset: u32 = slice_read(&bs, sym_ent_a + offsets.st_name).ok()?;
                let string_offset = string_table_a as usize + symbol_name_offset as usize;
                let symbol_name: &[u8] = &bs[string_offset..(string_offset + function_name_len + 1)];
                if symbol_name[function_name_len] == 0 && symbol_name.starts_with(function_name) {
                    return Some(slice_read::<u32>(&bs, sym_ent_a + offsets.st_value).ok()?);
                }
            }
        }
    }
    None
}

/// Reads a value of the type specified from the slice at the address
/// given.
fn slice_read<T: bytemuck::CheckedBitPattern>(slice: &[u8], address: usize) -> Result<T, bytemuck::checked::CheckedCastError> {
    let size = mem::size_of::<T>();
    let slice_src = &slice[address..(address + size)];
    bytemuck::checked::try_from_bytes(slice_src).cloned()
}
