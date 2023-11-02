use core::mem;

use asr::{Process, Address, file_format::elf::Info};
pub use asr::file_format::elf;
use bytemuck::{Pod, Zeroable};

use crate::binary_format::DerefType;

// --------------------------------------------------------

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
