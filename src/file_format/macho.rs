//! Support for parsing MachO files

use asr::{signature::Signature, string::ArrayCString, Address, PointerSize, Process};

use core::{
    fmt::Debug,
    iter::FusedIterator,
    mem,
};
use alloc::collections::BTreeMap;

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
/// 64-bit segment of this file to be mapped
/// see also segment_command_64
const LC_SEGMENT_64: u32 = 0x19;

const HEADER_SIZE: usize = 32;

struct MachOFormatOffsets {
    number_of_commands: u32,
    load_commands: u32,
    command_size: u32,
    symbol_table_offset: u32,
    number_of_symbols: u32,
    string_table_offset: u32,
    nlist_value: u32,
    size_of_nlist_item: u32,
    segmentcommand64_vmaddr: u32,
    segmentcommand64_fileoff: u32,
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
            segmentcommand64_vmaddr: 0x18,
            segmentcommand64_fileoff: 0x28,
        }
    }
}

/// A symbol exported into the current module.
pub struct Symbol {
    /// The address associated with the current function
    pub address: Address,
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


trait MachOView {
    fn read<T: bytemuck::CheckedBitPattern + Debug + PartialEq, N: Into<u64>>(
        &self,
        desc: &str,
        fileoff: N,
        vmaddr: N,
    ) -> Option<T>;

    fn read_bytes<N: Into<u64>>(&self, desc: &str, fileoff: N, vmaddr: N, len: usize) -> Option<Vec<u8>>;
}

struct MachOFile<'a> {
    /// The bytes of the MachO file starting with the header.
    /// May include more bytes after what should be the "end".
    bytes: &'a [u8],
}

struct MachOMemory<'a> {
    process: &'a Process,
    page: Address,
}

struct MachOFileMemory<'a> {
    file: MachOFile<'a>,
    memory: MachOMemory<'a>,
}

impl<'a> MachOView for MachOFile<'a> {
    fn read<T: bytemuck::CheckedBitPattern, N: Into<u64>>(&self, _: &str, fileoff: N, _: N) -> Option<T> {
        slice_read(self.bytes, fileoff).ok()
    }
    fn read_bytes<N: Into<u64>>(&self, _: &str, fileoff: N, _: N, len: usize) -> Option<Vec<u8>> {
        let start: usize = Into::<u64>::into(fileoff) as usize;
        Some(self.bytes[start..(start + len)].to_vec())
    }
}

impl<'a> MachOView for MachOMemory<'a> {
    fn read<T: bytemuck::CheckedBitPattern, N: Into<u64>>(&self, _: &str, _: N, vmaddr: N) -> Option<T> {
        self.process.read(self.page + vmaddr.into()).ok()
    }
    fn read_bytes<N: Into<u64>>(&self, _: &str, _: N, vmaddr: N, len: usize) -> Option<Vec<u8>> {
        self.process.read_vec(self.page + vmaddr.into(), len).ok()
    }
}

impl<'a> MachOFileMemory<'a> {
    fn compare_choose<T: Debug + PartialEq>(&self, desc: &str, ma: Option<T>, mb: Option<T>) -> Option<T> {
        match (ma, mb) {
            (None, None) => None,
            (Some(a), None) => {
                asr::print_message(&format!("{}: only found in file, not in memory: {:?}", desc, a));
                Some(a)
            }
            (None, Some(b)) => {
                asr::print_message(&format!("{}: only found in memory, not in file: {:?}", desc, b));
                Some(b)
            }
            (Some(a), Some(b)) => {
                if a == b {
                    Some(a)
                } else {
                    asr::print_message(&format!("{} mismatch: file {:?} vs memory {:?}", desc, a, b));
                    Some(a)
                }
            }
        }
    }
}


impl<'a> MachOView for MachOFileMemory<'a> {
    fn read<T: bytemuck::CheckedBitPattern + Debug + PartialEq, N: Into<u64>>(
        &self,
        desc: &str,
        fileoff: N,
        vmaddr: N,
    ) -> Option<T> {
        let fileoff: u64 = fileoff.into();
        let vmaddr: u64 = vmaddr.into();
        let ma = self.file.read(desc, fileoff, vmaddr);
        let mb = self.memory.read(desc, fileoff, vmaddr);
        self.compare_choose(desc, ma, mb)
    }
    fn read_bytes<N: Into<u64>>(&self, desc: &str, fileoff: N, vmaddr: N, len: usize) -> Option<Vec<u8>> {
        let fileoff: u64 = fileoff.into();
        let vmaddr: u64 = vmaddr.into();
        let ma = self.file.read_bytes(desc, fileoff, vmaddr, len);
        let mb = self.memory.read_bytes(desc, fileoff, vmaddr, len);
        self.compare_choose(desc, ma, mb)
    }
}

struct SymbolsState {
    offsets: MachOFormatOffsets,
    number_of_commands: u32,
    symbol_table_fileoff: u32,
    symbol_table_vmaddr: u64,
    number_of_symbols: u32,
    string_table_fileoff: u32,
    string_table_vmaddr: u64,
    map_fileoff_to_vmaddr: BTreeMap<u64, u64>,
}

impl SymbolsState {
    fn new() -> Self {
        SymbolsState {
            offsets: MachOFormatOffsets::new(),
            number_of_commands: 0,
            symbol_table_fileoff: 0,
            symbol_table_vmaddr: 0,
            number_of_symbols: 0,
            string_table_fileoff: 0,
            string_table_vmaddr: 0,
            map_fileoff_to_vmaddr: BTreeMap::new(),
        }
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
    let function_offset: u32 = get_function_offset(MachOFile{ bytes: &macho_bytes2 }, function_name)?;
    // asr::print_message(&format!("macho get_function_address: function_offset: 0x{:X?}", function_offset));
    let bytes_expected: [u8; 0x100] = slice_read(&macho_bytes2, function_offset).ok()?;
    let signature: Signature<0x100> = Signature::Simple(bytes_expected);
    let function_address_expected = signature.scan_process_range(process, range)?;
    // asr::print_message(&format!("macho get_function_address: function_address_expected: {}", function_address_expected));
    Some(function_address_expected)
}

/// Finds the offset of a function in the bytes of a MachO file.
fn get_function_offset<M: MachOView>(macho_bytes: M, function_name: &[u8]) -> Option<u32> {
    let mut s = SymbolsState::new();
    s.number_of_commands = macho_bytes.read("number_of_commands", s.offsets.number_of_commands, s.offsets.number_of_commands)?;
    let function_name_len = function_name.len();

    let mut offset_to_next_command = s.offsets.load_commands;
    for _i in 0..s.number_of_commands {
        // Check if load command is LC_SYMTAB
        let next_command: u32 = macho_bytes.read("next_command", offset_to_next_command, offset_to_next_command)?;
        if next_command == LC_SYMTAB {
            let next_command_symbol_table = offset_to_next_command + s.offsets.symbol_table_offset;
            s.symbol_table_fileoff = macho_bytes.read("symbol_table_fileoff", next_command_symbol_table, next_command_symbol_table)?;
            let next_command_number_of_symbols = offset_to_next_command + s.offsets.number_of_symbols;
            s.number_of_symbols = macho_bytes.read("number_of_symbols", next_command_number_of_symbols, next_command_number_of_symbols)?;
            let next_command_string_table = offset_to_next_command + s.offsets.string_table_offset;
            s.string_table_fileoff = macho_bytes.read("string_table_fileoff", next_command_string_table, next_command_string_table)?;

            for j in 0..s.number_of_symbols {
                let symbol_table_j = s.symbol_table_fileoff + (j * s.offsets.size_of_nlist_item);
                let symbol_name_offset: u32 = macho_bytes.read("symbol_name_offset", symbol_table_j, symbol_table_j)?;
                let string_offset = s.string_table_fileoff + symbol_name_offset;
                let symbol_name: Vec<u8> = macho_bytes.read_bytes("symbol_name", string_offset, string_offset, function_name_len + 1)?;

                if symbol_name[function_name_len] == 0 && symbol_name.starts_with(function_name) {
                    let symbol_table_j_value = s.symbol_table_fileoff + (j * s.offsets.size_of_nlist_item) + s.offsets.nlist_value;
                    return Some(macho_bytes.read("function_offset", symbol_table_j_value, symbol_table_j_value)?);
                }
            }
        }
        let next_command_size = offset_to_next_command + s.offsets.command_size;
        let command_size: u32 = macho_bytes.read("command_size", next_command_size, next_command_size)?;
        offset_to_next_command += command_size;
    }
    None
}

/// Reads a value of the type specified from the slice at the address
/// given.
pub fn slice_read<T: bytemuck::CheckedBitPattern, N: Into<u64>>(slice: &[u8], address: N) -> Result<T, bytemuck::checked::CheckedCastError> {
    let start: usize = Into::<u64>::into(address) as usize;
    let size = mem::size_of::<T>();
    let slice_src = &slice[start..(start + size)];
    bytemuck::checked::try_from_bytes(slice_src).cloned()
}

pub fn symbols(
    process: &Process,
    range: (Address, u64),
) -> Option<impl FusedIterator<Item = Symbol> + '_> {
    let page = scan_macho_page(process, range)?;
    let m = MachOMemory { process, page };
    let mut s = SymbolsState::new();
    s.number_of_commands = m.read("number_of_commands", s.offsets.number_of_commands, s.offsets.number_of_commands)?;

    let mut offset_to_next_command: u32 = s.offsets.load_commands;
    for _i in 0..s.number_of_commands {
        // Check if load command is LC_SYMTAB or LC_SEGMENT_64
        let next_command: u32 = m.read("next_command", offset_to_next_command, offset_to_next_command)?;
        if next_command == LC_SYMTAB {
            let next_command_symbol_table = offset_to_next_command + s.offsets.symbol_table_offset;
            s.symbol_table_fileoff = m.read("symbol_table_fileoff", next_command_symbol_table, next_command_symbol_table)?;
            let next_command_number_of_symbols = offset_to_next_command + s.offsets.number_of_symbols;
            s.number_of_symbols = m.read("number_of_symbols", next_command_number_of_symbols, next_command_number_of_symbols)?;
            let next_command_string_table = offset_to_next_command + s.offsets.string_table_offset;
            s.string_table_fileoff = m.read("string_table_fileoff", next_command_string_table, next_command_string_table)?;
        } else if next_command == LC_SEGMENT_64 {
            let next_command_vmaddr = offset_to_next_command + s.offsets.segmentcommand64_vmaddr;
            let vmaddr: u64 = m.read("vmaddr", next_command_vmaddr, next_command_vmaddr)?;
            let next_command_fileoff = offset_to_next_command + s.offsets.segmentcommand64_fileoff;
            let fileoff: u64 = m.read("fileoff", next_command_fileoff, next_command_fileoff)?;
            s.map_fileoff_to_vmaddr.insert(fileoff, vmaddr);
        }
        let next_command_size = offset_to_next_command + s.offsets.command_size;
        let command_size: u32 = m.read("command_size", next_command_size, next_command_size)?;
        offset_to_next_command += command_size;
    }

    if s.symbol_table_fileoff == 0 || s.number_of_symbols == 0 || s.string_table_fileoff == 0 {
        return None;
    }

    s.symbol_table_vmaddr = fileoff_to_vmaddr(&s.map_fileoff_to_vmaddr, s.symbol_table_fileoff as u64);

    s.string_table_vmaddr = fileoff_to_vmaddr(&s.map_fileoff_to_vmaddr, s.string_table_fileoff as u64);

    // TODO: figure out what this means:
    // https://www.reddit.com/r/jailbreakdevelopers/comments/ol9m1s/confusion_about_macho_offsets_and_addresses/

    Some((0..s.number_of_symbols).filter_map(move |j| {
        let symbol_name_offset: u32 = m.read(
            "symbol_name_offset",
            (s.symbol_table_fileoff + (j * s.offsets.size_of_nlist_item)) as u64,
            s.symbol_table_vmaddr + (j * s.offsets.size_of_nlist_item) as u64,
        )?;
        let string_address = page + s.string_table_vmaddr + symbol_name_offset;
        let symbol_fileoff = m.read(
            "symbol_fileoff",
            (s.symbol_table_fileoff + (j * s.offsets.size_of_nlist_item) + s.offsets.nlist_value) as u64,
            s.symbol_table_vmaddr + ((j * s.offsets.size_of_nlist_item) + s.offsets.nlist_value) as u64,
        )?;
        let symbol_vmaddr = fileoff_to_vmaddr(&s.map_fileoff_to_vmaddr, symbol_fileoff);
        let symbol_address = page + symbol_vmaddr;
        Some(Symbol {
            address: symbol_address,
            name_addr: string_address,
        })
    })
    .fuse())
}

fn fileoff_to_vmaddr(map: &BTreeMap<u64, u64>, fileoff: u64) -> u64 {
    map
        .iter()
        .filter(|(&k, _)| k <= fileoff)
        .max_by_key(|(&k, _)| k) // can/should this max_by_key be replaced with last?
        .map(|(&k, &v)| v + fileoff - k)
        .unwrap_or(fileoff)
}
