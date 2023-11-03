use std::path::Path;

use asr::Process;

use crate::file::file_read_all_bytes;

// --------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Hash, Debug)]
pub enum BinaryFormat {
    PE,
    ELF,
    MachO,
}

/// Describes the pointer size that should be used while deferecencing a pointer path
#[derive(Copy, Clone, Default, Debug)]
pub enum DerefType {
    /// 4-byte pointer size, used in 32bit processes
    Bit32,
    /// 8-byte pointer size, used in 64bit processes
    #[default]
    Bit64,
}

impl DerefType {
    pub fn size_of_ptr(&self) -> u64 {
        match self {
            DerefType::Bit64 => 8,
            DerefType::Bit32 => 4,
        }
    }
}

// --------------------------------------------------------

pub fn process_detect_binary_format(process: &Process) -> Option<BinaryFormat> {
    let path = process.get_path().ok()?;
    path_detect_binary_format(path)
}

pub fn path_detect_binary_format<P: AsRef<Path>>(path: P) -> Option<BinaryFormat> {
    let bytes = file_read_all_bytes(path).ok()?;
    bytes_detect_binary_format(&bytes)
}

fn bytes_detect_binary_format(bytes: &[u8]) -> Option<BinaryFormat> {
    if bytes.starts_with(&[0x4D, 0x5A]) {
        Some(BinaryFormat::PE)
    } else if bytes.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        Some(BinaryFormat::ELF)
    } else if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
           || bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
           || bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
           || bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
        Some(BinaryFormat::MachO)
    } else {
        None
    }
}
