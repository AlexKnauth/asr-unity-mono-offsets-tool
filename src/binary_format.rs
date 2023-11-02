use asr::Process;

use crate::file::file_read_all_bytes;

// --------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Hash, Debug)]
pub enum BinaryFormat {
    PE,
    ELF,
    MachO,
}

// --------------------------------------------------------

pub fn process_detect_binary_format(process: &Process) -> Option<BinaryFormat> {
    let path = process.get_path().ok()?;
    let bytes = file_read_all_bytes(path).ok()?;
    if bytes.starts_with(&[0x4D, 0x5A]) {
        Some(BinaryFormat::PE)
    } else if bytes.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        Some(BinaryFormat::ELF)
    } else if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) {
        Some(BinaryFormat::MachO)
    } else if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) {
        Some(BinaryFormat::MachO)
    } else if bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
        Some(BinaryFormat::MachO)
    } else if bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
        Some(BinaryFormat::MachO)
    } else {
        None
    }
}
