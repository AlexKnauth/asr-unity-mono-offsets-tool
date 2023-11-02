use asr::{Process, Address};
pub use asr::file_format::pe;

use crate::binary_format::DerefType;

pub fn detect_deref_type(process: &Process, module_range: (Address, u64)) -> Option<DerefType> {
    if pe::MachineType::read(process, module_range.0)? == pe::MachineType::X86_64 {
        Some(DerefType::Bit64)
    } else {
        Some(DerefType::Bit32)
    }
}
