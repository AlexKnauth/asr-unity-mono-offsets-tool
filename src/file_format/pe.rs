use asr::{Address, PointerSize, Process};
pub use asr::file_format::pe;

pub fn detect_pointer_size(process: &Process, module_range: (Address, u64)) -> Option<PointerSize> {
    pe::MachineType::read(process, module_range.0)?.pointer_size()
}
