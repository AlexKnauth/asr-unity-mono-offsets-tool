pub use asr::file_format::pe;
use asr::{Address, PointerSize, Process};

pub fn detect_pointer_size(process: &Process, module_range: (Address, u64)) -> Option<PointerSize> {
    pe::MachineType::read(process, module_range.0)?.pointer_size()
}
