
use asr::{Address, Process};

// --------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Hash, Debug)]
pub enum BinaryFormat {
    PE,
    ELF,
    MachO,
}

// --------------------------------------------------------

const PAGE_SIZE: u64 = 0x1000;

pub fn process_detect_binary_format(process: &Process, name: &str) -> Option<BinaryFormat> {
    let address = process.get_module_address(name).ok()?;
    asr::print_message(&format!("process_detect_binary_format: address = {}", address));
    address_detect_binary_format(process, address)
}

pub fn scan_page_detect_binary_format(process: &Process, range: (Address, u64)) -> Option<BinaryFormat> {
    let address = scan_page(process, range)?;
    if address != range.0 {
        asr::print_message(&format!("scan_page_detect_binary_format: offset = 0x{:X?}", address.value() - range.0.value()));
    }
    address_detect_binary_format(process, address)
}

/// Scans the range for a page that begins with Magic of any of the supported binary formats
fn scan_page(process: &Process, range: (Address, u64)) -> Option<Address> {
    let (addr, len) = range;
    // negation mod PAGE_SIZE
    let distance_to_page = (PAGE_SIZE - (addr.value() % PAGE_SIZE)) % PAGE_SIZE;
    // round up to the next multiple of PAGE_SIZE
    let first_page = addr + distance_to_page;
    for i in 0..((len - distance_to_page) / PAGE_SIZE) {
        let a = first_page + (i * PAGE_SIZE);
        if let Ok(magic) = process.read::<[u8; 4]>(a) {
            if bytes_detect_binary_format(&magic).is_some() {
                return Some(a);
            }
        }
    }
    None
}

pub fn address_detect_binary_format(process: &Process, address: Address) -> Option<BinaryFormat> {
    let magic: [u8; 4] = process.read(address).ok()?;
    let r = bytes_detect_binary_format(&magic);
    if r.is_none() {
        asr::print_message(&format!("unrecogized: {:X?}", magic));
    }
    r
}

fn bytes_detect_binary_format(bytes: &[u8]) -> Option<BinaryFormat> {
    if bytes.starts_with(&[0x4D, 0x5A]) {
        Some(BinaryFormat::PE)
    } else if bytes.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        Some(BinaryFormat::ELF)
    } else if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
           || bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
           || bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
           || bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
           || bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        Some(BinaryFormat::MachO)
    } else {
        None
    }
}
