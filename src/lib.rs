mod binary_format;
mod file;
mod file_format;

use asr::{
    future::{next_tick, retry},
    game_engine::unity::mono::Module,
    Process, file_format::pe, Address, Address32, signature::Signature, Address64, string::ArrayCString,
};

use binary_format::*;

use crate::{file::file_read_all_bytes, file_format::{elf, macho}};

asr::async_main!(stable);

// --------------------------------------------------------

const CSTR: usize = 128;

const PROCESS_NAMES: [&str; 7] = [
    "Hollow Knight",
    "hollow_knight",
    "hollow_knight.exe",
    "hollow_knight.x",
    "hollow_knight.x86_64",
    "SuperliminalSteam",
    "SuperliminalSteam.exe",
];

const MONO_NAMES: [&str; 6] = [
    "libmono.0.dylib",
    "libmono.so",
    "libmonobdwgc-2.0.dylib",
    "libmonobdwgc-2.0.so",
    "mono-2.0-bdwgc.dll",
    "mono.dll",
];

// --------------------------------------------------------

async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        asr::print_message(&panic_info.to_string());
    }));

    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let process = retry(|| {
            PROCESS_NAMES.into_iter().find_map(Process::attach)
        }).await;
        process
            .until_closes(async {
                match option_main(&process).await {
                    None => {
                        asr::print_message("option_main exit None");
                    },
                    Some(()) => {
                        asr::print_message("option_main exit Some(())");
                    }
                }
                loop {
                    next_tick().await;
                }
            })
            .await;
    }
}

async fn option_main(process: &Process) -> Option<()> {
    let format = process_detect_binary_format(&process)?;
    asr::print_message(&format!("binary format: {:?}", format));

    let (mono_name, mono_path, mono_range) = MONO_NAMES.into_iter().find_map(|mono_name| {
        let mono_path = process.get_module_path(mono_name).ok()?;
        let mono_range = process.get_module_range(mono_name).ok()?;
        Some((mono_name, mono_path, mono_range))
    })?;
    asr::print_message(&format!("mono_name: {}", mono_name));
    asr::print_message(&format!("mono_path: {}", mono_path));
    assert_eq!(path_detect_binary_format(&mono_path), Some(format));

    let deref_type = match format {
        BinaryFormat::PE => file_format::pe::detect_deref_type(process, mono_range)?,
        BinaryFormat::ELF => file_format::elf::detect_deref_type(process, mono_range)?,
        BinaryFormat::MachO => file_format::macho::detect_deref_type(process, mono_range)?,
    };
    asr::print_message(&format!("deref_type: {:?}", deref_type));

    let mono_assembly_foreach_address = match format {
        BinaryFormat::PE => {
            pe::symbols(process, mono_range.0)
                .find(|symbol| {
                    symbol
                        .get_name::<25>(process)
                        .is_ok_and(|name| name.matches("mono_assembly_foreach"))
                })?
                .address
        },
        BinaryFormat::ELF => {
            let mono_bytes = file_read_all_bytes(mono_path).ok()?;
            elf::get_function_address(process, mono_range, &mono_bytes, b"mono_assembly_foreach")?
        },
        BinaryFormat::MachO => {
            let mono_bytes = file_read_all_bytes(mono_path).ok()?;
            macho::get_function_address(process, mono_range, &mono_bytes, b"_mono_assembly_foreach")?
        }
    };
    asr::print_message(&format!("mono_assembly_foreach_address: {}", mono_assembly_foreach_address));

    let assemblies_pointer: Address = match (deref_type, format) {
        (DerefType::Bit64, BinaryFormat::PE) => {
            const SIG_MONO_64_PE: Signature<3> = Signature::new("48 8B 0D");
            let scan_address: Address = SIG_MONO_64_PE
                .scan_process_range(process, (mono_assembly_foreach_address, 0x100))?
                + 3;
            scan_address + 0x4 + process.read::<i32>(scan_address).ok()?
        },
        (DerefType::Bit64, BinaryFormat::ELF) => {
            const SIG_MONO_64_ELF: Signature<3> = Signature::new("48 8B 3D");
            // RIP-relative addressing
            // 3 is the offset to the next thing after the signature
            let scan_address = SIG_MONO_64_ELF.scan_process_range(process, (mono_assembly_foreach_address, 0x100))? + 3;
            // 4 is the offset to the next instruction after relative
            scan_address + 0x4 + process.read::<i32>(scan_address).ok()?
        },
        (DerefType::Bit64, BinaryFormat::MachO) => {
            const SIG_MONO_64_MACHO: Signature<3> = Signature::new("48 8B 3D");
            // RIP-relative addressing
            // 3 is the offset to the next thing after the signature
            let scan_address = SIG_MONO_64_MACHO.scan_process_range(process, (mono_assembly_foreach_address, 0x100))? + 3;
            // 4 is the offset to the next instruction after relative
            scan_address + 0x4 + process.read::<i32>(scan_address).ok()?
        },
        (DerefType::Bit32, BinaryFormat::PE) => {
            const SIG_32_1: Signature<2> = Signature::new("FF 35");
            const SIG_32_2: Signature<2> = Signature::new("8B 0D");

            let ptr = [SIG_32_1, SIG_32_2].iter().find_map(|sig| {
                sig.scan_process_range(process, (mono_assembly_foreach_address, 0x100))
            })? + 2;

            process.read::<Address32>(ptr + 2).ok()?.into()
        },
        (DerefType::Bit32, BinaryFormat::ELF) => { return None; },
        (DerefType::Bit32, BinaryFormat::MachO) => {
            return None;
        },
    };
    asr::print_message(&format!("assemblies_pointer: {}", assemblies_pointer));

    let assemblies: Address = match deref_type {
        DerefType::Bit64 => process.read::<Address64>(assemblies_pointer).ok()?.into(),
        DerefType::Bit32 => process.read::<Address32>(assemblies_pointer).ok()?.into(),
    };
    asr::print_message(&format!("assemblies: {}", assemblies));

    let mut assembly = assemblies;
    let [data, next_assembly]: [Address; 2] = match deref_type {
        DerefType::Bit64 => process
            .read::<[Address64; 2]>(assembly)
            .ok()?
            .map(|item| item.into()),
        DerefType::Bit32 => process
            .read::<[Address32; 2]>(assembly)
            .ok()?
            .map(|item| item.into()),
    };
    asr::print_message(&format!("data: {}", data));

    let monoassembly_aname = [0x8, 0x10].into_iter().max_by_key(|&monoassembly_aname| {
        address_aname_score(process, deref_type, data + monoassembly_aname)
    })?;
    let aname_score = address_aname_score(process, deref_type, data + monoassembly_aname);
    asr::print_message(&format!("Offsets monoassembly_aname: 0x{:X?}, aname_score: {}", monoassembly_aname, aname_score));
    if let Ok(aname) = read_pointer(process, deref_type, data + monoassembly_aname) {
        if let Ok(name_cstr) = process.read::<ArrayCString<CSTR>>(aname) {
            if let Ok(name_str) = std::str::from_utf8(&name_cstr) {
                asr::print_message(&format!("name_str: {}", name_str));
            }
        }
    }

    let module = Module::wait_attach_auto_detect(&process).await;
    let image = module.wait_get_default_image(&process).await;

    // TODO: Load some initial information from the process.
    loop {
        // TODO: Do something on every tick.
        next_tick().await;
    }
}

fn read_pointer(process: &Process, deref_type: DerefType, address: Address) -> Result<Address, asr::Error> {
    Ok(match deref_type {
        DerefType::Bit64 => process.read::<Address64>(address)?.into(),
        DerefType::Bit32 => process.read::<Address32>(address)?.into(),
    })
}

fn address_aname_score(process: &Process, deref_type: DerefType, address: Address) -> i32 {
    let Ok(aname) = read_pointer(process, deref_type, address) else { return 0; };
    let Ok(name_cstr) = process.read::<ArrayCString<CSTR>>(aname) else { return 1; };
    let Ok(name_str) = std::str::from_utf8(&name_cstr) else { return 2; };
    if name_str.is_empty() { return 3; }
    if name_str.contains("/") || name_str.contains("\\") { return 4; }
    5
}
