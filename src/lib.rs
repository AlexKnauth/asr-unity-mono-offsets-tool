mod binary_format;
mod file;
mod file_format;

use asr::{
    future::{next_tick, retry},
    game_engine::unity::mono::Module,
    Process, file_format::pe,
};

use binary_format::*;

use crate::{file::file_read_all_bytes, file_format::{elf, macho}};

asr::async_main!(stable);

// --------------------------------------------------------

const PROCESS_NAMES: [&str; 6] = [
    "Hollow Knight",
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

    let module = Module::wait_attach_auto_detect(&process).await;
    let image = module.wait_get_default_image(&process).await;

    // TODO: Load some initial information from the process.
    loop {
        // TODO: Do something on every tick.
        next_tick().await;
    }
}
