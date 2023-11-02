mod binary_format;
mod file;

use std::process;

use asr::{
    future::{next_tick, retry},
    game_engine::unity::mono::Module,
    Process,
};

use binary_format::*;

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
    let module = Module::wait_attach_auto_detect(&process).await;
    let image = module.wait_get_default_image(&process).await;

    // TODO: Load some initial information from the process.
    loop {
        // TODO: Do something on every tick.
        next_tick().await;
    }
}
