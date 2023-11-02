use asr::{future::next_tick, game_engine::unity::il2cpp::{Module, Version}, Process};

asr::async_main!(stable);

async fn main() {
    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let process = Process::wait_attach("Hollow Knight").await;
        process
            .until_closes(async {
                // TODO: Change this to use the correct version of IL2CPP (or mono backend).
                let module = Module::wait_attach(&process, Version::V2020).await;
                let image = module.wait_get_default_image(&process).await;

                // TODO: Load some initial information from the process.
                loop {
                    // TODO: Do something on every tick.
                    next_tick().await;
                }
            })
            .await;
    }
}
