use asr::{
    future::next_tick,
    game_engine::unity::mono::Module,
    Process,
};

asr::async_main!(stable);

async fn main() {
    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let process = Process::wait_attach("Hollow Knight").await;
        process
            .until_closes(async {
                let module = Module::wait_attach_auto_detect(&process).await;
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
