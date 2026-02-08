use anyhow::Result;
use tracing_subscriber::prelude::*;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_logging();
    smoo_gadget_app::run_from_env().await
}

fn init_logging() {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
