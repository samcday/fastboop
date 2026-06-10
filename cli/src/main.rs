use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;

use commands::{
    BootArgs, BootProfileArgs, ChannelArgs, DetectArgs, DevProfileArgs, ShowArgs, Stage0Args,
    run_boot, run_bootprofile, run_channel, run_detect, run_devprofile, run_show, run_stage0,
};

#[derive(Parser)]
#[command(author, version, about = "fastboop CLI utilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Boot a device by synthesizing stage0 and issuing fastboot download+boot.
    Boot(BootArgs),
    /// Compile or inspect boot profile binaries.
    #[command(alias = "bootpro")]
    Bootprofile(BootProfileArgs),
    /// Channel-level operations (indexing, packing, inspection).
    Channel(ChannelArgs),
    /// Compile, inspect, or list device profiles.
    #[command(alias = "devpro")]
    Devprofile(DevProfileArgs),
    /// Detect connected fastboot devices that match a DevPro.
    Detect(DetectArgs),
    /// Inspect channel/profile inputs and render all recognized resources.
    Show(ShowArgs),
    /// Synthesize a stage0 initrd from a channel artifact and device profile; writes cpio to stdout.
    Stage0(Stage0Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_default_tracing();

    match cli.command {
        Commands::Boot(args) => run_boot(args).await,
        Commands::Bootprofile(args) => run_bootprofile(args).await,
        Commands::Channel(args) => run_channel(args).await,
        Commands::Devprofile(args) => run_devprofile(args).await,
        Commands::Detect(args) => run_detect(args).await,
        Commands::Show(args) => run_show(args).await,
        Commands::Stage0(args) => run_stage0(args).await,
    }
}

pub(crate) fn setup_default_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
