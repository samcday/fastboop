use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod devpros;
mod personalization;
mod smoo_host;

use commands::{BootArgs, DetectArgs, Stage0Args, run_boot, run_detect, run_stage0};

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
    /// Detect connected fastboot devices that match a DevPro.
    Detect(DetectArgs),
    /// Synthesize a stage0 initrd from a rootfs and device profile; writes cpio to stdout.
    Stage0(Stage0Args),
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Boot(args) => run_boot(args),
        Commands::Detect(args) => run_detect(args),
        Commands::Stage0(args) => run_stage0(args),
    }
}
