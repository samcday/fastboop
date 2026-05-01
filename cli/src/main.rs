#[cfg(feature = "tui")]
use std::io::Write;
#[cfg(feature = "tui")]
use std::sync::mpsc::Sender;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
#[cfg(feature = "tui")]
use tracing_subscriber::fmt::MakeWriter;
#[cfg(feature = "tui")]
use tracing_subscriber::layer::SubscriberExt;
#[cfg(feature = "tui")]
use tracing_subscriber::util::SubscriberInitExt;

mod boot_ui;
mod commands;
mod devpros;
mod personalization;
mod smoo_host;
mod stage0_binary;
#[cfg(feature = "tui")]
mod tui;

#[cfg(feature = "tui")]
use boot_ui::BootEvent;
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
    if !matches!(&cli.command, Commands::Boot(_)) {
        setup_default_tracing();
    }

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

#[cfg(feature = "tui")]
pub(crate) fn setup_tui_tracing(tx: Sender<BootEvent>) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let writer = TuiWriter { tx };
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();
}

#[cfg(feature = "tui")]
#[derive(Clone)]
struct TuiWriter {
    tx: Sender<BootEvent>,
}

#[cfg(feature = "tui")]
impl<'a> MakeWriter<'a> for TuiWriter {
    type Writer = TuiWriterInner;

    fn make_writer(&'a self) -> Self::Writer {
        TuiWriterInner {
            tx: self.tx.clone(),
            buffer: Vec::new(),
        }
    }
}

#[cfg(feature = "tui")]
struct TuiWriterInner {
    tx: Sender<BootEvent>,
    buffer: Vec<u8>,
}

#[cfg(feature = "tui")]
impl std::io::Write for TuiWriterInner {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            let message = String::from_utf8_lossy(&self.buffer).trim_end().to_string();
            if !message.is_empty() {
                let _ = self.tx.send(BootEvent::Log(message));
            }
            self.buffer.clear();
        }
        Ok(())
    }
}

#[cfg(feature = "tui")]
impl Drop for TuiWriterInner {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}
