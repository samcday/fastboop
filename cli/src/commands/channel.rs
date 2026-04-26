use std::fs;
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use fastboop_core::index_channel_bytes;
use tracing::{debug, info};

#[derive(Args)]
pub struct ChannelArgs {
    #[command(subcommand)]
    pub command: ChannelCommand,
}

#[derive(Subcommand)]
pub enum ChannelCommand {
    /// Scan a concatenated-records channel and emit an indexed variant.
    ///
    /// The sequential walk is still a first-class input shape; indexing is
    /// an optional accelerator for channels large or numerous enough that
    /// the single-threaded decode stage becomes a bottleneck over HTTP.
    Index(ChannelIndexArgs),
}

#[derive(Args)]
pub struct ChannelIndexArgs {
    /// Input channel path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output indexed channel path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
}

pub async fn run_channel(args: ChannelArgs) -> Result<()> {
    match args.command {
        ChannelCommand::Index(args) => run_channel_index(args).await,
    }
}

async fn run_channel_index(args: ChannelIndexArgs) -> Result<()> {
    debug!(
        input = %io_label(&args.input),
        output = %io_label(&args.output),
        "channel index started"
    );

    let input_bytes = read_input_bytes(&args.input)?;
    debug!(bytes = input_bytes.len(), "channel index read input");

    let indexed = index_channel_bytes(input_bytes.as_slice()).map_err(|err| anyhow!("{err}"))?;
    info!(
        input_bytes = input_bytes.len(),
        indexed_bytes = indexed.len(),
        "channel index emitted indexed channel"
    );

    write_output_bytes(&args.output, indexed.as_slice())?;
    debug!(
        output = %io_label(&args.output),
        "channel index finished"
    );
    Ok(())
}

fn read_input_bytes(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .context("reading channel bytes from stdin")?;
        Ok(buffer)
    } else {
        fs::read(path).with_context(|| format!("reading channel bytes from {path}"))
    }
}

fn write_output_bytes(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(bytes)
            .context("writing indexed channel to stdout")?;
        stdout.flush().context("flushing stdout")?;
        return Ok(());
    }
    fs::write(path, bytes).with_context(|| format!("writing indexed channel to {path}"))
}

fn io_label(path: &str) -> String {
    if path == "-" {
        "stdin/stdout".to_string()
    } else {
        path.to_string()
    }
}
