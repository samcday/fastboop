use std::fs;
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use fastboop_core::{
    encode_channel_index_record_from_locations, scan_channel_head_record_locations,
};
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

    let indexed = index_channel_bytes(input_bytes.as_slice())?;
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

fn index_channel_bytes(input: &[u8]) -> Result<Vec<u8>> {
    let (locations, _consumed) = scan_channel_head_record_locations(input, input.len() as u64)
        .map_err(|err| anyhow!("{err}"))?;
    if locations.is_empty() {
        return Err(anyhow!("channel contains no head records to index"));
    }
    let index_record = encode_channel_index_record_from_locations(locations.as_slice())
        .map_err(|err| anyhow!("{err}"))?;
    let mut out = Vec::with_capacity(index_record.len() + input.len());
    out.extend_from_slice(index_record.as_slice());
    out.extend_from_slice(input);
    Ok(out)
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

#[cfg(test)]
mod tests {
    use fastboop_core::{
        ChannelHeadRecord, encode_channel_head, encode_channel_pipeline_hints_record,
        read_channel_stream_head,
    };
    use gibblox_pipeline::{
        PipelineContentDigestHint, PipelineHint, PipelineHintEntry, PipelineHints,
    };

    use super::*;

    fn sample_hints(url_suffix: &str) -> PipelineHints {
        PipelineHints {
            entries: vec![PipelineHintEntry {
                pipeline_identity: format!(
                    "xz{{source=http{{url=len:22:https://example.com/{url_suffix};}}}}",
                ),
                hints: vec![PipelineHint::ContentDigest(PipelineContentDigestHint {
                    digest: String::from(
                        "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    size_bytes: 1,
                })],
            }],
        }
    }

    #[test]
    fn index_channel_bytes_wraps_hints_only_channel() {
        let hints = sample_hints("a");
        let record_bytes = encode_channel_pipeline_hints_record(&hints).unwrap();
        let indexed = index_channel_bytes(record_bytes.as_slice()).unwrap();

        assert!(indexed.starts_with(b"FBCHIDX0"));
        assert!(indexed.len() > record_bytes.len());

        let head = read_channel_stream_head(indexed.as_slice(), indexed.len() as u64).unwrap();
        assert!(head.pipeline_hints.entries.is_empty());
        assert_eq!(head.pipeline_hint_records.len(), 1);
        assert_eq!(
            head.pipeline_hint_records[0].pipeline_identities,
            vec![String::from(
                "xz{source=http{url=len:22:https://example.com/a;}}"
            )]
        );
        assert_eq!(head.consumed_bytes, indexed.len() as u64);
    }

    #[test]
    fn index_channel_bytes_preserves_trailing_artifact() {
        let hints = sample_hints("a");
        let record_bytes = encode_channel_pipeline_hints_record(&hints).unwrap();
        let mut trailing = vec![0u8; 2048];
        // Erofs magic lives at offset 1024 within a block.
        trailing[1024..1028].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());

        let mut stream = Vec::new();
        stream.extend_from_slice(record_bytes.as_slice());
        stream.extend_from_slice(trailing.as_slice());

        let indexed = index_channel_bytes(stream.as_slice()).unwrap();
        assert!(indexed.starts_with(b"FBCHIDX0"));

        // The input bytes are copied verbatim after the index header,
        // so the trailing artifact survives byte-for-byte.
        let tail_start = indexed.len() - stream.len();
        assert_eq!(&indexed[tail_start..], stream.as_slice());

        let head = read_channel_stream_head(indexed.as_slice(), indexed.len() as u64).unwrap();
        assert_eq!(head.pipeline_hint_records.len(), 1);
        // consumed_bytes excludes the trailing artifact.
        assert!(head.consumed_bytes < indexed.len() as u64);
        // The artifact starts right after consumed_bytes within the indexed
        // stream: this is the boundary OffsetChannelBlockReader uses.
        assert_eq!(
            head.consumed_bytes as usize,
            tail_start + record_bytes.len(),
        );
    }

    #[test]
    fn index_channel_bytes_rejects_already_indexed_input() {
        let indexed =
            encode_channel_head(&[ChannelHeadRecord::PipelineHints(sample_hints("a"))]).unwrap();
        let err = index_channel_bytes(indexed.as_slice()).unwrap_err();
        let message = format!("{err}");
        assert!(
            message.contains("already begins"),
            "expected already-indexed rejection, got {message}"
        );
    }

    #[test]
    fn index_channel_bytes_rejects_empty_channel() {
        let err = index_channel_bytes(&[]).unwrap_err();
        let message = format!("{err}");
        assert!(
            message.contains("no head records"),
            "expected empty rejection, got {message}"
        );
    }
}
