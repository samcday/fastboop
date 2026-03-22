use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use fastboop_core::{ChannelStreamKind, classify_channel_prefix, read_channel_stream_head};

#[derive(Args)]
pub struct ShowArgs {
    /// Input channel/profile path or URL ("-" for stdin bytes).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output report path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
}

pub async fn run_show(args: ShowArgs) -> Result<()> {
    let rendered = if args.input == "-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("reading input from stdin")?;
        let stream = read_channel_stream_head(bytes.as_slice(), bytes.len() as u64)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        let kind = classify_channel_prefix(bytes.as_slice());
        render_show_report(
            io_label(&args.input).as_str(),
            kind,
            stream,
            bytes.len() as u64,
        )?
    } else {
        let source = super::open_channel_source_reader(Path::new(args.input.as_str())).await?;
        let kind = super::classify_channel_reader(source.reader.as_ref()).await?;
        let stream = super::read_channel_stream_head_from_reader(
            source.reader.as_ref(),
            source.exact_size_bytes,
        )
        .await?;
        render_show_report(args.input.as_str(), kind, stream, source.exact_size_bytes)?
    };

    write_output_bytes(args.output.as_str(), rendered.as_bytes())
}

fn render_show_report(
    input_label: &str,
    kind: ChannelStreamKind,
    stream: fastboop_core::ChannelStreamHead,
    total_bytes: u64,
) -> Result<String> {
    if stream.warning_count > 0 {
        eprintln!(
            "warning: channel stream has {} warning(s) while scanning leading records; parsed {} bytes",
            stream.warning_count, stream.consumed_bytes
        );
    }

    if stream.boot_profiles.is_empty()
        && stream.dev_profiles.is_empty()
        && stream.pipeline_hint_entry_count() == 0
    {
        match kind {
            ChannelStreamKind::Unknown => {
                eprintln!(
                    "warning: no embedded boot/dev profile or pipeline-hints records were found, and the input format is unrecognized"
                );
            }
            _ => {
                eprintln!(
                    "warning: no embedded boot/dev profile or pipeline-hints records were found; detected payload kind is '{}'",
                    render_kind(kind)
                );
            }
        }
    } else if stream.consumed_bytes < total_bytes {
        eprintln!(
            "warning: {} trailing byte(s) were not rendered as profile resources",
            total_bytes - stream.consumed_bytes
        );
    }

    let mut out = String::new();
    out.push_str("== Channel Summary ==\n");
    out.push_str(format!("input: {input_label}\n").as_str());
    out.push_str(format!("detected_kind: {}\n", render_kind(kind)).as_str());
    out.push_str(format!("total_bytes: {total_bytes}\n").as_str());
    out.push_str(format!("consumed_bytes: {}\n", stream.consumed_bytes).as_str());
    out.push_str(format!("boot_profiles: {}\n", stream.boot_profiles.len()).as_str());
    out.push_str(format!("dev_profiles: {}\n", stream.dev_profiles.len()).as_str());
    out.push_str(
        format!(
            "pipeline_hint_entries: {}\n",
            stream.pipeline_hint_entry_count()
        )
        .as_str(),
    );
    out.push('\n');

    for profile in stream.boot_profiles {
        out.push_str(format!("== Boot Profile: {} ==\n", profile.id).as_str());
        let yaml = super::bootprofile::render_boot_profile_yaml(&profile)?;
        out.push_str(yaml.as_str());
        if !yaml.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }

    for profile in stream.dev_profiles {
        out.push_str(format!("== Device Profile: {} ==\n", profile.id).as_str());
        let yaml = serde_yaml::to_string(&profile).context("serializing device profile YAML")?;
        out.push_str(yaml.as_str());
        if !yaml.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }

    if !stream.pipeline_hints.entries.is_empty() {
        out.push_str("== Pipeline Hints ==\n");
        let yaml = serde_yaml::to_string(&stream.pipeline_hints)
            .context("serializing pipeline hints YAML")?;
        out.push_str(yaml.as_str());
        if !yaml.ends_with('\n') {
            out.push('\n');
        }
    } else if !stream.pipeline_hint_records.is_empty() {
        out.push_str("== Pipeline Hints ==\n");
        out.push_str("details: deferred (indexed during channel intake)\n");
        out.push_str(format!("records: {}\n", stream.pipeline_hint_records.len()).as_str());
    }

    Ok(out)
}

fn render_kind(kind: ChannelStreamKind) -> &'static str {
    match kind {
        ChannelStreamKind::ProfileBundleV1 => "profile-bundle-v1",
        ChannelStreamKind::Xz => "xz",
        ChannelStreamKind::Zip => "zip",
        ChannelStreamKind::AndroidSparse => "android-sparse",
        ChannelStreamKind::Gpt => "gpt",
        ChannelStreamKind::Iso9660 => "iso9660",
        ChannelStreamKind::Erofs => "erofs",
        ChannelStreamKind::Ext4 => "ext4",
        ChannelStreamKind::Fat => "fat",
        ChannelStreamKind::Mbr => "mbr",
        ChannelStreamKind::Unknown => "unknown",
    }
}

fn write_output_bytes(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(bytes)
            .context("writing output to stdout")?;
        stdout.flush().context("flushing stdout")?;
        return Ok(());
    }

    fs::write(path, bytes).with_context(|| format!("writing {}", io_label(path)))
}

fn io_label(path: &str) -> String {
    if path == "-" {
        "stdin/stdout".to_string()
    } else {
        path.to_string()
    }
}
