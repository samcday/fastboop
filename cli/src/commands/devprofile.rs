use std::collections::BTreeMap;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use crate::devpros::{load_local_device_profiles, resolve_devpro_dirs};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::{DeviceProfile, decode_dev_profile, encode_dev_profile};

use super::ArtifactReaderResolver;

#[derive(Args)]
pub struct DevProfileArgs {
    #[command(subcommand)]
    pub command: DevProfileCommand,
}

#[derive(Subcommand)]
pub enum DevProfileCommand {
    /// Compile a YAML/JSON device profile into binary form.
    Create(DevProfileCreateArgs),
    /// Render a compiled device profile binary as YAML.
    Show(DevProfileShowArgs),
    /// List available device profiles.
    List(DevProfileListArgs),
}

#[derive(Args)]
pub struct DevProfileCreateArgs {
    /// Input device profile document path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output compiled device profile path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
}

#[derive(Args)]
pub struct DevProfileShowArgs {
    /// Input compiled device profile path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output YAML path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
}

#[derive(Args)]
pub struct DevProfileListArgs {
    /// Include device profiles embedded in a channel stream.
    #[arg(long, value_name = "CHANNEL")]
    pub channel: Option<PathBuf>,
}

pub async fn run_devprofile(args: DevProfileArgs) -> Result<()> {
    match args.command {
        DevProfileCommand::Create(args) => run_create(args),
        DevProfileCommand::Show(args) => run_show(args),
        DevProfileCommand::List(args) => run_list(args).await,
    }
}

fn run_create(args: DevProfileCreateArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let profile: DeviceProfile = serde_yaml::from_slice(&input)
        .with_context(|| format!("parsing device profile document {}", io_label(&args.input)))?;

    let bytes = encode_dev_profile(&profile).context("encoding device profile binary")?;

    validate_binary_output(
        &args.output,
        "devprofile create",
        std::io::stdout().is_terminal(),
    )?;
    write_output_bytes(&args.output, &bytes)
}

fn run_show(args: DevProfileShowArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let profile = decode_dev_profile(&input).map_err(|err| anyhow!("{err}"))?;

    let yaml = serde_yaml::to_string(&profile).context("serializing device profile YAML")?;
    write_output_bytes(&args.output, yaml.as_bytes())
}

#[derive(Default)]
struct ProfileSourceSet {
    builtin: bool,
    local: bool,
    channel: bool,
}

impl ProfileSourceSet {
    fn add_local(&mut self) {
        self.local = true;
    }

    fn add_channel(&mut self) {
        self.channel = true;
    }

    fn render(&self) -> String {
        let mut labels = Vec::new();
        if self.builtin {
            labels.push("builtin");
        }
        if self.local {
            labels.push("local");
        }
        if self.channel {
            labels.push("channel");
        }
        labels.join(",")
    }
}

#[derive(Default)]
struct ProfileListEntry {
    profile: Option<DeviceProfile>,
    source: ProfileSourceSet,
}

async fn run_list(args: DevProfileListArgs) -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let mut entries = builtins_with_source()?;

    let mut local_profiles = load_local_device_profiles(&devpro_dirs)?;
    for profile in local_profiles.drain().map(|(_, profile)| profile) {
        if let Some(entry) = entries.get_mut(profile.id.as_str()) {
            entry.source.add_local();
            entry.profile = Some(profile);
        } else {
            entries.insert(
                profile.id.clone(),
                ProfileListEntry {
                    profile: Some(profile),
                    source: ProfileSourceSet {
                        builtin: false,
                        local: true,
                        channel: false,
                    },
                },
            );
        }
    }

    if let Some(channel) = args.channel {
        let resolver = ArtifactReaderResolver::new();
        let head = resolver
            .read_channel_stream_head(&channel)
            .await
            .with_context(|| {
                format!("reading channel profile stream head {}", channel.display())
            })?;

        if head.warning_count > 0 {
            eprintln!(
                "channel stream has {} warning(s) while reading profile head; using {} bytes of leading records",
                head.warning_count, head.consumed_bytes
            );
        }

        for profile in head.dev_profiles {
            if let Some(entry) = entries.get_mut(profile.id.as_str()) {
                entry.source.add_channel();
                continue;
            }

            entries.insert(
                profile.id.clone(),
                ProfileListEntry {
                    profile: Some(profile),
                    source: ProfileSourceSet {
                        builtin: false,
                        local: false,
                        channel: true,
                    },
                },
            );
        }
    }

    for entry in entries.values() {
        let Some(profile) = entry.profile.as_ref() else {
            continue;
        };
        let Some(name) = profile.display_name.as_deref() else {
            println!("{:40} [{}]", profile.id, entry.source.render());
            continue;
        };
        println!("{:40} {:24} [{}]", profile.id, name, entry.source.render());
    }

    Ok(())
}

fn builtins_with_source() -> Result<BTreeMap<String, ProfileListEntry>> {
    let profiles = builtin_profiles().context("loading builtin device profiles")?;
    let mut entries = BTreeMap::new();
    for profile in profiles {
        entries.insert(
            profile.id.clone(),
            ProfileListEntry {
                profile: Some(profile),
                source: ProfileSourceSet {
                    builtin: true,
                    ..Default::default()
                },
            },
        );
    }
    Ok(entries)
}

fn read_input_bytes(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading input from stdin")?;
        return Ok(buf);
    }

    fs::read(path).with_context(|| format!("reading {}", io_label(path)))
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

fn validate_binary_output(path: &str, command: &str, stdout_is_tty: bool) -> Result<()> {
    if path == "-" && stdout_is_tty {
        bail!(
            "{} output is binary and terminal output is disabled by default; use --output <FILE>",
            command
        );
    }
    Ok(())
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
    use super::*;

    #[test]
    fn parses_yaml_and_roundtrips() {
        let yaml = r#"
id: dev-one
display_name: Dev One
devicetree_name: oneplus,enchilada
match:
  - fastboot:
      vid: 0x18d1
      pid: 0x4ee1
boot:
  fastboot_boot:
    android_bootimg:
      header_version: 2
      page_size: 4096
      kernel:
        encoding: image
stage0: {}
probe: []
"#;

        let profile: DeviceProfile = serde_yaml::from_str(yaml).expect("parse device profile");
        let encoded = encode_dev_profile(&profile).expect("encode device profile");
        let decoded = decode_dev_profile(&encoded).expect("decode device profile");

        assert_eq!(decoded.id, profile.id);
        assert_eq!(decoded.devicetree_name, profile.devicetree_name);
        assert_eq!(decoded.r#match.len(), profile.r#match.len());
        assert_eq!(
            decoded.r#match[0].fastboot.vid,
            profile.r#match[0].fastboot.vid
        );
        assert_eq!(
            decoded.r#match[0].fastboot.pid,
            profile.r#match[0].fastboot.pid
        );
    }

    #[test]
    fn create_output_rejects_tty_stdout() {
        let err = validate_binary_output("-", "devprofile create", true)
            .expect_err("expected tty stdout to be rejected");
        let message = format!("{err}");
        assert!(message.contains("terminal output is disabled by default"));
    }

    #[test]
    fn create_output_allows_non_tty_stdout() {
        assert!(
            validate_binary_output("-", "devprofile create", false).is_ok(),
            "expected non-tty stdout to be allowed"
        );
    }
}
