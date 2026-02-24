use std::fs;
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use fastboop_core::{DeviceProfile, decode_dev_profile, encode_dev_profile};

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

pub fn run_devprofile(args: DevProfileArgs) -> Result<()> {
    match args.command {
        DevProfileCommand::Create(args) => run_create(args),
        DevProfileCommand::Show(args) => run_show(args),
    }
}

fn run_create(args: DevProfileCreateArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let profile: DeviceProfile = serde_yaml::from_slice(&input)
        .with_context(|| format!("parsing device profile document {}", io_label(&args.input)))?;

    let bytes = encode_dev_profile(&profile).context("encoding device profile binary")?;
    write_output_bytes(&args.output, &bytes)
}

fn run_show(args: DevProfileShowArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let profile = decode_dev_profile(&input).map_err(|err| anyhow!("{err}"))?;

    let yaml = serde_yaml::to_string(&profile).context("serializing device profile YAML")?;
    write_output_bytes(&args.output, yaml.as_bytes())
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
}
