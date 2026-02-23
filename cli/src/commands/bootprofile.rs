use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use fastboop_core::{
    BootProfileManifest, decode_boot_profile, encode_boot_profile, validate_boot_profile,
};

#[derive(Args)]
pub struct BootProfileArgs {
    #[command(subcommand)]
    pub command: BootProfileCommand,
}

#[derive(Subcommand)]
pub enum BootProfileCommand {
    /// Compile a YAML/JSON boot profile into binary form.
    Create(BootProfileCreateArgs),
    /// Render a compiled boot profile binary as YAML.
    Show(BootProfileShowArgs),
}

#[derive(Args)]
pub struct BootProfileCreateArgs {
    /// Input boot profile document path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output compiled boot profile path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
}

#[derive(Args)]
pub struct BootProfileShowArgs {
    /// Input compiled boot profile path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output YAML path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
}

pub fn run_bootprofile(args: BootProfileArgs) -> Result<()> {
    match args.command {
        BootProfileCommand::Create(args) => run_create(args),
        BootProfileCommand::Show(args) => run_show(args),
    }
}

fn run_create(args: BootProfileCreateArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let manifest: BootProfileManifest = serde_yaml::from_slice(&input)
        .with_context(|| format!("parsing boot profile document {}", io_label(&args.input)))?;

    let compiled = manifest
        .compile_dt_overlays(compile_dt_overlay)
        .context("compiling dt_overlays with dtc")?;

    validate_boot_profile(&compiled).map_err(|err| anyhow!("{err}"))?;

    let bytes = encode_boot_profile(&compiled).context("encoding boot profile binary")?;
    write_output_bytes(&args.output, &bytes)
}

fn run_show(args: BootProfileShowArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let compiled = decode_boot_profile(&input).map_err(|err| anyhow!("{err}"))?;

    validate_boot_profile(&compiled).map_err(|err| anyhow!("{err}"))?;

    let manifest = compiled
        .decompile_dt_overlays(decompile_dt_overlay)
        .context("decompiling dt_overlays with dtc")?;

    let yaml = serde_yaml::to_string(&manifest).context("serializing boot profile YAML")?;
    write_output_bytes(&args.output, yaml.as_bytes())
}

fn compile_dt_overlay(dtso: &str) -> Result<Vec<u8>> {
    run_dtc(
        &["-@", "-I", "dts", "-O", "dtb", "-o", "-", "-"],
        dtso.as_bytes(),
        "compile DTS overlay",
    )
}

fn decompile_dt_overlay(dtbo: &[u8]) -> Result<String> {
    let output = run_dtc(
        &["-I", "dtb", "-O", "dts", "-o", "-", "-"],
        dtbo,
        "decompile DT overlay",
    )?;
    String::from_utf8(output).map_err(|err| anyhow!("dtc produced non-UTF8 output: {err}"))
}

fn run_dtc(args: &[&str], input: &[u8], context: &str) -> Result<Vec<u8>> {
    let mut child = Command::new("dtc")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning dtc to {context}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open dtc stdin"))?;
    let write_result = stdin.write_all(input);
    drop(stdin);

    if let Err(err) = write_result {
        let output = child
            .wait_with_output()
            .with_context(|| format!("waiting for dtc after write failure for {context}"))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            return Err(err).with_context(|| format!("writing input to dtc for {context}"));
        }
        return Err(anyhow!(
            "writing input to dtc for {context}: {err}; dtc stderr: {stderr}"
        ));
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for dtc to {context}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("dtc failed to {context} (status: {})", output.status);
        }
        bail!("dtc failed to {context}: {stderr}");
    }
    Ok(output.stdout)
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
    use fastboop_core::{BootProfileArtifactSource, BootProfileRootfs};

    #[test]
    fn parses_nested_rootfs_pipeline_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: pmos-fajita
rootfs:
  ext4:
    gpt:
      partlabel: rootfs
      android_sparseimg:
        xz:
          http: https://images.postmarketos.org/example.img.xz
"#,
        )
        .expect("parse manifest");

        match manifest.rootfs {
            BootProfileRootfs::Ext4(_) => {}
            other => panic!("expected ext4 rootfs, got {other:?}"),
        }
    }

    #[test]
    fn parses_file_rootfs_source_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: local-erofs
rootfs:
  erofs:
    file: ./images/rootfs.ero
"#,
        )
        .expect("parse manifest");

        let source = manifest.rootfs.source();
        match source {
            BootProfileArtifactSource::File(source) => {
                assert_eq!(source.file, "./images/rootfs.ero")
            }
            other => panic!("expected file source, got {other:?}"),
        }
    }

    #[test]
    fn parses_kernel_and_dtbs_profile_sources() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: pmos-fajita
rootfs:
  ext4:
    gpt:
      index: 1
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
kernel:
  path: /vmlinuz
  ext4:
    gpt:
      index: 0
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
dtbs:
  path: /dtbs
  ext4:
    gpt:
      index: 0
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
"#,
        )
        .expect("parse manifest");

        let kernel = manifest.kernel.expect("kernel source");
        assert_eq!(kernel.path, "/vmlinuz");
        let dtbs = manifest.dtbs.expect("dtbs source");
        assert_eq!(dtbs.path, "/dtbs");
    }
}
