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
    stdin
        .write_all(input)
        .with_context(|| format!("writing input to dtc for {context}"))?;
    drop(stdin);

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
