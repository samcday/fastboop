use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use fastboop_core::FastbootBoot;
use fastboop_environment_std::{
    NativeBootConfig, NativeBootEnvironment, NativeBootStage0Config, parse_ostree_arg,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Args)]
pub struct BootStage0Args {
    /// Path or HTTP(S) URL to a channel artifact containing kernel/modules.
    #[arg(value_name = "CHANNEL")]
    pub channel: PathBuf,
    /// Resolve kernel/modules inside this OSTree deployment path (`--ostree` auto-detects).
    #[arg(long, value_name = "PATH", num_args = 0..=1)]
    pub ostree: Option<Option<String>>,
    /// Device profile id to use. If omitted, fastboop auto-probes matching profiles.
    #[arg(long)]
    pub device_profile: Option<String>,
    /// Boot profile id to select when channel starts with a boot profile stream.
    #[arg(long)]
    pub boot_profile: Option<String>,
    /// Override DTB path (host path).
    #[arg(long)]
    pub dtb: Option<PathBuf>,
    /// DTBO overlay to apply (repeatable).
    #[arg(long)]
    pub dtbo: Vec<PathBuf>,
    /// Existing initrd (cpio newc) to augment.
    #[arg(long)]
    pub augment: Option<PathBuf>,
    /// Stage0 binary to inject as /init (defaults to FASTBOOP_STAGE0_PATH or local/package paths).
    #[arg(long, value_name = "PATH")]
    pub stage0: Option<PathBuf>,
    /// Extra required modules (repeatable).
    #[arg(long = "require-module")]
    pub require_modules: Vec<String>,
    /// Extra kernel cmdline to append after generated stage0 arguments.
    #[arg(long, alias = "cmdline")]
    pub cmdline_append: Option<String>,
    /// Enable CDC-ACM gadget (smoo.acm=1) and include usb_f_acm.
    #[arg(long)]
    pub serial: bool,
    /// Mimic fastboot USB protocol identity so existing fastboot udev rules apply
    /// (use --impersonate-fastboot=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub impersonate_fastboot: bool,
    /// Number of smoo/ublk queues to configure in stage0 (default: 1).
    #[arg(long = "smoo-queue-count", value_name = "N", value_parser = parse_nonzero_u16)]
    pub smoo_queue_count: Option<u16>,
    /// Depth of each smoo/ublk queue configured in stage0 (default: 16).
    #[arg(long = "smoo-queue-depth", value_name = "N", value_parser = parse_nonzero_u16)]
    pub smoo_queue_depth: Option<u16>,
    /// Maximum per-I/O size advertised by smoo in stage0 (default: 1 MiB).
    #[arg(long = "smoo-max-io", value_name = "BYTES", value_parser = parse_byte_size)]
    pub smoo_max_io: Option<usize>,
    /// Local artifact file to short-circuit matching pipeline stages (repeatable).
    #[arg(long = "local-artifact", value_name = "PATH")]
    pub local_artifact: Vec<PathBuf>,
}

#[derive(Args)]
pub struct BootArgs {
    #[command(flatten)]
    pub stage0: BootStage0Args,
    /// Write boot image to a file and skip device detection/boot.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// ABL exorcist raw arm64 Image shim to wrap around the selected kernel.
    #[arg(long = "abl-exorcist", value_name = "PATH")]
    pub abl_exorcist: Option<PathBuf>,
    /// Append host time to cmdline as systemd.clock_usec=... (use --system-time=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub system_time: bool,
    /// Append systemd-firstboot credentials (use --systemd-firstboot=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub systemd_firstboot: bool,
    /// Wait up to N seconds for a matching device (0 = infinite).
    #[arg(long, default_value_t = 0)]
    pub wait: u64,
    /// Expose fastboop's smoo host metrics on this TCP port (0 disables).
    #[arg(long = "smoo-metrics-port", default_value_t = 0)]
    pub smoo_metrics_port: u16,
}

pub async fn run_boot(args: BootArgs) -> Result<()> {
    let output = args.output.clone();
    let config = native_boot_config_from_args(&args)?;
    let mut env = NativeBootEnvironment::new(config, CancellationToken::new());

    info!(channel = %args.stage0.channel.display(), "preparing boot payload");
    let prepared = env.prepare_boot().await?;
    if let Some(path) = output {
        std::fs::write(&path, &prepared.boot_image)
            .with_context(|| format!("writing bootimg to {}", path.display()))?;
        info!(path = %path.display(), bytes = prepared.boot_image.len(), "wrote boot image");
        return Ok(());
    }

    info!(
        bytes = prepared.boot_image.len(),
        "opening fastboot transport"
    );
    let mut fastboot = env.connect_fastboot().await?;
    info!(bytes = prepared.boot_image.len(), "issuing fastboot boot");
    FastbootBoot::new(&prepared.boot_image)
        .run(&mut fastboot)
        .await
        .map_err(|err| anyhow!("fastboot handoff failed: {err}"))?;

    info!(identity = %prepared.export.identity, size_bytes = prepared.export.size_bytes, "serving smoo runtime");
    env.serve_runtime(prepared.export).await
}

fn native_boot_config_from_args(args: &BootArgs) -> Result<NativeBootConfig> {
    Ok(NativeBootConfig {
        stage0: NativeBootStage0Config {
            channel: args.stage0.channel.clone(),
            ostree: parse_ostree_arg(args.stage0.ostree.as_ref())?,
            device_profile: args.stage0.device_profile.clone(),
            boot_profile: args.stage0.boot_profile.clone(),
            dtb: args.stage0.dtb.clone(),
            dtbo: args.stage0.dtbo.clone(),
            augment: args.stage0.augment.clone(),
            stage0: args.stage0.stage0.clone(),
            require_modules: args.stage0.require_modules.clone(),
            cmdline_append: args.stage0.cmdline_append.clone(),
            serial: args.stage0.serial,
            impersonate_fastboot: args.stage0.impersonate_fastboot,
            smoo_queue_count: args.stage0.smoo_queue_count,
            smoo_queue_depth: args.stage0.smoo_queue_depth,
            smoo_max_io: args.stage0.smoo_max_io,
            abl_exorcist: args.abl_exorcist.clone(),
            local_artifact: args.stage0.local_artifact.clone(),
        },
        boot_device: args.output.is_none(),
        system_time: args.system_time,
        systemd_firstboot: args.systemd_firstboot,
        wait: Duration::from_secs(args.wait),
        smoo_metrics_port: args.smoo_metrics_port,
    })
}

fn parse_nonzero_u16(input: &str) -> std::result::Result<u16, String> {
    let value = input.parse::<u16>().map_err(|err| err.to_string())?;
    if value == 0 {
        return Err("value must be non-zero".to_string());
    }
    Ok(value)
}

fn parse_byte_size(input: &str) -> std::result::Result<usize, String> {
    let input = input.trim();
    let digits = input
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(input.len());
    if digits == 0 {
        return Err("byte size must start with a number".to_string());
    }

    let value = input[..digits]
        .parse::<usize>()
        .map_err(|err| err.to_string())?;
    if value == 0 {
        return Err("byte size must be non-zero".to_string());
    }

    let suffix = input[digits..].trim().to_ascii_lowercase();
    let multiplier = match suffix.as_str() {
        "" | "b" => 1usize,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => {
            return Err(format!(
                "unsupported byte-size suffix {suffix:?}; use B, KiB, MiB, or GiB"
            ));
        }
    };

    value
        .checked_mul(multiplier)
        .ok_or_else(|| "byte size overflows usize".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_size_accepts_raw_and_binary_suffixes() {
        assert_eq!(parse_byte_size("4096").unwrap(), 4096);
        assert_eq!(parse_byte_size("256KiB").unwrap(), 256 * 1024);
        assert_eq!(parse_byte_size("1 MiB").unwrap(), 1024 * 1024);
    }

    #[test]
    fn parse_byte_size_rejects_zero_and_unknown_suffixes() {
        assert!(parse_byte_size("0").is_err());
        assert!(parse_byte_size("1TiB").is_err());
    }

    #[test]
    fn parse_nonzero_u16_rejects_zero() {
        assert_eq!(parse_nonzero_u16("1").unwrap(), 1);
        assert!(parse_nonzero_u16("0").is_err());
    }
}
