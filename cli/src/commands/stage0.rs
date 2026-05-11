use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use fastboop_environment_std::{NativeBootStage0Config, build_stage0_initrd, parse_ostree_arg};

#[derive(Args)]
pub struct Stage0Args {
    /// Path or HTTP(S) URL to a channel artifact containing kernel/modules.
    #[arg(value_name = "CHANNEL")]
    pub channel: PathBuf,
    /// Resolve kernel/modules inside this OSTree deployment path (`--ostree` auto-detects).
    #[arg(long, value_name = "PATH", num_args = 0..=1)]
    pub ostree: Option<Option<String>>,
    /// Device profile id to use (must be present in loaded DevPros).
    #[arg(long, required = true)]
    pub device_profile: String,
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
    /// Local artifact file to short-circuit matching pipeline stages (repeatable).
    #[arg(long = "local-artifact", value_name = "PATH")]
    pub local_artifact: Vec<PathBuf>,
}

pub async fn run_stage0(args: Stage0Args) -> Result<()> {
    let output = build_stage0_initrd(NativeBootStage0Config {
        channel: args.channel,
        ostree: parse_ostree_arg(args.ostree.as_ref())?,
        device_profile: Some(args.device_profile),
        boot_profile: args.boot_profile,
        dtb: args.dtb,
        dtbo: args.dtbo,
        augment: args.augment,
        stage0: args.stage0,
        require_modules: args.require_modules,
        cmdline_append: args.cmdline_append,
        serial: args.serial,
        impersonate_fastboot: args.impersonate_fastboot,
        smoo_queue_count: None,
        smoo_queue_depth: None,
        smoo_max_io: None,
        local_artifact: args.local_artifact,
    })
    .await?;

    for warning in &output.warnings {
        eprintln!("{warning}");
    }

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output.initrd)
        .context("writing initrd to stdout")?;
    eprintln!("Kernel cmdline append: {}", output.kernel_cmdline_append);
    eprintln!(
        "Kernel: {} ({} bytes); init: {}",
        output.kernel_path, output.kernel_image_len, output.init_path
    );
    Ok(())
}
