use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use fastboop_erofs_rootfs::open_erofs_rootfs;
use fastboop_stage0_generator::{Stage0Options, build_stage0};

use crate::devpros::{load_device_profiles, resolve_devpro_dirs};

use super::{read_dtbo_overlays, read_existing_initrd};

#[derive(Args)]
pub struct Stage0Args {
    /// Path or HTTP(S) URL to EROFS image containing kernel/modules.
    #[arg(value_name = "ROOTFS")]
    pub rootfs: PathBuf,
    /// Device profile id to use (must be present in loaded DevPros).
    #[arg(long, required = true)]
    pub device_profile: String,
    /// Override DTB path (host path).
    #[arg(long)]
    pub dtb: Option<PathBuf>,
    /// DTBO overlay to apply (repeatable).
    #[arg(long)]
    pub dtbo: Vec<PathBuf>,
    /// Existing initrd (cpio newc) to augment.
    #[arg(long)]
    pub augment: Option<PathBuf>,
    /// Extra required modules (repeatable).
    #[arg(long = "require-module")]
    pub require_modules: Vec<String>,
    /// Extra kernel cmdline to append after generated stage0 arguments.
    #[arg(long, alias = "cmdline")]
    pub cmdline_append: Option<String>,
    /// Enable CDC-ACM gadget (smoo.acm=1) and include usb_f_acm.
    #[arg(long)]
    pub serial: bool,
}

pub fn run_stage0(args: Stage0Args) -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    let profile = profiles
        .get(&args.device_profile)
        .or_else(|| profiles.get(&format!("file:{}", args.device_profile)));
    let profile = profile.with_context(|| {
        let mut ids: Vec<_> = profiles
            .keys()
            .filter(|k| !k.starts_with("file:"))
            .cloned()
            .collect();
        ids.sort();
        format!(
            "device profile '{}' not found in {:?}; available ids: {:?}",
            args.device_profile, devpro_dirs, ids
        )
    })?;

    let dtb_override = match &args.dtb {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("reading dtb {}", path.display()))?)
        }
        None => None,
    };

    let dtbo_overlays = read_dtbo_overlays(&args.dtbo)?;
    let opts = Stage0Options {
        extra_modules: args.require_modules,
        dtb_override,
        dtbo_overlays,

        enable_serial: args.serial,
        personalization: None,
    };

    let existing = read_existing_initrd(&args.augment)?;
    let rootfs_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create tokio runtime for rootfs reads")?;
    let build = rootfs_rt
        .block_on(async {
            let opened = open_erofs_rootfs(&args.rootfs.to_string_lossy()).await?;
            let build = build_stage0(
                profile,
                &opened.provider,
                &opts,
                args.cmdline_append.as_deref(),
                existing.as_deref(),
            )
            .await;
            anyhow::Ok(build)
        })?
        .map_err(|e| anyhow::anyhow!("stage0 build failed: {e:?}"))?;

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&build.initrd)
        .context("writing initrd to stdout")?;
    eprintln!("Kernel cmdline append: {}", build.kernel_cmdline_append);
    eprintln!(
        "Kernel: {} ({} bytes); init: {}",
        build.kernel_path,
        build.kernel_image.len(),
        build.init_path
    );
    Ok(())
}
