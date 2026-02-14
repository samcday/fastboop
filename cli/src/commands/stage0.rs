use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use fastboop_rootfs_erofs::ErofsRootfs;
use fastboop_stage0_generator::{Stage0Options, build_stage0};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_core::BlockReader;
use gibblox_file::StdFileBlockReader;
use gibblox_http::HttpBlockReader;
use url::Url;

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

pub async fn run_stage0(args: Stage0Args) -> Result<()> {
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
        mimic_fastboot: false,
        smoo_vendor: None,
        smoo_product: None,
        smoo_serial: None,
        personalization: None,
    };

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

    let existing = read_existing_initrd(&args.augment)?;
    let build = {
        let rootfs_str = args.rootfs.to_string_lossy();

        // Build gibblox pipeline explicitly
        let reader: Arc<dyn BlockReader> =
            if rootfs_str.starts_with("http://") || rootfs_str.starts_with("https://") {
                // HTTP pipeline: HTTP → Cache
                let url = Url::parse(&rootfs_str)
                    .with_context(|| format!("parse rootfs URL {rootfs_str}"))?;
                let http_reader = HttpBlockReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
                    .await
                    .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;

                let cache = StdCacheOps::open_default_for_reader(&http_reader)
                    .await
                    .map_err(|err| anyhow!("open std cache: {err}"))?;
                let cached = CachedBlockReader::new(http_reader, cache)
                    .await
                    .map_err(|err| anyhow!("initialize std cache: {err}"))?;
                Arc::new(cached)
            } else {
                // File pipeline: File only
                let canonical = std::fs::canonicalize(&args.rootfs)
                    .with_context(|| format!("canonicalize {}", args.rootfs.display()))?;
                let file_reader = StdFileBlockReader::open(&canonical, DEFAULT_IMAGE_BLOCK_SIZE)
                    .map_err(|err| anyhow!("open file {}: {err}", canonical.display()))?;
                Arc::new(file_reader)
            };

        let total_blocks = reader.total_blocks().await?;
        let image_size_bytes = total_blocks * reader.block_size() as u64;

        // Wrap in EROFS
        let provider = ErofsRootfs::new(reader, image_size_bytes).await?;

        let build = build_stage0(
            profile,
            &provider,
            &opts,
            args.cmdline_append.as_deref(),
            existing.as_deref(),
        )
        .await;
        anyhow::Ok(build)
    }?
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
