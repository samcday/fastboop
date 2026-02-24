use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use fastboop_stage0_generator::{Stage0Options, build_stage0};
use gibblox_core::BlockReader;
use gibblox_zip::ZipEntryBlockReader;
use gobblytes_core::OstreeFs as OstreeRootfs;
use gobblytes_erofs::ErofsRootfs;
use tracing::debug;
use url::Url;

use crate::devpros::{load_device_profiles, resolve_devpro_dirs};

use super::{
    OstreeArg, auto_detect_ostree_deployment_path, open_rootfs_block_reader, parse_ostree_arg,
    read_dtbo_overlays, read_existing_initrd,
};

#[derive(Args)]
pub struct Stage0Args {
    /// Path or HTTP(S) URL to an EROFS image, or HTTP(S) casync blob index (.caibx), containing kernel/modules.
    #[arg(value_name = "ROOTFS")]
    pub rootfs: PathBuf,
    /// Resolve kernel/modules inside this OSTree deployment path (`--ostree` auto-detects).
    #[arg(long, value_name = "PATH", num_args = 0..=1)]
    pub ostree: Option<Option<String>>,
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
    let profile = profiles.get(&args.device_profile);
    let profile = profile.with_context(|| {
        let mut ids: Vec<_> = profiles.keys().cloned().collect();
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
    let ostree_arg = parse_ostree_arg(args.ostree.as_ref())?;
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

    let existing = read_existing_initrd(&args.augment)?;
    let cmdline_append = args
        .cmdline_append
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let build = {
        let rootfs_str = args.rootfs.to_string_lossy();
        let reader = open_rootfs_block_reader(&args.rootfs).await?;

        let reader: Arc<dyn BlockReader> = match zip_entry_name_from_rootfs(&rootfs_str)? {
            Some(entry_name) => {
                let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                    .await
                    .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                Arc::new(zip_reader)
            }
            None => reader,
        };

        let total_blocks = reader.total_blocks().await?;
        let image_size_bytes = total_blocks * reader.block_size() as u64;

        // Wrap in EROFS
        let provider = ErofsRootfs::new(reader, image_size_bytes).await?;

        let selected_ostree = match &ostree_arg {
            OstreeArg::Disabled => None,
            OstreeArg::AutoDetect => {
                let detected = auto_detect_ostree_deployment_path(&provider).await?;
                debug!(ostree = %detected, "auto-detected ostree deployment path");
                Some(detected)
            }
            OstreeArg::Explicit(path) => Some(path.clone()),
        };

        let mut extra_parts = Vec::new();
        if let Some(ostree) = selected_ostree.as_deref() {
            extra_parts.push(format!("ostree=/{ostree}"));
        }
        if let Some(cmdline) = cmdline_append.as_deref() {
            extra_parts.push(cmdline.to_string());
        }
        let extra_cmdline = if extra_parts.is_empty() {
            None
        } else {
            Some(extra_parts.join(" "))
        };

        let build = if let Some(ostree) = selected_ostree.as_deref() {
            let resolved_ostree = OstreeRootfs::resolve_deployment_path(&provider, ostree)
                .await
                .map_err(|err| anyhow!("resolve ostree deployment path {ostree}: {err}"))?;
            debug!(ostree = %ostree, resolved_ostree = %resolved_ostree, "resolved ostree deployment path");
            let provider = OstreeRootfs::new(provider, &resolved_ostree)
                .map_err(|err| anyhow!("initialize ostree filesystem view: {err}"))?;
            build_stage0(
                profile,
                &provider,
                &opts,
                extra_cmdline.as_deref(),
                existing.as_deref(),
            )
            .await
        } else {
            build_stage0(
                profile,
                &provider,
                &opts,
                extra_cmdline.as_deref(),
                existing.as_deref(),
            )
            .await
        };
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

fn zip_entry_name_from_rootfs(rootfs: &str) -> Result<Option<String>> {
    let trimmed = rootfs.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let url = Url::parse(trimmed).with_context(|| format!("parse rootfs URL {trimmed}"))?;
        let file_name = url
            .path_segments()
            .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back());
        return zip_entry_name_from_file_name(file_name);
    }

    let file_name = std::path::Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str());
    zip_entry_name_from_file_name(file_name)
}

fn zip_entry_name_from_file_name(file_name: Option<&str>) -> Result<Option<String>> {
    let Some(file_name) = file_name else {
        return Ok(None);
    };
    if !file_name.to_ascii_lowercase().ends_with(".zip") {
        return Ok(None);
    }

    let stem = &file_name[..file_name.len() - 4];
    if stem.is_empty() {
        return Err(anyhow!("zip artifact name must include a filename stem"));
    }
    Ok(Some(format!("{stem}.ero")))
}
