use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use fastboop_rootfs_erofs::{ErofsRootfs, OstreeRootfs};
use fastboop_rootfs_ext4::Ext4Rootfs;
use fastboop_stage0_generator::{Stage0Options, Stage0SwitchrootFs, build_stage0};
use gibblox_core::BlockReader;
use gibblox_zip::ZipEntryBlockReader;
use tracing::debug;
use url::Url;

use crate::devpros::{load_device_profiles, resolve_devpro_dirs};

use super::{
    ArtifactReaderResolver, OstreeArg, RootfsKindHint, auto_detect_ostree_deployment_path,
    parse_ostree_arg, read_dtbo_overlays, read_existing_initrd,
    resolve_boot_profile_source_overrides,
};

#[derive(Args)]
pub struct Stage0Args {
    /// Path/URL to rootfs image pipeline input, or a compiled BootProfile binary file.
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

    let cli_dtb_override = match &args.dtb {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("reading dtb {}", path.display()))?)
        }
        None => None,
    };

    let dtbo_overlays = read_dtbo_overlays(&args.dtbo)?;
    let ostree_arg = parse_ostree_arg(args.ostree.as_ref())?;
    let extra_modules = args.require_modules;
    let serial_enabled = args.serial;

    let existing = read_existing_initrd(&args.augment)?;
    let cmdline_append = args
        .cmdline_append
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut artifact_resolver = ArtifactReaderResolver::new();
    let build = {
        let rootfs_str = args.rootfs.to_string_lossy();
        let input = artifact_resolver.open_rootfs_input(&args.rootfs).await?;
        let profile_source_overrides = resolve_boot_profile_source_overrides(
            input.boot_profile.as_ref(),
            profile,
            &mut artifact_resolver,
        )
        .await?;
        let reader = input.reader;

        let reader: Arc<dyn BlockReader> = match input.allow_zip_entry_probe {
            true => match zip_entry_name_from_rootfs(&rootfs_str)? {
                Some(entry_name) => {
                    let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                        .await
                        .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                    Arc::new(zip_reader)
                }
                None => reader,
            },
            false => reader,
        };

        let total_blocks = reader.total_blocks().await?;
        let image_size_bytes = total_blocks * reader.block_size() as u64;
        let kernel_override = profile_source_overrides.kernel_override;
        let dtb_override = cli_dtb_override.or(profile_source_overrides.dtb_override);
        let make_opts = |switchroot_fs: Stage0SwitchrootFs| Stage0Options {
            switchroot_fs,
            extra_modules: extra_modules.clone(),
            kernel_override: kernel_override.clone(),
            dtb_override: dtb_override.clone(),
            dtbo_overlays: dtbo_overlays.clone(),
            enable_serial: serial_enabled,
            mimic_fastboot: false,
            smoo_vendor: None,
            smoo_product: None,
            smoo_serial: None,
            personalization: None,
        };

        let build = match input.kind_hint {
            Some(RootfsKindHint::Erofs) => {
                let opts = make_opts(Stage0SwitchrootFs::Erofs);
                let provider = ErofsRootfs::new(reader.clone(), image_size_bytes)
                    .await
                    .map_err(|err| anyhow!("boot profile rootfs declared EROFS but reader failed: {err}"))?;
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

                if let Some(ostree) = selected_ostree.as_deref() {
                    let resolved_ostree =
                        OstreeRootfs::resolve_deployment_path(&provider, ostree).await?;
                    debug!(ostree = %ostree, resolved_ostree = %resolved_ostree, "resolved ostree deployment path");
                    let provider = OstreeRootfs::new(provider, &resolved_ostree)?;
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
                }
            }
            Some(RootfsKindHint::Ext4) => {
                let opts = make_opts(Stage0SwitchrootFs::Ext4);
                let provider = Ext4Rootfs::new(reader).await.map_err(|ext4_err| {
                    anyhow!(
                        "boot profile rootfs declared ext4 but reader failed: {ext4_err}"
                    )
                })?;

                if !matches!(&ostree_arg, OstreeArg::Disabled) {
                    bail!(
                        "--ostree requires an EROFS rootfs; ext4 rootfs images do not support OSTree path resolution"
                    );
                }

                build_stage0(
                    profile,
                    &provider,
                    &opts,
                    cmdline_append.as_deref(),
                    existing.as_deref(),
                )
                .await
            }
            None => match ErofsRootfs::new(reader.clone(), image_size_bytes).await {
                Ok(provider) => {
                    let opts = make_opts(Stage0SwitchrootFs::Erofs);
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

                    if let Some(ostree) = selected_ostree.as_deref() {
                        let resolved_ostree =
                            OstreeRootfs::resolve_deployment_path(&provider, ostree).await?;
                        debug!(ostree = %ostree, resolved_ostree = %resolved_ostree, "resolved ostree deployment path");
                        let provider = OstreeRootfs::new(provider, &resolved_ostree)?;
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
                    }
                }
                Err(erofs_err) => {
                    let opts = make_opts(Stage0SwitchrootFs::Ext4);
                    let provider = Ext4Rootfs::new(reader).await.map_err(|ext4_err| {
                        anyhow!(
                            "rootfs is neither EROFS nor ext4 (erofs: {erofs_err}; ext4: {ext4_err})"
                        )
                    })?;

                    if !matches!(&ostree_arg, OstreeArg::Disabled) {
                        bail!(
                            "--ostree requires an EROFS rootfs; ext4 rootfs images do not support OSTree path resolution"
                        );
                    }

                    build_stage0(
                        profile,
                        &provider,
                        &opts,
                        cmdline_append.as_deref(),
                        existing.as_deref(),
                    )
                    .await
                }
            },
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
