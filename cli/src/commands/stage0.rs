use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use fastboop_core::resolve_effective_boot_profile_stage0;
use fastboop_stage0_generator::{Stage0Options, build_stage0};
use gobblytes_core::OstreeFs as OstreeRootfs;
use tracing::debug;

use crate::devpros::{load_device_profiles, resolve_devpro_dirs};

use super::{
    ArtifactReaderResolver, OstreeArg, Stage0CoalescingFilesystem,
    auto_detect_ostree_deployment_path, parse_ostree_arg, read_dtbo_overlays, read_existing_initrd,
    resolve_boot_profile_source_overrides, resolve_effective_ostree_arg,
};

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

    let cli_dtbo_overlays = read_dtbo_overlays(&args.dtbo)?;
    let ostree_arg = parse_ostree_arg(args.ostree.as_ref())?;
    let cli_extra_modules = args.require_modules;
    let serial_enabled = args.serial;

    let existing = read_existing_initrd(&args.augment)?;
    let cli_cmdline_append = args
        .cmdline_append
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut artifact_resolver = ArtifactReaderResolver::new();
    let build = {
        let input = artifact_resolver
            .open_channel_input(
                &args.channel,
                profile.id.as_str(),
                args.boot_profile.as_deref(),
            )
            .await?;

        if input.warning_count > 0 {
            eprintln!(
                "channel stream has {} warning(s) while reading profile head; using {} bytes of leading records",
                input.warning_count,
                input.consumed_bytes
            );
        }

        let accepted_profile_ids: HashSet<&str> =
            input.dev_profiles.iter().map(|profile| profile.id.as_str()).collect();
        if !accepted_profile_ids.is_empty() && !accepted_profile_ids.contains(profile.id.as_str()) {
            let mut accepted_ids: Vec<_> =
                input.dev_profiles.iter().map(|profile| profile.id.as_str()).collect();
            accepted_ids.sort_unstable();
            bail!(
                "device profile '{}' is not accepted by channel profile constraints [{}]",
                profile.id,
                accepted_ids.join(", ")
            );
        }

        let profile_source_overrides = resolve_boot_profile_source_overrides(
            input.boot_profile.as_ref(),
            profile,
            &mut artifact_resolver,
        )
        .await?;
        let profile_stage0 = input
            .boot_profile
            .as_ref()
            .map(|boot_profile| resolve_effective_boot_profile_stage0(boot_profile, &profile.id))
            .unwrap_or_default();
        let stage0_readers = input.stage0_readers;

        let provider = Stage0CoalescingFilesystem::open(stage0_readers).await?;

        let mut extra_modules = profile_stage0.extra_modules;
        extra_modules.extend(cli_extra_modules.iter().cloned());

        let mut dtbo_overlays = profile_stage0.dt_overlays;
        dtbo_overlays.extend(cli_dtbo_overlays.iter().cloned());

        let merged_profile_cmdline = join_cmdline(
            profile_stage0.extra_cmdline.as_deref(),
            cli_cmdline_append.as_deref(),
        );

        let opts = Stage0Options {
            switchroot_fs: provider.switchroot_fs(),
            extra_modules,
            kernel_override: profile_source_overrides.kernel_override,
            dtb_override: cli_dtb_override.or(profile_source_overrides.dtb_override),
            dtbo_overlays,
            enable_serial: serial_enabled,
            mimic_fastboot: false,
            smoo_vendor: None,
            smoo_product: None,
            smoo_serial: None,
            personalization: None,
        };

        let effective_ostree_arg =
            resolve_effective_ostree_arg(&ostree_arg, input.boot_profile.as_ref());
        let selected_ostree = match &effective_ostree_arg {
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
        if let Some(cmdline) = merged_profile_cmdline.as_deref() {
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

fn join_cmdline(left: Option<&str>, right: Option<&str>) -> Option<String> {
    let left = left.map(str::trim).filter(|value| !value.is_empty());
    let right = right.map(str::trim).filter(|value| !value.is_empty());
    match (left, right) {
        (Some(a), Some(b)) => Some([a, b].join(" ")),
        (Some(a), None) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    }
}
