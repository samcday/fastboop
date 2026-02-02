use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::fastboot::{
    FastbootProtocolError, ProbeError, boot, download, probe_profile_with_cache,
    profile_matches_vid_pid,
};
use fastboop_core::{DeviceProfile, Personalization, RootfsProvider};
use fastboop_stage0::{Stage0Options, build_stage0};
use fastboop_transport_fastboot_rusb::FastbootRusb;
use rusb::{Context as UsbContext, UsbContext as _};
use tracing::{debug, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(author, version, about = "fastboop CLI utilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Boot a device by synthesizing stage0 and issuing fastboot download+boot.
    Boot(BootArgs),
    /// Detect connected fastboot devices that match a DevPro.
    Detect,
    /// Synthesize a stage0 initrd from a rootfs and device profile; writes cpio to stdout.
    Stage0(Stage0Args),
}

#[derive(Args)]
struct BootArgs {
    #[command(flatten)]
    stage0: Stage0Args,
    /// Write boot image to a file and skip device detection/boot.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Append host time to cmdline as systemd.clock_usec=... (use --system-time=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    system_time: bool,
    /// Append systemd-firstboot credentials (use --systemd-firstboot=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    systemd_firstboot: bool,
}

#[derive(Args)]
struct Stage0Args {
    /// Path to rootfs (directory or mount) containing kernel/modules.
    #[arg(value_name = "ROOTFS")]
    rootfs: PathBuf,
    /// Path to smoo-gadget binary to embed as /init (must be self-contained/static for now).
    #[arg(long)]
    smoo: Option<PathBuf>,
    /// Device profile id to use (must be present in loaded DevPros).
    #[arg(long, required = true)]
    device_profile: String,
    /// Override DTB path (host path).
    #[arg(long)]
    dtb: Option<PathBuf>,
    /// Existing initrd (cpio newc) to augment.
    #[arg(long)]
    augment: Option<PathBuf>,
    /// Extra required modules (repeatable).
    #[arg(long = "require-module")]
    require_modules: Vec<String>,
    /// Extra kernel cmdline to append after the smoo.modules= argument.
    #[arg(long, alias = "cmdline")]
    cmdline_append: Option<String>,
    /// Enable CDC-ACM gadget (smoo.acm=1) and include usb_f_acm.
    #[arg(long)]
    serial: bool,
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Boot(args) => run_boot(args),
        Commands::Detect => run_detect(),
        Commands::Stage0(args) => run_stage0(args),
    }
}

fn run_detect() -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    if profiles.is_empty() {
        eprintln!("No device profiles found in {:?}", devpro_dirs);
        return Ok(());
    }

    let profiles = dedup_profiles(&profiles);
    let context = UsbContext::new().context("creating USB context")?;
    let devices = context.devices().context("enumerating USB devices")?;
    let mut found = false;
    for device in devices.iter() {
        let desc = match device.device_descriptor() {
            Ok(desc) => desc,
            Err(err) => {
                eprintln!("Skipping USB device: unable to read descriptor: {err}");
                continue;
            }
        };
        let vid = desc.vendor_id();
        let pid = desc.product_id();
        let matching: Vec<_> = profiles
            .iter()
            .filter(|profile| profile_matches_vid_pid(profile, vid, pid))
            .collect();
        if matching.is_empty() {
            continue;
        }

        let mut fastboot = match FastbootRusb::open(&device) {
            Ok(fastboot) => fastboot,
            Err(err) => {
                eprintln!(
                    "Skipping {:04x}:{:04x} bus={} addr={}: open failed: {err}",
                    vid,
                    pid,
                    device.bus_number(),
                    device.address()
                );
                continue;
            }
        };

        let mut cache = std::collections::BTreeMap::new();
        for profile in matching {
            match pollster::block_on(probe_profile_with_cache(&mut fastboot, profile, &mut cache)) {
                Ok(()) => {
                    found = true;
                    print_detected(&device, profile, vid, pid);
                }
                Err(err) => {
                    debug!(
                        profile_id = %profile.id,
                        vid = %format!("{:04x}", vid),
                        pid = %format!("{:04x}", pid),
                        bus = device.bus_number(),
                        addr = device.address(),
                        error = %format_probe_error(err),
                        "fastboot probe failed"
                    );
                }
            }
        }
    }

    if !found {
        eprintln!("No matching fastboot devices detected.");
    }
    Ok(())
}

fn run_boot(args: BootArgs) -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    let profile = profiles
        .get(&args.stage0.device_profile)
        .or_else(|| profiles.get(&format!("file:{}", args.stage0.device_profile)));
    let profile = profile.with_context(|| {
        let mut ids: Vec<_> = profiles
            .keys()
            .filter(|k| !k.starts_with("file:"))
            .cloned()
            .collect();
        ids.sort();
        format!(
            "device profile '{}' not found in {:?}; available ids: {:?}",
            args.stage0.device_profile, devpro_dirs, ids
        )
    })?;

    let mut fastboot = if args.output.is_none() {
        let context = UsbContext::new().context("creating USB context")?;
        let devices = context.devices().context("enumerating USB devices")?;
        let mut matched = Vec::new();

        for device in devices.iter() {
            let desc = match device.device_descriptor() {
                Ok(desc) => desc,
                Err(err) => {
                    eprintln!("Skipping USB device: unable to read descriptor: {err}");
                    continue;
                }
            };
            let vid = desc.vendor_id();
            let pid = desc.product_id();
            if !profile_matches_vid_pid(profile, vid, pid) {
                continue;
            }

            let mut fastboot = match FastbootRusb::open(&device) {
                Ok(fastboot) => fastboot,
                Err(err) => {
                    eprintln!(
                        "Skipping {:04x}:{:04x} bus={} addr={}: open failed: {err}",
                        vid,
                        pid,
                        device.bus_number(),
                        device.address()
                    );
                    continue;
                }
            };

            let mut cache = std::collections::BTreeMap::new();
            match pollster::block_on(probe_profile_with_cache(&mut fastboot, profile, &mut cache)) {
                Ok(()) => matched.push(fastboot),
                Err(err) => {
                    debug!(
                        profile_id = %profile.id,
                        vid = %format!("{:04x}", vid),
                        pid = %format!("{:04x}", pid),
                        bus = device.bus_number(),
                        addr = device.address(),
                        error = %format_probe_error(err),
                        "fastboot probe failed"
                    );
                }
            }
        }

        Some(match matched.len() {
            0 => bail!(
                "no matching fastboot device found for profile {}",
                profile.id
            ),
            1 => matched.remove(0),
            _ => bail!(
                "multiple fastboot devices matched profile {}; please connect only one",
                profile.id
            ),
        })
    } else {
        None
    };

    let dtb_override = match &args.stage0.dtb {
        Some(path) => {
            Some(fs::read(path).with_context(|| format!("reading dtb {}", path.display()))?)
        }
        None => None,
    };

    let opts = Stage0Options {
        extra_modules: args.stage0.require_modules,
        dtb_override,

        enable_serial: args.stage0.serial,
        personalization: args.systemd_firstboot.then(personalization_from_host),
    };

    let existing = read_existing_initrd(&args.stage0.augment)?;
    ensure_smoo_source(&args.stage0.smoo, &existing)?;

    let provider = DirectoryRootfs {
        root: args.stage0.rootfs,
        smoo: args.stage0.smoo,
    };

    let mut extra_parts = Vec::new();
    if let Some(cmdline) = args
        .stage0
        .cmdline_append
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        extra_parts.push(cmdline.to_string());
    }
    if args.system_time {
        extra_parts.push(system_time_cmdline()?);
    }
    let extra_cmdline = if extra_parts.is_empty() {
        None
    } else {
        Some(extra_parts.join(" "))
    };

    let build = build_stage0(
        profile,
        &provider,
        &opts,
        extra_cmdline.as_deref(),
        existing.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("stage0 build failed: {:?}", e))?;

    let cmdline = join_cmdline(
        profile
            .boot
            .fastboot_boot
            .android_bootimg
            .cmdline_append
            .as_deref(),
        Some(build.kernel_cmdline_append.as_str()),
    );

    let mut kernel_image = build.kernel_image;
    let mut profile = profile.clone();
    if profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .append_dtb()
    {
        kernel_image.extend_from_slice(&build.dtb);
        let header_version = profile.boot.fastboot_boot.android_bootimg.header_version;
        if header_version >= 2 {
            debug!(
                from = header_version,
                to = 0,
                "downgrading android boot header for appended dtb"
            );
            profile.boot.fastboot_boot.android_bootimg.header_version = 0;
        }
    }

    let bootimg = build_android_bootimg(
        &profile,
        &kernel_image,
        &build.initrd,
        Some(&build.dtb),
        &cmdline,
    )
    .map_err(|e| anyhow::anyhow!("bootimg build failed: {e}"))?;

    if let Some(path) = args.output {
        fs::write(&path, &bootimg)
            .with_context(|| format!("writing bootimg to {}", path.display()))?;
        eprintln!("Wrote boot image to {}", path.display());
        return Ok(());
    }

    let mut fastboot = fastboot
        .take()
        .expect("fastboot device probed when no --output");

    pollster::block_on(download(&mut fastboot, &bootimg))
        .map_err(|e| anyhow::anyhow!("fastboot download failed: {e}"))?;
    pollster::block_on(boot(&mut fastboot))
        .map_err(|e| anyhow::anyhow!("fastboot boot failed: {e}"))?;
    Ok(())
}

fn print_detected(device: &rusb::Device<UsbContext>, profile: &DeviceProfile, vid: u16, pid: u16) {
    let name = profile.display_name.as_deref().unwrap_or("unknown");
    println!(
        "{:04x}:{:04x} bus={} addr={} profile={} name=\"{}\"",
        vid,
        pid,
        device.bus_number(),
        device.address(),
        profile.id,
        name
    );
}

fn format_probe_error(
    err: ProbeError<FastbootProtocolError<fastboop_transport_fastboot_rusb::FastbootRusbError>>,
) -> String {
    match err {
        ProbeError::Transport(err) => err.to_string(),
        ProbeError::MissingVar(name) => format!("missing getvar {name}"),
        ProbeError::Mismatch {
            name,
            expected,
            actual,
        } => format!("getvar {name} mismatch: expected '{expected}', got '{actual}'"),
    }
}

fn join_cmdline(left: Option<&str>, right: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(left) = left {
        out.push_str(left.trim());
    }
    if let Some(right) = right {
        let right = right.trim();
        if !right.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(right);
        }
    }
    out
}

fn system_time_cmdline() -> Result<String> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?;
    let usec: u64 = since_epoch
        .as_micros()
        .try_into()
        .context("system time exceeds u64 microseconds")?;
    Ok(format!("systemd.clock_usec={usec}"))
}

fn personalization_from_host() -> Personalization {
    let locale = detect_locale().unwrap_or_else(|| "en_US.UTF-8".to_string());
    let locale_messages = detect_locale_messages().unwrap_or_else(|| locale.clone());
    let keymap = detect_keymap().unwrap_or_else(|| "us".to_string());
    let timezone = detect_timezone().unwrap_or_else(|| "UTC".to_string());
    Personalization {
        locale: Some(locale),
        locale_messages: Some(locale_messages),
        keymap: Some(keymap),
        timezone: Some(timezone),
    }
}

fn detect_locale() -> Option<String> {
    locale_from_env_or_file("LC_ALL").or_else(|| locale_from_env_or_file("LANG"))
}

fn detect_locale_messages() -> Option<String> {
    locale_from_env_or_file("LC_MESSAGES")
        .or_else(|| locale_from_env_or_file("LC_ALL"))
        .or_else(|| locale_from_env_or_file("LANG"))
}

fn locale_from_env_or_file(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .and_then(nonempty)
        .or_else(|| read_key_from_file(Path::new("/etc/locale.conf"), key))
}

fn detect_keymap() -> Option<String> {
    read_key_from_file(Path::new("/etc/vconsole.conf"), "KEYMAP")
        .or_else(|| read_key_from_file(Path::new("/etc/default/keyboard"), "XKBLAYOUT"))
        .map(|s| s.split(',').next().unwrap_or(&s).trim().to_string())
        .and_then(nonempty)
}

fn detect_timezone() -> Option<String> {
    if let Some(tz) = read_timezone_from_localtime() {
        return Some(tz);
    }
    if let Ok(tz) = fs::read_to_string("/etc/timezone")
        && let Some(tz) = nonempty(tz)
    {
        return Some(tz);
    }
    env::var("TZ").ok().and_then(nonempty)
}

fn read_timezone_from_localtime() -> Option<String> {
    let target = fs::read_link("/etc/localtime").ok()?;
    let target = if target.is_absolute() {
        target
    } else {
        Path::new("/etc").join(target)
    };
    let target = target.to_string_lossy();
    let marker = "zoneinfo/";
    let idx = target.find(marker)? + marker.len();
    let tz = target[idx..].trim();
    if tz.is_empty() {
        None
    } else {
        Some(tz.to_string())
    }
}

fn read_key_from_file(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        if k.trim() != key {
            continue;
        }
        let v = v.trim().trim_matches('"').trim_matches('\'');
        if let Some(v) = nonempty(v.to_string()) {
            return Some(v);
        }
    }
    None
}

fn nonempty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn dedup_profiles(profiles: &HashMap<String, DeviceProfile>) -> Vec<&DeviceProfile> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for profile in profiles.values() {
        if seen.insert(profile.id.clone()) {
            unique.push(profile);
        }
    }
    unique
}

fn run_stage0(args: Stage0Args) -> Result<()> {
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
            Some(fs::read(path).with_context(|| format!("reading dtb {}", path.display()))?)
        }
        None => None,
    };

    let opts = Stage0Options {
        extra_modules: args.require_modules,
        dtb_override,

        enable_serial: args.serial,
        personalization: None,
    };

    let existing = read_existing_initrd(&args.augment)?;
    ensure_smoo_source(&args.smoo, &existing)?;

    let provider = DirectoryRootfs {
        root: args.rootfs,
        smoo: args.smoo,
    };

    let build = build_stage0(
        profile,
        &provider,
        &opts,
        args.cmdline_append.as_deref(),
        existing.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("stage0 build failed: {:?}", e))?;

    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&build.initrd)
        .context("writing initrd to stdout")?;
    eprintln!("Kernel cmdline append: {}", build.kernel_cmdline_append);
    eprintln!(
        "Kernel: {} ({} bytes); smoo: {}",
        build.kernel_path,
        build.kernel_image.len(),
        build.smoo_path
    );
    Ok(())
}

#[derive(Clone)]
struct DirectoryRootfs {
    root: PathBuf,
    smoo: Option<PathBuf>,
}

impl RootfsProvider for DirectoryRootfs {
    type Error = anyhow::Error;

    fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        if path == "smoo-gadget" {
            let smoo = self.smoo.as_ref().context("smoo-gadget not provided")?;
            return fs::read(smoo)
                .with_context(|| format!("reading smoo binary {}", smoo.display()));
        }
        let path = resolve_rooted(&self.root, path)?;
        fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let path = resolve_rooted(&self.root, path)?;
        let mut f = fs::File::open(&path)
            .with_context(|| format!("opening {} for range read", path.display()))?;
        f.seek(SeekFrom::Start(offset))
            .with_context(|| format!("seeking {} to {}", path.display(), offset))?;
        let mut buf = vec![0u8; len];
        let n = f
            .read(&mut buf)
            .with_context(|| format!("reading range from {}", path.display()))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        let path = resolve_rooted(&self.root, path)?;
        let entries =
            fs::read_dir(&path).with_context(|| format!("reading directory {}", path.display()))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    fn exists(&self, path: &str) -> Result<bool> {
        let path = resolve_rooted(&self.root, path)?;
        Ok(path.exists())
    }
}

fn resolve_rooted(root: &Path, path: &str) -> Result<PathBuf> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        bail!("empty path");
    }
    Ok(root.join(trimmed))
}

fn read_existing_initrd(path: &Option<PathBuf>) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    Ok(Some(fs::read(path).with_context(|| {
        format!("reading initrd {}", path.display())
    })?))
}

fn ensure_smoo_source(smoo: &Option<PathBuf>, existing: &Option<Vec<u8>>) -> Result<()> {
    if smoo.is_some() {
        return Ok(());
    }
    let Some(data) = existing else {
        bail!("--smoo is required unless --augment contains /usr/bin/smoo-gadget");
    };
    let has_smoo = fastboop_stage0::cpio_contains_path(data, "usr/bin/smoo-gadget")
        .map_err(|e| anyhow::anyhow!("invalid initrd: {:?}", e))?;
    if !has_smoo {
        bail!("--smoo is required unless --augment contains /usr/bin/smoo-gadget");
    }
    Ok(())
}

fn resolve_devpro_dirs() -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    if let Ok(env_paths) = env::var("FASTBOOP_SCHEMA_PATH") {
        for part in env_paths.split(':') {
            if part.is_empty() {
                continue;
            }
            dirs.push(PathBuf::from(part));
        }
    }
    if let Some(devprofiles) = devprofiles_dir_for_cargo_run() {
        dirs.push(devprofiles);
    }
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        dirs.push(PathBuf::from(xdg).join("fastboop/devpro"));
    } else if let Ok(home) = env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".config/fastboop/devpro"));
    }
    dirs.push(PathBuf::from("/usr/share/fastboop/devpro"));
    let mut seen = HashMap::new();
    dirs.retain(|p| seen.insert(p.clone(), ()).is_none());
    Ok(dirs)
}

fn devprofiles_dir_for_cargo_run() -> Option<PathBuf> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let running_under_cargo = env::var_os("CARGO").is_some()
        || env::var_os("CARGO_MANIFEST_DIR").is_some()
        || env::var_os("CARGO_PKG_NAME").is_some();
    if !running_under_cargo {
        return None;
    }
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let workspace_root = manifest_dir.parent().and_then(|p| p.parent())?;
    Some(workspace_root.join("devprofiles.d"))
}

fn load_device_profiles(dirs: &[PathBuf]) -> Result<HashMap<String, DeviceProfile>> {
    let mut profiles = HashMap::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(dir)
            .with_context(|| format!("reading device profile dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default();
            if !matches!(ext, "yml" | "yaml" | "json") {
                continue;
            }
            let text = fs::read_to_string(&path)
                .with_context(|| format!("reading device profile {}", path.display()))?;
            let profile: DeviceProfile = match serde_yaml::from_str(&text) {
                Ok(profile) => profile,
                Err(err) => {
                    warn!(
                        path = %path.display(),
                        error = %err,
                        "Skipping invalid device profile"
                    );
                    continue;
                }
            };
            if profiles.contains_key(&profile.id) {
                bail!(
                    "duplicate device profile id '{}' found in {}",
                    profile.id,
                    path.display()
                );
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                let key = format!("file:{}", stem);
                profiles.entry(key).or_insert_with(|| profile.clone());
            }
            profiles.insert(profile.id.clone(), profile);
        }
    }
    Ok(profiles)
}
