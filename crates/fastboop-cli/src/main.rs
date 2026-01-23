use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use fastboop_core::fastboot::{
    FastbootProtocolError, ProbeError, probe_profile_with_cache, profile_matches_vid_pid,
};
use fastboop_core::{DeviceProfile, RootfsProvider};
use fastboop_stage0::{Stage0Options, build_stage0};
use fastboop_transport_fastboot_rusb::FastbootRusb;
use rusb::{Context as UsbContext, UsbContext as _};
use tracing::debug;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(author, version, about = "fastboop CLI utilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Detect connected fastboot devices that match a DevPro.
    Detect,
    /// Synthesize a stage0 initrd from a rootfs and device profile; writes cpio to stdout.
    Stage0(Stage0Args),
}

#[derive(Args)]
struct Stage0Args {
    /// Path to rootfs (directory or mount) containing kernel/modules/firmware.
    #[arg(value_name = "ROOTFS")]
    rootfs: PathBuf,
    /// Path to smoo-gadget binary to embed as /init (must be self-contained/static for now).
    #[arg(long, required = true)]
    smoo: PathBuf,
    /// Device profile id to use (must be present in loaded DevPros).
    #[arg(long, required = true)]
    device_profile: String,
    /// Override DTB path (inside rootfs).
    #[arg(long)]
    dtb: Option<String>,
    /// Existing initrd (cpio newc) to augment.
    #[arg(long)]
    augment: Option<PathBuf>,
    /// Skip including firmware derived from DTB firmware-name properties.
    #[arg(long)]
    skip_dtb_firmware: bool,
    /// Allow firmware references to be missing without failing stage0 build.
    #[arg(long)]
    allow_missing_firmware: bool,
    /// Extra required modules (repeatable).
    #[arg(long = "require-module")]
    require_modules: Vec<String>,
    /// Extra kernel cmdline to append after the smoo.modules= argument.
    #[arg(long)]
    cmdline_append: Option<String>,
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    let cli = Cli::parse();
    match cli.command {
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

    let provider = DirectoryRootfs {
        root: args.rootfs,
        smoo: args.smoo,
    };

    let opts = Stage0Options {
        extra_modules: args.require_modules,
        dtb_override: args.dtb,
        include_dtb_firmware: !args.skip_dtb_firmware,
        allow_missing_firmware: args.allow_missing_firmware,
    };

    let existing = if let Some(path) = args.augment {
        Some(fs::read(&path).with_context(|| format!("reading initrd {}", path.display()))?)
    } else {
        None
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
    smoo: PathBuf,
}

impl RootfsProvider for DirectoryRootfs {
    type Error = anyhow::Error;

    fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        if path == "smoo-gadget" {
            return fs::read(&self.smoo)
                .with_context(|| format!("reading smoo binary {}", self.smoo.display()));
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
            let profile: DeviceProfile = serde_yaml::from_str(&text)
                .with_context(|| format!("parsing {}", path.display()))?;
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
