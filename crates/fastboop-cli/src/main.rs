use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use fastboop_core::{DeviceProfile, RootfsProvider};
use fastboop_stage0::{Stage0Options, build_stage0};

#[derive(Parser)]
#[command(author, version, about = "fastboop CLI utilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    let cli = Cli::parse();
    match cli.command {
        Commands::Stage0(args) => run_stage0(args),
    }
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
