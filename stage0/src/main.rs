use anyhow::{Context, Result, anyhow, ensure};
use clap::{Parser, ValueEnum};
use drm::{ClientCapability, Device as _, buffer::Buffer as _, control::Device as _};
use std::io::{Read, Write};
use std::{
    collections::{HashMap, HashSet},
    ffi::{CString, OsStr, OsString},
    fs::File,
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    os::unix::fs::{FileTypeExt, symlink},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use usb_gadget::{
    Class, Config, Gadget, Id, RegGadget, Strings,
    function::{
        custom::{Custom, CustomBuilder, Endpoint, EndpointDirection, Interface, TransferType},
        serial::{Serial, SerialClass},
    },
};

struct KmsgWriter {
    file: File,
}

impl Write for KmsgWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct KmsgMakeWriter;

impl<'a> MakeWriter<'a> for KmsgMakeWriter {
    type Writer = Box<dyn Write + Send>;

    fn make_writer(&'a self) -> Self::Writer {
        match File::options().write(true).open("/dev/kmsg") {
            Ok(file) => Box::new(KmsgWriter { file }),
            Err(_) => Box::new(io::sink()),
        }
    }
}

const SMOO_SUBCLASS: u8 = 0x42;
const SMOO_PROTOCOL: u8 = 0x03;
const STAGE0_ROLE_ENV: &str = "FASTBOOP_STAGE0_ROLE";
const STAGE0_ROLE_GADGET_CHILD: &str = "gadget-child";
const STAGE0_ROLE_KMSG_CHILD: &str = "kmsg-child";
const STAGE0_ROLE_FRAMEBUFFER_CHILD: &str = "framebuffer-child";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage0Role {
    Pid1,
    GadgetChild,
    KmsgChild,
    FramebufferChild,
}

#[derive(Debug, Parser)]
#[command(name = "fastboop-stage0", version)]
#[command(about = "fastboop stage0 PID1", long_about = None)]
struct Args {
    /// USB vendor ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xDEAD", value_parser = parse_hex_u16)]
    vendor_id: u16,
    /// USB product ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xBEEF", value_parser = parse_hex_u16)]
    product_id: u16,
    /// USB serial string for gadget descriptors.
    #[arg(long, value_name = "SERIAL", default_value = "0001")]
    serial: String,
    /// Number of ublk queues to configure.
    #[arg(long, default_value_t = 1)]
    queue_count: u16,
    /// Depth of each ublk queue.
    #[arg(long, default_value_t = 16)]
    queue_depth: u16,
    /// Maximum per-I/O size in bytes to advertise to ublk (block-aligned).
    #[arg(long = "max-io", value_name = "BYTES")]
    max_io_bytes: Option<usize>,
    /// Opt-in to the experimental DMA-BUF fast path when supported by the kernel.
    #[arg(long)]
    experimental_dma_buf: bool,
    /// DMA-HEAP to allocate from when DMA-BUF mode is enabled.
    #[arg(long, value_enum, default_value_t = DmaHeapSelection::System)]
    dma_heap: DmaHeapSelection,
    /// Path to the recovery state file.
    #[arg(long, value_name = "PATH", default_value = "/run/smoo/state.json")]
    state_file: PathBuf,
    /// Adopt existing ublk devices via user recovery.
    #[arg(long)]
    adopt: bool,
    /// Expose Prometheus metrics on this TCP port (0 disables).
    #[arg(long, default_value_t = 0)]
    metrics_port: u16,
    /// Use an existing FunctionFS directory and skip configfs management.
    #[arg(long, value_name = "PATH")]
    ffs_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DmaHeapSelection {
    System,
    Cma,
    Reserved,
}

fn main() -> Result<()> {
    let role = stage0_role_from_env();
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    let cleaned_args = sanitize_startup_args(raw_args, role);
    let args = Args::parse_from(cleaned_args.clone());
    match role {
        Stage0Role::KmsgChild => {
            init_logging(true);
            info!(role = "kmsg-child", "stage0 startup role selected");
            warn!("pid1: kmsg forwarder starting");
            run_kmsg_daemon().context("kmsg daemon")
        }
        Stage0Role::FramebufferChild => {
            init_logging(true);
            info!(role = "framebuffer-child", "stage0 startup role selected");
            run_framebuffer_child().context("framebuffer worker")
        }
        Stage0Role::GadgetChild => {
            init_logging(true);
            info!(role = "gadget-child", "stage0 startup role selected");
            write_kmsg_line("stage0 role=gadget-child");
            run_gadget_child(args)
        }
        Stage0Role::Pid1 => {
            init_logging(true);
            info!(role = "pid1", "stage0 startup role selected");
            run_pid1(&args, &cleaned_args).context("pid1 initramfs flow")
        }
    }
}

fn stage0_role_from_env() -> Stage0Role {
    parse_stage0_role(std::env::var_os(STAGE0_ROLE_ENV).as_deref())
}

fn parse_stage0_role(value: Option<&OsStr>) -> Stage0Role {
    match value {
        Some(v) if v == OsStr::new(STAGE0_ROLE_GADGET_CHILD) => Stage0Role::GadgetChild,
        Some(v) if v == OsStr::new(STAGE0_ROLE_KMSG_CHILD) => Stage0Role::KmsgChild,
        Some(v) if v == OsStr::new(STAGE0_ROLE_FRAMEBUFFER_CHILD) => Stage0Role::FramebufferChild,
        _ => Stage0Role::Pid1,
    }
}

fn sanitize_startup_args(raw_args: Vec<OsString>, role: Stage0Role) -> Vec<OsString> {
    let argv0 = raw_args.first().cloned().unwrap_or_else(OsString::new);
    let auto_pid1 = argv0 == OsStr::new("/init");
    if auto_pid1 && role == Stage0Role::Pid1 {
        vec![argv0]
    } else {
        raw_args
    }
}

fn run_gadget_child(args: Args) -> Result<()> {
    write_kmsg_line("pid1-child: starting gadget runtime");
    let gadget_args = smoo_gadget_app::Args {
        vendor_id: args.vendor_id,
        product_id: args.product_id,
        queue_count: args.queue_count,
        queue_depth: args.queue_depth,
        max_io_bytes: args.max_io_bytes,
        experimental_dma_buf: args.experimental_dma_buf,
        dma_heap: map_dma_heap(args.dma_heap),
        state_file: Some(args.state_file),
        adopt: args.adopt,
        metrics_port: args.metrics_port,
        ffs_dir: args.ffs_dir,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let result = runtime.block_on(smoo_gadget_app::run_with_args(gadget_args));
    if let Err(err) = &result {
        write_kmsg_line(&format!("pid1-child: gadget runtime failed: {err:#}"));
    }
    result
}

fn map_dma_heap(heap: DmaHeapSelection) -> smoo_gadget_app::DmaHeapSelection {
    match heap {
        DmaHeapSelection::System => smoo_gadget_app::DmaHeapSelection::System,
        DmaHeapSelection::Cma => smoo_gadget_app::DmaHeapSelection::Cma,
        DmaHeapSelection::Reserved => smoo_gadget_app::DmaHeapSelection::Reserved,
    }
}

fn init_logging(pid1: bool) {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if pid1 {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(KmsgMakeWriter),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

fn run_pid1(args: &Args, cleaned_args: &[OsString]) -> Result<()> {
    ensure!(unsafe { libc::getpid() } == 1, "pid1 mode requires PID 1");

    info!("pid1: starting smoo initramfs flow");
    if args.ffs_dir.is_some() {
        warn!("pid1: ignoring --ffs-dir; pid1 manages gadget configfs");
    }
    std::fs::create_dir_all("/proc").ok();
    std::fs::create_dir_all("/sys").ok();
    std::fs::create_dir_all("/dev").ok();
    std::fs::create_dir_all("/run").ok();
    mount_fs(Some("proc"), "/proc", Some("proc"), 0, None).context("mount proc")?;
    mount_fs(Some("sysfs"), "/sys", Some("sysfs"), 0, None).context("mount sysfs")?;
    mount_fs(Some("devtmpfs"), "/dev", Some("devtmpfs"), 0, None).context("mount devtmpfs")?;
    mount_fs(Some("tmpfs"), "/run", Some("tmpfs"), 0, None).context("mount tmpfs /run")?;
    debug!("pid1: mounted proc/sys/dev/run");
    if cmdline_bool("stage0.fb") {
        if let Err(err) = spawn_framebuffer_child() {
            warn!(error = ?err, "pid1: failed to spawn framebuffer child");
        }
    }

    let default_modules = [
        "configfs",
        "ublk",
        "ublk_drv",
        "overlay",
        "erofs",
        "libcomposite",
        "usb_f_fs",
    ];
    let modules = load_modules_from_dir("/etc/modules-load.d")
        .filter(|list| !list.is_empty())
        .unwrap_or_else(|| default_modules.iter().map(|s| s.to_string()).collect());
    match ModuleIndex::load() {
        Ok(module_index) => {
            for module in modules {
                if let Err(err) = module_index.load_module_by_name(&module) {
                    warn!("module load failed for {module}: {err:#}");
                }
            }
        }
        Err(err) => {
            warn!("module index unavailable: {err:#}");
        }
    }

    std::fs::create_dir_all("/sys/kernel/config").ok();
    mount_fs(
        Some("configfs"),
        "/sys/kernel/config",
        Some("configfs"),
        0,
        None,
    )
    .context("mount configfs")?;
    debug!("pid1: mounted configfs");

    let udc_wait_secs = 15;
    info!("pid1: waiting for UDC (timeout {udc_wait_secs}s)");
    if !wait_for_udc(Duration::from_secs(udc_wait_secs))? {
        error!("pid1: fatal UDC not ready after {udc_wait_secs}s");
        return Err(anyhow!("UDC not ready after {udc_wait_secs}s"));
    }

    let gadget_guard = setup_pid1_configfs(args).context("setup pid1 configfs")?;
    let ffs_dir = gadget_guard.ffs_dir.clone();
    info!(
        ffs_dir = %ffs_dir.display(),
        "pid1: configfs gadget configured"
    );

    info!("pid1: spawning gadget child");
    let mut child =
        spawn_gadget_child(Some(&ffs_dir), cleaned_args).context("spawn gadget child")?;
    info!("pid1: gadget child pid {}", child.id());
    let ffs_wait_secs = 15;
    info!("pid1: waiting for FunctionFS endpoints (timeout {ffs_wait_secs}s)");
    if !wait_for_ffs_endpoints(&ffs_dir, Duration::from_secs(ffs_wait_secs), &mut child)? {
        error!("pid1: fatal FunctionFS endpoints not ready after {ffs_wait_secs}s");
        return Err(anyhow!(
            "FunctionFS endpoints not ready after {ffs_wait_secs}s"
        ));
    }

    let udc = usb_gadget::default_udc().context("locate UDC")?;
    gadget_guard
        .registration
        .bind(Some(&udc))
        .context("bind gadget to UDC")?;
    info!("pid1: gadget bound to UDC");
    if cmdline_bool("smoo.acm") {
        if let Err(err) = spawn_kmsg_daemon() {
            warn!(error = ?err, "pid1: failed to spawn kmsg forwarder");
        }
    }
    let ublk_dev = "/dev/ublkb0";
    let wait_secs = 30;
    debug!("pid1: waiting for block device {ublk_dev} (timeout {wait_secs}s)");
    if !wait_for_block_device(ublk_dev, Duration::from_secs(wait_secs), &mut child)? {
        error!("pid1: fatal timeout waiting for {ublk_dev} after {wait_secs}s");
        return Err(anyhow!("timed out waiting for {ublk_dev}"));
    }
    info!("pid1: found ublk device {ublk_dev}");

    std::fs::create_dir_all("/lower").ok();
    std::fs::create_dir_all("/upper").ok();
    std::fs::create_dir_all("/newroot").ok();

    debug!("pid1: mounting lower erofs from {ublk_dev}");
    mount_fs(
        Some(ublk_dev),
        "/lower",
        Some("erofs"),
        libc::MS_RDONLY as libc::c_ulong,
        None,
    )
    .context("mount erofs lower")?;
    debug!("pid1: mounted lower EROFS");
    debug!("pid1: mounting upper tmpfs");
    mount_fs(Some("tmpfs"), "/upper", Some("tmpfs"), 0, None).context("mount tmpfs upper")?;
    std::fs::create_dir_all("/upper/upper").ok();
    std::fs::create_dir_all("/upper/work").ok();
    if !filesystem_available("overlay")? {
        return Err(anyhow!("overlayfs not available in kernel"));
    }
    debug!("pid1: mounting overlay root");
    mount_fs(
        Some("overlay"),
        "/newroot",
        Some("overlay"),
        0,
        Some("lowerdir=/lower,upperdir=/upper/upper,workdir=/upper/work"),
    )
    .context("mount overlay root")?;
    debug!("pid1: mounted overlay root");

    // Avoid EINVAL from pivot_root on shared mount trees.
    debug!("pid1: making / private");
    mount_fs(None, "/", None, libc::MS_PRIVATE | libc::MS_REC, None).context("make / private")?;

    if matches!(cmdline_value("smoo.break").as_deref(), Some("1")) {
        debug_shell("smoo.break requested")?;
    }

    std::fs::create_dir_all("/newroot/proc").ok();
    std::fs::create_dir_all("/newroot/sys").ok();
    std::fs::create_dir_all("/newroot/dev").ok();
    std::fs::create_dir_all("/newroot/run").ok();

    debug!("pid1: bind-mounting proc/sys/dev/run into newroot");
    bind_mount_if_needed("/proc", "/newroot/proc", true)?;
    bind_mount_if_needed("/sys", "/newroot/sys", true)?;
    bind_mount_if_needed("/dev", "/newroot/dev", true)?;
    bind_mount_if_needed("/run", "/newroot/run", false)?;
    debug!("pid1: bind mounts into newroot complete");

    std::env::set_current_dir("/newroot").ok();
    debug!("pid1: moving newroot to /");
    mount_fs(
        Some("/newroot"),
        "/",
        None,
        libc::MS_MOVE as libc::c_ulong,
        None,
    )
    .context("move newroot to /")?;
    debug!("pid1: chrooting to new root");
    chroot_to(".").context("chroot to new root")?;
    std::env::set_current_dir("/").ok();
    info!("pid1: switched root");

    ensure_kernel_mounts()?;
    log_mountinfo("before exec /sbin/init");
    for path in [
        "/proc/self/mountinfo",
        "/sys/fs/cgroup",
        "/dev/console",
        "/proc",
        "/sys",
        "/dev",
        "/run",
    ] {
        if !Path::new(path).exists() {
            warn!("pid1: missing required path {path} before exec");
        }
    }

    std::fs::create_dir_all("/run/systemd/system").ok();
    if Path::new("/run/systemd/system").exists() {
        info!("pid1: ensured /run/systemd/system");
    } else {
        warn!("pid1: /run/systemd/system missing before exec");
    }
    ensure_serial_getty().ok();

    let systemd_path = if Path::new("/lib/systemd/systemd").exists() {
        "/lib/systemd/systemd"
    } else {
        "/sbin/init"
    };
    info!("pid1: exec {}", systemd_path);
    let err = std::process::Command::new(systemd_path).exec();
    Err(anyhow!("exec {systemd_path} failed: {err}"))
}

fn cmdline_value(key: &str) -> Option<String> {
    let data = std::fs::read_to_string("/proc/cmdline").ok()?;
    for token in data.split_whitespace() {
        if let Some(value) = token.strip_prefix(&format!("{key}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn ensure_serial_getty() -> Result<()> {
    if !cmdline_bool("smoo.acm") {
        return Ok(());
    }
    let unit_path = if Path::new("/lib/systemd/system/serial-getty@.service").exists() {
        "/lib/systemd/system/serial-getty@.service"
    } else if Path::new("/usr/lib/systemd/system/serial-getty@.service").exists() {
        "/usr/lib/systemd/system/serial-getty@.service"
    } else {
        warn!("pid1: serial-getty@.service not found; skipping ttyGS0 getty");
        return Ok(());
    };
    let wants_dir = Path::new("/run/systemd/system/getty.target.wants");
    std::fs::create_dir_all(wants_dir).ok();
    let link_path = wants_dir.join("serial-getty@ttyGS0.service");
    if link_path.exists() {
        info!("pid1: serial-getty@ttyGS0 already requested");
        return Ok(());
    }
    if let Err(err) = symlink(unit_path, &link_path) {
        warn!(error = ?err, "pid1: failed to enable serial-getty@ttyGS0");
    } else {
        info!("pid1: enabled serial-getty@ttyGS0");
    }
    Ok(())
}

fn cmdline_flag(key: &str) -> bool {
    let Ok(data) = std::fs::read_to_string("/proc/cmdline") else {
        return false;
    };
    data.split_whitespace().any(|token| token == key)
}

fn cmdline_bool(key: &str) -> bool {
    if let Some(raw) = cmdline_value(key) {
        return match raw.as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => {
                warn!("pid1: invalid {key} value '{raw}'");
                false
            }
        };
    }
    cmdline_flag(key)
}

fn log_mountinfo(context: &str) {
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(data) => {
            info!("pid1: mountinfo ({context})\n{data}");
        }
        Err(err) => {
            warn!("pid1: failed to read mountinfo ({context}): {err}");
        }
    }
}

fn ensure_kernel_mounts() -> Result<()> {
    ensure_cgroup2_mount()?;
    ensure_bpffs_mount()?;
    ensure_securityfs_mount()?;
    ensure_devpts_mount()?;
    ensure_dev_shm_mount()?;
    Ok(())
}

fn ensure_cgroup2_mount() -> Result<()> {
    let cgroup_path = "/sys/fs/cgroup";
    std::fs::create_dir_all(cgroup_path).ok();
    if is_mount_point(cgroup_path)? {
        info!("pid1: cgroup already mounted at {cgroup_path}");
    } else {
        mount_fs(Some("cgroup2"), cgroup_path, Some("cgroup2"), 0, None)
            .context("mount cgroup2")?;
        info!("pid1: mounted cgroup2 at {cgroup_path}");
    }
    if let Ok(controllers) = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
        let controllers = controllers.trim();
        info!(
            "pid1: cgroup controllers: {}",
            if controllers.is_empty() {
                "<empty>"
            } else {
                controllers
            }
        );
    }
    Ok(())
}

fn ensure_bpffs_mount() -> Result<()> {
    let path = "/sys/fs/bpf";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: bpffs already mounted at {path}");
        return Ok(());
    }
    mount_fs(Some("bpffs"), path, Some("bpf"), 0, None).context("mount bpffs")?;
    info!("pid1: mounted bpffs at {path}");
    Ok(())
}

fn ensure_securityfs_mount() -> Result<()> {
    let path = "/sys/kernel/security";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: securityfs already mounted at {path}");
        return Ok(());
    }
    mount_fs(Some("securityfs"), path, Some("securityfs"), 0, None).context("mount securityfs")?;
    info!("pid1: mounted securityfs at {path}");
    Ok(())
}

fn ensure_devpts_mount() -> Result<()> {
    let path = "/dev/pts";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: devpts already mounted at {path}");
        return Ok(());
    }
    mount_fs(
        Some("devpts"),
        path,
        Some("devpts"),
        0,
        Some("mode=620,ptmxmode=666"),
    )
    .context("mount devpts")?;
    info!("pid1: mounted devpts at {path}");
    Ok(())
}

fn ensure_dev_shm_mount() -> Result<()> {
    let path = "/dev/shm";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: tmpfs already mounted at {path}");
        return Ok(());
    }
    mount_fs(Some("tmpfs"), path, Some("tmpfs"), 0, Some("mode=1777")).context("mount /dev/shm")?;
    info!("pid1: mounted tmpfs at {path}");
    Ok(())
}

fn cmdline_u16(key: &str) -> Option<u16> {
    let raw = cmdline_value(key)?;
    match raw.parse::<u16>() {
        Ok(value) => Some(value),
        Err(_) => {
            warn!("pid1: invalid {key} value '{raw}'");
            None
        }
    }
}

fn cmdline_u16_flexible(key: &str) -> Option<u16> {
    let raw = cmdline_value(key)?;
    parse_u16_flexible(&raw).or_else(|| {
        warn!("pid1: invalid {key} value '{raw}'");
        None
    })
}

fn parse_u16_flexible(input: &str) -> Option<u16> {
    let trimmed = input.trim();
    let maybe_hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    if let Some(hex) = maybe_hex {
        return u16::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u16>().ok()
}

fn cmdline_usize(key: &str) -> Option<usize> {
    let raw = cmdline_value(key)?;
    match raw.parse::<usize>() {
        Ok(value) => Some(value),
        Err(_) => {
            warn!("pid1: invalid {key} value '{raw}'");
            None
        }
    }
}

fn load_modules_from_dir(path: &str) -> Option<Vec<String>> {
    let mut modules = Vec::new();
    let entries = std::fs::read_dir(path).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".conf") {
            if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    modules.push(trimmed.to_string());
                }
            }
        }
    }
    Some(modules)
}

struct ModuleIndex {
    base_dir: PathBuf,
    name_to_path: HashMap<String, String>,
    path_to_deps: HashMap<String, Vec<String>>,
    aliases: Vec<(String, String)>,
}

impl ModuleIndex {
    fn load() -> Result<Self> {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .context("read /proc/sys/kernel/osrelease")?;
        let base_dir = PathBuf::from("/lib/modules").join(release.trim());
        let dep_path = base_dir.join("modules.dep");
        let alias_path = base_dir.join("modules.alias");

        let mut name_to_path = HashMap::new();
        let mut path_to_deps = HashMap::new();
        let dep_contents = std::fs::read_to_string(&dep_path)
            .with_context(|| format!("read {}", dep_path.display()))?;
        for line in dep_contents.lines() {
            let (path, deps) = match line.split_once(':') {
                Some(parts) => parts,
                None => continue,
            };
            let path = path.trim().to_string();
            let deps = deps
                .split_whitespace()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            let name = module_name_from_path(&path);
            name_to_path.entry(name).or_insert_with(|| path.clone());
            path_to_deps.insert(path, deps);
        }

        let mut aliases = Vec::new();
        if let Ok(alias_contents) = std::fs::read_to_string(&alias_path) {
            for line in alias_contents.lines() {
                let line = line.trim();
                if !line.starts_with("alias ") {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let _ = parts.next();
                if let (Some(pattern), Some(target)) = (parts.next(), parts.next()) {
                    aliases.push((pattern.to_string(), target.to_string()));
                }
            }
        }

        Ok(Self {
            base_dir,
            name_to_path,
            path_to_deps,
            aliases,
        })
    }

    fn load_module_by_name(&self, name: &str) -> Result<()> {
        let path = self
            .resolve_module_path(name)
            .ok_or_else(|| anyhow!("module {name} not found"))?;
        let mut loaded = HashSet::new();
        let mut stack = HashSet::new();
        self.load_module_recursive(&path, &mut loaded, &mut stack)
    }

    fn resolve_module_path(&self, name: &str) -> Option<String> {
        if let Some(path) = self.name_to_path.get(name) {
            return Some(path.clone());
        }
        for (pattern, target) in &self.aliases {
            if glob_match(pattern, name) {
                if let Some(path) = self.name_to_path.get(target) {
                    return Some(path.clone());
                }
            }
        }
        None
    }

    fn load_module_recursive(
        &self,
        rel_path: &str,
        loaded: &mut HashSet<String>,
        stack: &mut HashSet<String>,
    ) -> Result<()> {
        if loaded.contains(rel_path) {
            return Ok(());
        }
        if !stack.insert(rel_path.to_string()) {
            return Err(anyhow!("dependency cycle at {rel_path}"));
        }

        let deps = self.path_to_deps.get(rel_path).cloned().unwrap_or_default();
        for dep in deps {
            self.load_module_recursive(&dep, loaded, stack)?;
        }

        let path = self.base_dir.join(rel_path);
        let params = CString::new("")?;
        let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let fd = file.as_raw_fd();
        let res = if is_compressed_module(&path) {
            // Let the kernel handle module decompression when supported.
            finit_module(fd, &params, MODULE_INIT_COMPRESSED_FILE)
        } else {
            finit_module(fd, &params, 0)
        };
        if res != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                warn!("pid1: module {} load failed: {}", path.display(), err);
                return Err(err).with_context(|| format!("finit_module {}", path.display()));
            }
        }
        info!("pid1: module {} load ok", path.display());

        loaded.insert(rel_path.to_string());
        stack.remove(rel_path);
        Ok(())
    }
}

fn finit_module(fd: libc::c_int, params: &CString, flags: libc::c_int) -> libc::c_long {
    unsafe { libc::syscall(libc::SYS_finit_module, fd, params.as_ptr(), flags) }
}

const MODULE_INIT_COMPRESSED_FILE: libc::c_int = 4;

fn module_name_from_path(path: &str) -> String {
    let filename = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    let mut name = filename.to_string();
    for suffix in [".xz", ".zst", ".gz"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            name = stripped.to_string();
        }
    }
    if let Some(stripped) = name.strip_suffix(".ko") {
        name = stripped.to_string();
    }
    name
}

fn is_compressed_module(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("xz") | Some("zst") | Some("gz")
    )
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None, None);
    let p = pattern.as_bytes();
    let t = text.as_bytes();

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
            continue;
        }
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = Some(ti);
            pi += 1;
            continue;
        }
        if let (Some(sp), Some(st)) = (star_pi, star_ti) {
            pi = sp + 1;
            ti = st + 1;
            star_ti = Some(ti);
            continue;
        }
        return false;
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn debug_shell(reason: &str) -> Result<()> {
    warn!("pid1: dropping to shell ({reason})");
    for dev in ["/dev/ttyMSM0", "/dev/console"] {
        if let Ok(meta) = std::fs::metadata(dev) {
            if meta.file_type().is_char_device() {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(dev)
                    .with_context(|| format!("open {dev}"))?;
                let _ = unsafe { libc::setsid() };
                let err = std::process::Command::new("/bin/sh")
                    .arg("-i")
                    .stdin(file.try_clone()?)
                    .stdout(file.try_clone()?)
                    .stderr(file)
                    .exec();
                return Err(anyhow!("exec /bin/sh failed: {err}"));
            }
        }
    }
    Err(anyhow!("no console device available for debug shell"))
}

fn wait_for_udc(timeout: Duration) -> Result<bool> {
    let start = Instant::now();
    let mut warned_missing = false;
    let mut ticks: u32 = 0;
    loop {
        if Path::new("/sys/class/udc").exists() {
            if let Ok(entries) = std::fs::read_dir("/sys/class/udc") {
                if let Some(entry) = entries.filter_map(Result::ok).next() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    info!("pid1: UDC ready ({name})");
                    return Ok(true);
                }
            }
        } else if !warned_missing {
            warn!("pid1: /sys/class/udc missing");
            warned_missing = true;
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(5) {
            debug!("pid1: UDC not ready yet");
        }
        if start.elapsed() >= timeout {
            warn!("pid1: UDC wait timed out");
            return Ok(false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_block_device(
    path: &str,
    timeout: Duration,
    child: &mut std::process::Child,
) -> Result<bool> {
    let start = Instant::now();
    let mut ticks: u32 = 0;
    loop {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.file_type().is_block_device() {
                return Ok(true);
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            error!("pid1: gadget child exited while waiting for {path}: {status}");
            return Err(anyhow!("gadget child exited: {status}"));
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(5) {
            debug!("pid1: waiting for {path}");
        }
        if start.elapsed() >= timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_ffs_endpoints(
    ffs_dir: &Path,
    timeout: Duration,
    child: &mut std::process::Child,
) -> Result<bool> {
    let start = Instant::now();
    let mut ticks: u32 = 0;
    let ep1 = ffs_dir.join("ep1");
    loop {
        if ep1.exists() {
            return Ok(true);
        }
        if let Ok(Some(status)) = child.try_wait() {
            error!(
                "pid1: gadget child exited while waiting for FunctionFS endpoints: {}",
                describe_exit_status(status)
            );
            return Err(anyhow!("gadget child exited: {status}"));
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(5) {
            debug!(
                ffs_dir = %ffs_dir.display(),
                "pid1: waiting for FunctionFS endpoints"
            );
        }
        if start.elapsed() >= timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn spawn_gadget_child(
    ffs_dir: Option<&Path>,
    cleaned_args: &[OsString],
) -> Result<std::process::Child> {
    let exe = std::env::current_exe().context("locate self")?;
    let mut child_args = Vec::new();
    let mut args = cleaned_args.iter();
    let Some(argv0) = args.next() else {
        return Err(anyhow!("missing argv0"));
    };
    child_args.push(argv0.clone());

    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let arg_str = arg.to_string_lossy();
        if matches!(
            arg_str.as_ref(),
            "--queue-depth" | "--queue-count" | "--max-io" | "--ffs-dir"
        ) {
            skip_next = true;
            continue;
        }
        if arg_str.starts_with("--queue-depth=")
            || arg_str.starts_with("--queue-count=")
            || arg_str.starts_with("--max-io=")
            || arg_str.starts_with("--ffs-dir=")
        {
            continue;
        }
        child_args.push(arg.clone());
    }
    if let Some(queue_depth) =
        cmdline_u16("smoo.queue_depth").or_else(|| cmdline_u16("smoo.queue_size"))
    {
        child_args.push(OsStr::new("--queue-depth").to_os_string());
        child_args.push(OsStr::new(&queue_depth.to_string()).to_os_string());
        info!("pid1: using queue depth {queue_depth} from cmdline");
    }
    if let Some(queue_count) = cmdline_u16("smoo.queue_count") {
        child_args.push(OsStr::new("--queue-count").to_os_string());
        child_args.push(OsStr::new(&queue_count.to_string()).to_os_string());
        info!("pid1: using queue count {queue_count} from cmdline");
    }
    if let Some(max_io_bytes) =
        cmdline_usize("smoo.max_io_bytes").or_else(|| cmdline_usize("smoo.max_io"))
    {
        child_args.push(OsStr::new("--max-io").to_os_string());
        child_args.push(OsStr::new(&max_io_bytes.to_string()).to_os_string());
        info!("pid1: using max io bytes {max_io_bytes} from cmdline");
    }
    if let Some(vendor_id) =
        cmdline_u16_flexible("smoo.vendor").or_else(|| cmdline_u16_flexible("smoo.vendor_id"))
    {
        child_args.push(OsStr::new("--vendor-id").to_os_string());
        child_args.push(OsStr::new(&format!("0x{vendor_id:04x}")).to_os_string());
        info!("pid1: using vendor id 0x{vendor_id:04x} from cmdline");
    }
    if let Some(product_id) =
        cmdline_u16_flexible("smoo.product").or_else(|| cmdline_u16_flexible("smoo.product_id"))
    {
        child_args.push(OsStr::new("--product-id").to_os_string());
        child_args.push(OsStr::new(&format!("0x{product_id:04x}")).to_os_string());
        info!("pid1: using product id 0x{product_id:04x} from cmdline");
    }
    if let Some(serial) = cmdline_value("smoo.serial") {
        let serial = serial.trim();
        if !serial.is_empty() {
            child_args.push(OsStr::new("--serial").to_os_string());
            child_args.push(OsStr::new(serial).to_os_string());
            info!("pid1: using USB serial from cmdline");
        }
    }
    if let Some(ffs_dir) = ffs_dir {
        child_args.push(OsStr::new("--ffs-dir").to_os_string());
        child_args.push(ffs_dir.as_os_str().to_os_string());
    }
    let mut cmd = std::process::Command::new(exe);
    cmd.env(STAGE0_ROLE_ENV, STAGE0_ROLE_GADGET_CHILD);
    if let Some(log_level) = cmdline_value("smoo.log") {
        cmd.env("RUST_LOG", log_level);
        info!("pid1: set RUST_LOG from smoo.log");
    }
    debug!(
        "pid1: spawning gadget child exe={:?} args={:?}",
        cmd.get_program(),
        child_args
    );
    cmd.args(child_args.iter().skip(1));
    cmd.stdin(std::process::Stdio::null());
    cmd.spawn().context("spawn gadget process")
}

fn describe_exit_status(status: std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            return format!("exit code {code}");
        }
        if let Some(signal) = status.signal() {
            return format!("signal {signal}");
        }
    }
    status.to_string()
}

fn write_kmsg_line(message: &str) {
    if let Ok(mut file) = File::options().write(true).open("/dev/kmsg") {
        let _ = writeln!(file, "{message}");
    }
}

fn spawn_kmsg_daemon() -> Result<std::process::Child> {
    let exe = std::env::current_exe().context("locate self")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.env(STAGE0_ROLE_ENV, STAGE0_ROLE_KMSG_CHILD);
    if let Some(log_level) = cmdline_value("smoo.log") {
        cmd.env("RUST_LOG", log_level);
        info!("pid1: set RUST_LOG from smoo.log for kmsg forwarder");
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.spawn().context("spawn kmsg forwarder")
}

struct DrmCard {
    file: File,
}

impl AsFd for DrmCard {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl drm::Device for DrmCard {}
impl drm::control::Device for DrmCard {}

struct FramebufferSession {
    card: DrmCard,
    dumb: drm::control::dumbbuffer::DumbBuffer,
    fb: drm::control::framebuffer::Handle,
    connector: drm::control::connector::Handle,
    crtc: drm::control::crtc::Handle,
}

impl FramebufferSession {
    fn open_and_paint() -> Result<Self> {
        let mut last_err: Option<anyhow::Error> = None;
        for idx in 0..8u8 {
            let path = format!("/dev/dri/card{idx}");
            if !Path::new(&path).exists() {
                continue;
            }
            match Self::open_card(&path) {
                Ok(session) => return Ok(session),
                Err(err) => {
                    last_err = Some(err.context(format!("probe {path}")));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no DRM card nodes found")))
    }

    fn open_card(path: &str) -> Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open {path}"))?;
        let card = DrmCard { file };

        let _ = card.set_client_capability(ClientCapability::UniversalPlanes, true);
        card.acquire_master_lock().context("set DRM master")?;

        let resources = card.resource_handles().context("get DRM resources")?;
        let (connector, mode) = pick_connector_and_mode(&card, &resources)?;
        let crtc = *resources
            .crtcs()
            .first()
            .ok_or_else(|| anyhow!("DRM has no CRTC"))?;

        let (width, height) = mode.size();
        let mut dumb = card
            .create_dumb_buffer(
                (u32::from(width), u32::from(height)),
                drm::buffer::DrmFourcc::Xrgb8888,
                32,
            )
            .context("create dumb buffer")?;
        let fb = card
            .add_framebuffer(&dumb, 24, 32)
            .context("add framebuffer")?;

        let pitch = dumb.pitch() as usize;
        {
            let mut map = card.map_dumb_buffer(&mut dumb).context("map dumb buffer")?;
            fill_hot_pink(map.as_mut(), pitch, width as usize, height as usize);
        }

        card.set_crtc(crtc, Some(fb), (0, 0), &[connector], Some(mode))
            .context("set CRTC")?;

        Ok(Self {
            card,
            dumb,
            fb,
            connector,
            crtc,
        })
    }
}

impl Drop for FramebufferSession {
    fn drop(&mut self) {
        let _ = self
            .card
            .set_crtc(self.crtc, None, (0, 0), &[self.connector], None);
        let _ = self.card.destroy_framebuffer(self.fb);
        let _ = self.card.destroy_dumb_buffer(self.dumb);
        let _ = self.card.release_master_lock();
    }
}

fn pick_connector_and_mode(
    card: &DrmCard,
    resources: &drm::control::ResourceHandles,
) -> Result<(drm::control::connector::Handle, drm::control::Mode)> {
    for connector in resources.connectors() {
        let info = card
            .get_connector(*connector, false)
            .with_context(|| format!("get connector {connector:?}"))?;
        if info.state() != drm::control::connector::State::Connected {
            continue;
        }
        let mode = match info.modes().first() {
            Some(mode) => *mode,
            None => continue,
        };
        return Ok((*connector, mode));
    }
    Err(anyhow!("no connected connector with display mode"))
}

fn fill_hot_pink(buf: &mut [u8], stride: usize, width: usize, height: usize) {
    let pixel = [0x80u8, 0x00u8, 0xFFu8, 0x00u8];
    for y in 0..height {
        let row_start = y.saturating_mul(stride);
        let row_end = row_start.saturating_add(width.saturating_mul(4));
        if row_end > buf.len() {
            break;
        }
        let row = &mut buf[row_start..row_end];
        for px in row.chunks_exact_mut(4) {
            px.copy_from_slice(&pixel);
        }
    }
}

fn spawn_framebuffer_child() -> Result<std::process::Child> {
    let exe = std::env::current_exe().context("locate self")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.env(STAGE0_ROLE_ENV, STAGE0_ROLE_FRAMEBUFFER_CHILD);
    if let Some(log_level) = cmdline_value("smoo.log") {
        cmd.env("RUST_LOG", log_level);
        info!("pid1: set RUST_LOG from smoo.log for framebuffer worker");
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.spawn().context("spawn framebuffer worker")
}

fn run_framebuffer_child() -> Result<()> {
    loop {
        match FramebufferSession::open_and_paint() {
            Ok(_session) => {
                info!("fb: hot-pink framebuffer active");
                loop {
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
            Err(err) => {
                warn!(error = ?err, "fb: DRM setup failed; retrying");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn run_kmsg_daemon() -> Result<()> {
    const KMSG_PATH: &str = "/dev/kmsg";
    const TTY_PATH: &str = "/dev/ttyGS0";
    let mut buffer = vec![0u8; 8192];
    let mut pending = Vec::new();
    let mut last_tty_error = Instant::now() - Duration::from_secs(60);
    loop {
        let mut kmsg = match File::open(KMSG_PATH) {
            Ok(file) => file,
            Err(err) => {
                warn!(error = ?err, "kmsg: open failed; retrying");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let mut tty = match std::fs::OpenOptions::new().write(true).open(TTY_PATH) {
            Ok(file) => file,
            Err(err) => {
                warn!(error = ?err, "kmsg: ttyGS0 unavailable; retrying");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        loop {
            match kmsg.read(&mut buffer) {
                Ok(0) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(n) => {
                    pending.extend_from_slice(&buffer[..n]);
                    while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                        let mut line = pending.drain(..=pos).collect::<Vec<u8>>();
                        if line.ends_with(b"\n") {
                            line.pop();
                        }
                        if line.ends_with(b"\r") {
                            line.pop();
                        }
                        if line.is_empty() {
                            continue;
                        }
                        let Some(sep) = line.iter().position(|&b| b == b';') else {
                            continue;
                        };
                        let meta = &line[..sep];
                        let msg = &line[sep + 1..];
                        if msg.is_empty() {
                            continue;
                        }
                        if let Some(prefix) = kmsg_prefix(meta) {
                            if let Err(err) = tty.write_all(prefix.as_bytes()) {
                                if handle_tty_write_error(&err, &mut last_tty_error) {
                                    return Ok(());
                                }
                                pending.clear();
                                break;
                            }
                        }
                        if let Err(err) = tty.write_all(msg) {
                            if handle_tty_write_error(&err, &mut last_tty_error) {
                                return Ok(());
                            }
                            pending.clear();
                            break;
                        }
                        if let Err(err) = tty.write_all(b"\r\n") {
                            if handle_tty_write_error(&err, &mut last_tty_error) {
                                return Ok(());
                            }
                            pending.clear();
                            break;
                        }
                    }
                    if pending.len() > 1024 * 1024 {
                        pending.clear();
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(err) => {
                    warn!(error = ?err, "kmsg: read failed; reopening");
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn kmsg_prefix(meta: &[u8]) -> Option<String> {
    let meta_str = std::str::from_utf8(meta).ok()?;
    let mut parts = meta_str.splitn(4, ',');
    let _pri = parts.next()?;
    let _seq = parts.next()?;
    let ts = parts.next()?;
    let ts = ts.parse::<u64>().ok()?;
    let secs = ts / 1_000_000;
    let usec = ts % 1_000_000;
    Some(format!("[{secs:>5}.{usec:06}] "))
}

fn handle_tty_write_error(err: &io::Error, last_log: &mut Instant) -> bool {
    if err.raw_os_error() == Some(libc::EIO) {
        info!("kmsg: ttyGS0 closed (EIO); exiting");
        return true;
    }
    let now = Instant::now();
    if now.duration_since(*last_log) >= Duration::from_secs(2) {
        warn!(error = ?err, "kmsg: write to ttyGS0 failed; reopening");
        *last_log = now;
    } else {
        debug!(error = ?err, "kmsg: write to ttyGS0 failed; reopening");
    }
    false
}

fn filesystem_available(name: &str) -> Result<bool> {
    let data = std::fs::read_to_string("/proc/filesystems").context("read /proc/filesystems")?;
    Ok(data
        .lines()
        .any(|line| line.split_whitespace().last() == Some(name)))
}

fn chroot_to(path: &str) -> Result<()> {
    let path = CString::new(path)?;
    let res = unsafe { libc::chroot(path.as_ptr()) };
    if res != 0 {
        return Err(io::Error::last_os_error()).context("chroot syscall failed");
    }
    Ok(())
}

fn bind_mount_if_needed(src: &str, dst: &str, recursive: bool) -> Result<()> {
    if !Path::new(src).exists() {
        warn!("pid1: bind mount source {src} missing, skipping");
        return Ok(());
    }
    if is_mount_point(dst)? {
        info!("pid1: {dst} already a mount point");
        return Ok(());
    }
    let mut flags = libc::MS_BIND as libc::c_ulong;
    if recursive {
        flags |= libc::MS_REC as libc::c_ulong;
    }
    mount_fs(Some(src), dst, None, flags, None)
        .with_context(|| format!("bind mount {src} -> {dst}"))?;
    Ok(())
}

fn is_mount_point(path: &str) -> Result<bool> {
    let data =
        std::fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    for line in data.lines() {
        let mut parts = line.split_whitespace();
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        if let Some(mount_point) = parts.next() {
            if mount_point == path {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn mount_fs(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let target = CString::new(target)?;
    let source = source.map(CString::new).transpose()?;
    let fstype = fstype.map(CString::new).transpose()?;
    let data = data.map(CString::new).transpose()?;
    let data_ptr = data
        .as_ref()
        .map(|s| s.as_ptr() as *const libc::c_void)
        .unwrap_or(std::ptr::null());
    let res = unsafe {
        libc::mount(
            source
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            target.as_ptr(),
            fstype
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            flags,
            data_ptr,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error()).context("mount failed");
    }
    Ok(())
}

struct GadgetGuard {
    registration: RegGadget,
    ffs_dir: PathBuf,
}

fn setup_pid1_configfs(args: &Args) -> Result<GadgetGuard> {
    usb_gadget::remove_all().context("remove existing USB gadgets")?;
    let mut builder = configfs_builder();
    builder.ffs_no_init = true;
    let (mut custom, handle) = builder.build();

    let klass = Class::interface_specific();
    let (vendor_id, product_id, serial) = gadget_usb_identity(args);
    let id = Id::new(vendor_id, product_id);
    let strings = Strings::new("smoo", "smoo gadget", serial.as_str());
    let mut config = Config::new("config").with_function(handle);

    if cmdline_bool("smoo.acm") {
        let serial_builder = Serial::builder(SerialClass::Acm);
        let (_serial, serial_handle) = serial_builder.build();
        config = config.with_function(serial_handle);
        info!("pid1: enabled USB ACM function");
    }

    let gadget = Gadget::new(klass, id, strings).with_config(config);
    let reg = gadget.register().context("register gadget")?;
    let ffs_dir = custom.ffs_dir().context("resolve FunctionFS dir")?;

    Ok(GadgetGuard {
        registration: reg,
        ffs_dir,
    })
}

fn gadget_usb_identity(args: &Args) -> (u16, u16, String) {
    let vendor_id = cmdline_u16_flexible("smoo.vendor")
        .or_else(|| cmdline_u16_flexible("smoo.vendor_id"))
        .unwrap_or(args.vendor_id);
    let product_id = cmdline_u16_flexible("smoo.product")
        .or_else(|| cmdline_u16_flexible("smoo.product_id"))
        .unwrap_or(args.product_id);
    let serial = cmdline_value("smoo.serial")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| args.serial.clone());
    (vendor_id, product_id, serial)
}

fn configfs_builder() -> CustomBuilder {
    Custom::builder().with_interface(
        Interface::new(Class::vendor_specific(SMOO_SUBCLASS, SMOO_PROTOCOL), "smoo")
            .with_endpoint(interrupt_in_ep())
            .with_endpoint(interrupt_out_ep())
            .with_endpoint(bulk_in_ep())
            .with_endpoint(bulk_out_ep()),
    )
}

fn interrupt_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Interrupt, 1024)
}

fn interrupt_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Interrupt, 1024)
}

fn bulk_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Bulk, 512)
}

fn bulk_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Bulk, 512)
}

fn make_ep(direction: EndpointDirection, ty: TransferType, packet_size: u16) -> Endpoint {
    let mut ep = match ty {
        TransferType::Bulk => Endpoint::bulk(direction),
        _ => Endpoint::custom(direction, ty),
    };
    ep.max_packet_size_hs = packet_size;
    ep.max_packet_size_ss = packet_size;
    if matches!(ty, TransferType::Interrupt) {
        ep.interval = 1;
    }
    ep
}

fn parse_hex_u16(input: &str) -> Result<u16, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid1_role_sanitizes_bootloader_tail_on_init() {
        let cleaned = sanitize_startup_args(
            vec![OsString::from("/init"), OsString::from("android")],
            Stage0Role::Pid1,
        );
        assert_eq!(cleaned, vec![OsString::from("/init")]);
    }

    #[test]
    fn child_roles_preserve_full_args_on_init() {
        let raw = vec![
            OsString::from("/init"),
            OsString::from("--queue-depth"),
            OsString::from("64"),
        ];
        assert_eq!(
            sanitize_startup_args(raw.clone(), Stage0Role::GadgetChild),
            raw
        );
    }

    #[test]
    fn role_parser_defaults_and_matches_known_values() {
        assert_eq!(parse_stage0_role(None), Stage0Role::Pid1);
        assert_eq!(
            parse_stage0_role(Some(OsStr::new(STAGE0_ROLE_GADGET_CHILD))),
            Stage0Role::GadgetChild
        );
        assert_eq!(
            parse_stage0_role(Some(OsStr::new(STAGE0_ROLE_KMSG_CHILD))),
            Stage0Role::KmsgChild
        );
        assert_eq!(
            parse_stage0_role(Some(OsStr::new(STAGE0_ROLE_FRAMEBUFFER_CHILD))),
            Stage0Role::FramebufferChild
        );
        assert_eq!(
            parse_stage0_role(Some(OsStr::new("weird-value"))),
            Stage0Role::Pid1
        );
    }
}
