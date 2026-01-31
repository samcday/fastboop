#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod kernel;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use fastboop_core::{DeviceProfile, Personalization, RootfsProvider};
use fdt::Fdt;

const FIRMWARE_LIST_PATH: &str = "etc/smoo/firmware.list";
const MODULES_LOAD_PATH: &str = "etc/modules-load.d/fastboop-stage0.conf";
const MODULES_ROOT: &str = "lib/modules";
const FIRMWARE_ROOT: &str = "lib/firmware";
const SMOO_BIN_PATH: &str = "usr/bin/smoo-gadget";
const BASE_REQUIRED_MODULES: &[&str] = &[
    "configfs",
    "libcomposite",
    "usb_f_fs",
    "ublk_drv",
    "overlay",
];
const MODULE_INDEX_FILES: &[&str] = &[
    "modules.dep",
    "modules.alias",
    "modules.builtin",
    "modules.order",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage0Error {
    MissingFile(String),
    EmptyPath,
    Oversized(u64),
    ParseError(&'static str),
    InvalidCpio(&'static str),
    KernelFormat(&'static str),
    KernelDecode(&'static str),
}

#[derive(Default)]
pub struct Stage0Options {
    pub extra_modules: Vec<String>,
    pub dtb_override: Option<Vec<u8>>,
    pub scan_modules: bool,
    pub scan_firmware: bool,
    pub include_dtb_firmware: bool,
    pub allow_missing_firmware: bool,
    pub enable_serial: bool,
    pub personalization: Option<Personalization>,
}

/// Resulting artifacts and recommended kernel cmdline additions.
pub struct Stage0Build {
    pub kernel_image: Vec<u8>,
    pub kernel_path: String,
    pub smoo_path: String,
    pub initrd: Vec<u8>,
    pub dtb: Vec<u8>,
    pub kernel_cmdline_append: String,
}

pub fn cpio_contains_path(data: &[u8], path: &str) -> Result<bool, Stage0Error> {
    let entries = parse_cpio_newc(data)?;
    Ok(entries.iter().any(|e| e.path == path))
}

#[derive(Clone, Debug)]
struct ModulesDir {
    kver: String,
    source_root: String,
}

/// Build a minimal stage0 initrd containing smoo as PID1 plus modules/firmware.
pub fn build_stage0<P: RootfsProvider>(
    profile: &DeviceProfile,
    rootfs: &P,
    opts: &Stage0Options,
    extra_cmdline: Option<&str>,
    existing_cpio: Option<&[u8]>,
) -> Result<Stage0Build, Stage0Error> {
    let kernel_path = detect_kernel(rootfs)?;
    let kernel_image = rootfs
        .read_all(&kernel_path)
        .map_err(|_| Stage0Error::MissingFile(kernel_path.clone()))?;

    let smoo_path = SMOO_BIN_PATH.to_string();

    let mut modules_dir = None;
    let mut modules_map = ModulesMap::new();
    let mut modules_dep = ModulesDep::new();
    let mut module_paths = ModulePaths::new();
    let mut modules_builtin = BTreeSet::new();
    let needs_modules = opts.scan_modules
        || !opts.extra_modules.is_empty()
        || !profile.stage0.kernel_modules.is_empty();
    if needs_modules {
        let dir = detect_modules_dir(rootfs)?;
        let (map, dep, paths, builtin) = load_modules_metadata(rootfs, &dir)?;
        modules_dir = Some(dir);
        modules_map = map;
        modules_dep = dep;
        module_paths = paths;
        modules_builtin = builtin;
    }

    let dtb_bytes = if let Some(override_bytes) = &opts.dtb_override {
        override_bytes.clone()
    } else {
        let dtb_path = select_dtb(profile, rootfs)?;
        rootfs
            .read_all(&dtb_path)
            .map_err(|_| Stage0Error::MissingFile(dtb_path.clone()))?
    };

    let kernel_image = kernel::normalize_kernel(profile, &kernel_image)?;
    let dtb = Fdt::new(&dtb_bytes).map_err(|_| Stage0Error::ParseError("dtb"))?;

    let required_modules = collect_required_modules(
        profile,
        opts,
        &dtb,
        &modules_map,
        &modules_dep,
        &module_paths,
        &modules_builtin,
    );

    let firmware_files = if opts.scan_firmware {
        let firmware_files = load_firmware_list(rootfs)?;
        let dtb_firmware = if opts.include_dtb_firmware {
            firmware_from_dtb(&dtb)?
        } else {
            Vec::new()
        };
        merge_firmware_lists(firmware_files, dtb_firmware)
    } else {
        Vec::new()
    };

    let mut image = if let Some(data) = existing_cpio {
        CpioImage::from_bytes(data)?
    } else {
        CpioImage::new()
    };
    let has_smoo = image.has_path(SMOO_BIN_PATH);

    image.ensure_dir("dev")?;
    image.ensure_dir("proc")?;
    image.ensure_dir("sys")?;
    image.ensure_dir("etc")?;
    image.ensure_dir("etc/smoo")?;
    image.ensure_dir("etc/modules-load.d")?;
    image.ensure_dir("lib")?;
    image.ensure_dir("lib/modules")?;
    image.ensure_dir("lib/firmware")?;
    image.ensure_dir("sbin")?;
    image.ensure_dir("usr")?;
    image.ensure_dir("usr/bin")?;

    if !has_smoo {
        let smoo_init = rootfs
            .read_all("smoo-gadget")
            .map_err(|_| Stage0Error::MissingFile("smoo-gadget".into()))?;
        image.ensure_file(SMOO_BIN_PATH, 0o100755, &smoo_init)?;
    }
    image.ensure_symlink("init", SMOO_BIN_PATH)?;

    if !required_modules.is_empty() {
        let modules_dir = modules_dir
            .ok_or_else(|| Stage0Error::MissingFile("/lib/modules (modules directory)".into()))?;
        copy_module_indexes(rootfs, &modules_dir, &mut image)?;

        for module in &required_modules {
            if modules_builtin.contains(module) {
                continue;
            }
            let (rel, path) = module_path_for(module, &module_paths, &modules_dir)?;
            let data = rootfs
                .read_all(&path)
                .map_err(|_| Stage0Error::MissingFile(path.clone()))?;
            let cpio_path = format!("{MODULES_ROOT}/{rel}");
            image.ensure_file(cpio_path.as_str(), 0o100644, &data)?;
        }
    }

    for firmware_rel in firmware_files {
        let rel = trim_leading_slash(&firmware_rel)?;
        let path = join_paths("/lib/firmware", rel)?;
        let data = match rootfs.read_all(&path) {
            Ok(d) => d,
            Err(_) if opts.allow_missing_firmware => {
                continue;
            }
            Err(_) => return Err(Stage0Error::MissingFile(path.clone())),
        };
        let cpio_path = format!("{FIRMWARE_ROOT}/{rel}");
        image.ensure_file(cpio_path.as_str(), 0o100644, &data)?;
    }

    let module_load_list: Vec<String> = required_modules
        .iter()
        .filter(|m| !modules_builtin.contains(*m))
        .cloned()
        .collect();
    let module_load_bytes = serialize_module_load(&module_load_list);
    image.ensure_file(MODULES_LOAD_PATH, 0o100644, &module_load_bytes)?;

    let mut cmdline_parts: Vec<String> = Vec::new();
    if opts.enable_serial {
        cmdline_parts.push("smoo.acm=1".to_string());
        cmdline_parts.push("console=ttyGS0".to_string());
        cmdline_parts.push("console=tty0".to_string());
    }
    if let Some(personalization) = &opts.personalization {
        let personalization = personalization.cmdline_append();
        if !personalization.is_empty() {
            cmdline_parts.push(personalization);
        }
    }
    if let Some(extra) = extra_cmdline {
        let extra = extra.trim();
        if !extra.is_empty() {
            cmdline_parts.push(extra.to_string());
        }
    }
    let cmdline = if cmdline_parts.is_empty() {
        String::new()
    } else {
        cmdline_parts.join(" ")
    };

    Ok(Stage0Build {
        kernel_image,
        kernel_path,
        smoo_path,
        initrd: image.finish()?,
        dtb: dtb_bytes,
        kernel_cmdline_append: cmdline,
    })
}

fn detect_kernel<P: RootfsProvider>(rootfs: &P) -> Result<String, Stage0Error> {
    if let Some(found) = find_kernel_in_modules(rootfs, "/lib/modules")? {
        return Ok(found);
    }
    if let Some(found) = find_kernel_in_modules(rootfs, "/usr/lib/modules")? {
        return Ok(found);
    }

    const CANDIDATES: &[&str] = &["/boot/vmlinuz", "/boot/Image", "/boot/Image.gz"];
    for cand in CANDIDATES {
        if rootfs.exists(cand).unwrap_or(false) {
            return Ok(cand.trim_start_matches('/').to_string());
        }
    }
    if let Some(found) = find_kernel_recursive(rootfs, "/boot", 3)? {
        return Ok(found);
    }
    Err(Stage0Error::MissingFile("kernel image".into()))
}

fn find_kernel_in_modules<P: RootfsProvider>(
    rootfs: &P,
    base: &str,
) -> Result<Option<String>, Stage0Error> {
    let mut entries = match rootfs.read_dir(base) {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };
    entries.sort();
    for entry in entries {
        if entry.contains("rescue") {
            continue;
        }
        let candidate = format!("{}/{}/vmlinuz", base, entry);
        if rootfs.exists(&candidate).unwrap_or(false) {
            return Ok(Some(candidate.trim_start_matches('/').to_string()));
        }
    }
    Ok(None)
}

fn detect_modules_dir<P: RootfsProvider>(rootfs: &P) -> Result<ModulesDir, Stage0Error> {
    let bases = ["/lib/modules", "/usr/lib/modules"];
    for base in &bases {
        if let Ok(mut entries) = rootfs.read_dir(base) {
            entries.sort();
            if let Some(first) = entries.first() {
                return Ok(ModulesDir {
                    kver: first.clone(),
                    source_root: format!("{}/{}", base, first),
                });
            }
        }
    }
    Err(Stage0Error::MissingFile(
        "/lib/modules or /usr/lib/modules".into(),
    ))
}

fn find_kernel_recursive<P: RootfsProvider>(
    rootfs: &P,
    start: &str,
    max_depth: usize,
) -> Result<Option<String>, Stage0Error> {
    let mut stack = Vec::new();
    stack.push((start.trim_end_matches('/').to_string(), 0usize));
    while let Some((dir, depth)) = stack.pop() {
        let entries = match rootfs.read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for name in entries {
            let mut path = dir.clone();
            path.push('/');
            path.push_str(&name);
            let is_dir = rootfs.read_dir(&path).is_ok();
            if is_dir && depth < max_depth {
                stack.push((path, depth + 1));
            } else if is_kernel_name(&name) {
                return Ok(Some(path.trim_start_matches('/').to_string()));
            }
        }
    }
    Ok(None)
}

fn is_kernel_name(name: &str) -> bool {
    name.starts_with("vmlinuz") || name.starts_with("Image") || name == "linux"
}

fn load_modules_metadata<P: RootfsProvider>(
    rootfs: &P,
    modules_dir: &ModulesDir,
) -> Result<(ModulesMap, ModulesDep, ModulePaths, BTreeSet<String>), Stage0Error> {
    let alias_path = format!("{}/modules.alias", modules_dir.source_root);
    let alias_data = rootfs
        .read_all(&alias_path)
        .map_err(|_| Stage0Error::MissingFile(alias_path.clone()))?;
    let modules_map = parse_modules_alias(&alias_data);

    let dep_path = format!("{}/modules.dep", modules_dir.source_root);
    let dep_data = rootfs
        .read_all(&dep_path)
        .map_err(|_| Stage0Error::MissingFile(dep_path.clone()))?;
    let (modules_dep, module_paths) = parse_modules_dep(&dep_data);

    let builtin_path = format!("{}/modules.builtin", modules_dir.source_root);
    let builtin_data = rootfs.read_all(&builtin_path).unwrap_or_default();
    let modules_builtin = parse_modules_builtin(&builtin_data);

    Ok((modules_map, modules_dep, module_paths, modules_builtin))
}

fn copy_module_indexes<P: RootfsProvider>(
    rootfs: &P,
    modules_dir: &ModulesDir,
    image: &mut CpioImage,
) -> Result<(), Stage0Error> {
    for name in MODULE_INDEX_FILES {
        let source = format!("{}/{}", modules_dir.source_root, name);
        if !rootfs.exists(&source).unwrap_or(false) {
            continue;
        }
        let data = rootfs
            .read_all(&source)
            .map_err(|_| Stage0Error::MissingFile(source.clone()))?;
        let rel = format!("{}/{}", modules_dir.kver, name);
        let cpio_path = format!("{MODULES_ROOT}/{rel}");
        image.ensure_file(cpio_path.as_str(), 0o100644, &data)?;
    }
    Ok(())
}

fn select_dtb<P: RootfsProvider>(
    profile: &DeviceProfile,
    rootfs: &P,
) -> Result<String, Stage0Error> {
    let name = profile.devicetree_name.trim_start_matches('/');
    let mut candidates = Vec::new();
    candidates.extend_from_slice(&[
        format!("/boot/dtb/{}.dtb", name),
        format!("/boot/{}.dtb", name),
        format!("/lib/firmware/{}.dtb", name),
        format!("/usr/lib/firmware/{}.dtb", name),
    ]);
    if let Ok(mods) = rootfs.read_dir("/usr/lib/modules") {
        for m in mods {
            let base = format!("/usr/lib/modules/{}/dtb", m);
            candidates.push(format!("{}/{}.dtb", base, name));
            candidates.push(format!("{}/{}", base, name));
            if let Ok(entries) = rootfs.read_dir(&base) {
                for e in entries {
                    if e.ends_with(".dtb") && e.contains(name) {
                        candidates.push(format!("{}/{}", base, e));
                    }
                }
            }
        }
    }
    for cand in candidates {
        if rootfs.exists(&cand).unwrap_or(false) {
            return Ok(cand.trim_start_matches('/').to_string());
        }
    }
    Err(Stage0Error::MissingFile(format!(
        "dtb for {}",
        profile.devicetree_name
    )))
}

fn collect_required_modules(
    profile: &DeviceProfile,
    opts: &Stage0Options,
    dtb: &Fdt<'_>,
    modules_map: &ModulesMap,
    modules_dep: &ModulesDep,
    module_paths: &ModulePaths,
    modules_builtin: &BTreeSet<String>,
) -> Vec<String> {
    let mut required = Vec::new();
    let mut required_set = BTreeSet::new();
    for m in BASE_REQUIRED_MODULES {
        push_module_unique(&mut required, &mut required_set, m);
    }
    for m in &profile.stage0.kernel_modules {
        push_module_unique(&mut required, &mut required_set, m);
    }
    for m in &opts.extra_modules {
        push_module_unique(&mut required, &mut required_set, m);
    }
    if opts.enable_serial {
        push_module_unique(&mut required, &mut required_set, "usb_f_acm");
    }
    if opts.scan_modules {
        let compatibles = dtb_compatibles(dtb);
        for compat in compatibles {
            if let Some(module) = modules_map.get(&compat)
                && (module_paths.contains_key(module) || modules_builtin.contains(module))
            {
                push_module_unique(&mut required, &mut required_set, module);
            }
        }
    }

    let mut ordered = Vec::new();
    let mut visited = BTreeSet::new();
    for m in required {
        collect_with_deps(&m, modules_dep, &mut visited, &mut ordered);
    }
    ordered
}

fn push_module_unique(out: &mut Vec<String>, seen: &mut BTreeSet<String>, module: &str) {
    if seen.insert(module.to_string()) {
        out.push(module.to_string());
    }
}

fn collect_with_deps(
    module: &str,
    dep: &ModulesDep,
    visited: &mut BTreeSet<String>,
    out: &mut Vec<String>,
) {
    if !visited.insert(module.to_string()) {
        return;
    }
    if let Some(deps) = dep.get(module) {
        for d in deps {
            collect_with_deps(d, dep, visited, out);
        }
    }
    out.push(module.to_string());
}

fn firmware_from_dtb(dtb: &Fdt<'_>) -> Result<Vec<String>, Stage0Error> {
    let mut out = Vec::new();
    for node in dtb.all_nodes() {
        if let Some(prop) = node.property("firmware-name") {
            if let Some(s) = prop.as_str() {
                out.push(s.to_string());
                continue;
            }
            let bytes = prop.value;
            let mut start = 0;
            for (idx, b) in bytes.iter().enumerate() {
                if *b == 0 {
                    if let Ok(s) = core::str::from_utf8(&bytes[start..idx])
                        && !s.is_empty()
                    {
                        out.push(s.to_string());
                    }
                    start = idx + 1;
                }
            }
        }
    }
    Ok(out)
}

fn merge_firmware_lists(mut a: Vec<String>, b: Vec<String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    let mut out = Vec::new();
    for f in a.drain(..).chain(b.into_iter()) {
        if set.insert(f.clone()) {
            out.push(f);
        }
    }
    out
}

fn dtb_compatibles(dtb: &Fdt<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for node in dtb.all_nodes() {
        if let Some(compats) = node.compatible() {
            for c in compats.all() {
                out.push(c.to_string());
            }
        }
    }
    out
}

type ModulesMap = BTreeMap<String, String>;
type ModulesDep = BTreeMap<String, Vec<String>>;
type ModulePaths = BTreeMap<String, String>;

fn parse_modules_alias(data: &[u8]) -> ModulesMap {
    let mut map = ModulesMap::new();
    for line in data.split(|b| *b == b'\n') {
        if !line.starts_with(b"alias ") {
            continue;
        }
        let line_str = match core::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut parts = line_str.split_whitespace();
        let _alias = parts.next();
        let alias_val = parts.next().unwrap_or_default();
        let module = parts.next().unwrap_or_default();
        let alias_val = match alias_val.strip_prefix("of:") {
            Some(a) => a,
            None => continue,
        };
        if let Some((_, compat)) = alias_val.split_once('C') {
            map.insert(compat.to_string(), module.to_string());
        }
    }
    map
}

fn parse_modules_dep(data: &[u8]) -> (ModulesDep, ModulePaths) {
    let mut map = ModulesDep::new();
    let mut paths = ModulePaths::new();
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Some((left, deps)) = split_two(line, b':') {
            let module_name = path_to_module_name(left);
            if let Ok(path_str) = core::str::from_utf8(left) {
                paths.insert(module_name.clone(), path_str.trim().to_string());
            }
            let mut dep_list = Vec::new();
            for dep in deps.split(|b| *b == b' ') {
                if dep.is_empty() {
                    continue;
                }
                dep_list.push(path_to_module_name(dep));
            }
            map.insert(module_name, dep_list);
        }
    }
    (map, paths)
}

fn parse_modules_builtin(data: &[u8]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        set.insert(path_to_module_name(line));
    }
    set
}

fn path_to_module_name(path: &[u8]) -> String {
    let s = core::str::from_utf8(path).unwrap_or_default();
    let base = s.rsplit('/').next().unwrap_or(s);
    strip_module_suffix(base).to_string()
}

fn strip_module_suffix(name: &str) -> &str {
    let mut n = name;
    for suffix in [".ko.zst", ".ko.xz", ".ko.gz", ".ko"] {
        if let Some(stripped) = n.strip_suffix(suffix) {
            n = stripped;
            break;
        }
    }
    n
}

fn split_two(line: &[u8], delim: u8) -> Option<(&[u8], &[u8])> {
    line.iter()
        .position(|b| *b == delim)
        .map(|idx| (&line[..idx], &line[idx + 1..]))
}

fn module_path_for(
    module: &str,
    paths: &ModulePaths,
    modules_dir: &ModulesDir,
) -> Result<(String, String), Stage0Error> {
    if let Some(path) = paths.get(module) {
        let rel = path.trim_start_matches('/').to_string();
        let rel_cpio = format!("{}/{}", modules_dir.kver, rel);
        let source = format!("{}/{}", modules_dir.source_root, rel);
        return Ok((rel_cpio, source));
    }
    let rel = format!("{}/{}.ko", modules_dir.kver, module);
    let source = format!("{}/{}.ko", modules_dir.source_root, module);
    Ok((rel, source))
}

fn load_firmware_list<P: RootfsProvider>(rootfs: &P) -> Result<Vec<String>, Stage0Error> {
    if !rootfs.exists(FIRMWARE_LIST_PATH).unwrap_or(false) {
        return Ok(Vec::new());
    }
    let data = rootfs
        .read_all(FIRMWARE_LIST_PATH)
        .map_err(|_| Stage0Error::MissingFile(FIRMWARE_LIST_PATH.into()))?;
    parse_lines(&data)
}

fn parse_lines(data: &[u8]) -> Result<Vec<String>, Stage0Error> {
    let mut out = Vec::new();
    for line in data.split(|b| *b == b'\n') {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() || trimmed.starts_with(b"#") {
            continue;
        }
        let s = String::from_utf8(trimmed.to_vec()).map_err(|_| Stage0Error::EmptyPath)?;
        out.push(s);
    }
    Ok(out)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

fn trim_leading_slash(path: &str) -> Result<&str, Stage0Error> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(Stage0Error::EmptyPath);
    }
    Ok(trimmed)
}

fn join_paths(root: &str, rel: &str) -> Result<String, Stage0Error> {
    let rel = trim_leading_slash(rel)?;
    let mut s = String::from(root);
    if !s.is_empty() && !s.ends_with('/') {
        s.push('/');
    }
    s.push_str(rel);
    Ok(s)
}

fn serialize_module_load(entries: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for name in entries {
        out.extend_from_slice(name.as_bytes());
        out.push(b'\n');
    }
    out
}

#[derive(Clone, Debug)]
struct CpioEntry {
    path: String,
    mode: u32,
    data: Vec<u8>,
}

struct CpioImage {
    entries: Vec<CpioEntry>,
    index: BTreeSet<String>,
}

impl CpioImage {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeSet::new(),
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, Stage0Error> {
        let entries = parse_cpio_newc(data)?;
        let mut index = BTreeSet::new();
        for e in &entries {
            index.insert(e.path.clone());
        }
        Ok(Self { entries, index })
    }

    fn ensure_dir(&mut self, path: &str) -> Result<(), Stage0Error> {
        if self.index.contains(path) {
            return Ok(());
        }
        self.push(CpioEntry {
            path: path.to_string(),
            mode: 0o040755,
            data: Vec::new(),
        });
        Ok(())
    }

    fn has_path(&self, path: &str) -> bool {
        self.index.contains(path)
    }

    fn ensure_file(&mut self, path: &str, mode: u32, data: &[u8]) -> Result<(), Stage0Error> {
        if self.index.contains(path) {
            return Ok(());
        }
        self.push(CpioEntry {
            path: path.to_string(),
            mode,
            data: data.to_vec(),
        });
        Ok(())
    }

    fn ensure_symlink(&mut self, path: &str, target: &str) -> Result<(), Stage0Error> {
        if self.index.contains(path) {
            return Ok(());
        }
        self.push(CpioEntry {
            path: path.to_string(),
            mode: 0o120777,
            data: target.as_bytes().to_vec(),
        });
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, Stage0Error> {
        let mut entries = self.entries;
        let mut index = self.index;

        let mut missing_dirs = BTreeSet::new();
        for entry in &entries {
            for parent in parent_paths(entry.path.as_str()) {
                if !index.contains(parent) {
                    missing_dirs.insert(parent.to_string());
                }
            }
        }
        for path in missing_dirs {
            index.insert(path.clone());
            entries.push(CpioEntry {
                path,
                mode: 0o040755,
                data: Vec::new(),
            });
        }

        entries.sort_by(|a, b| {
            let a_dir = is_dir_mode(a.mode);
            let b_dir = is_dir_mode(b.mode);
            match (a_dir, b_dir) {
                (true, false) => core::cmp::Ordering::Less,
                (false, true) => core::cmp::Ordering::Greater,
                _ => a.path.cmp(&b.path),
            }
        });

        let mut builder = CpioBuilder::new();
        for entry in entries {
            builder.entry(entry.path.as_str(), entry.mode, &entry.data)?;
        }
        builder.finish()
    }

    fn push(&mut self, entry: CpioEntry) {
        self.index.insert(entry.path.clone());
        self.entries.push(entry);
    }
}

fn parse_cpio_newc(data: &[u8]) -> Result<Vec<CpioEntry>, Stage0Error> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 6 <= data.len() {
        if &data[i..i + 6] != b"070701" {
            return Err(Stage0Error::InvalidCpio("bad magic"));
        }
        i += 6;
        let mut fields = [0u32; 13];
        for f in fields.iter_mut() {
            if i + 8 > data.len() {
                return Err(Stage0Error::InvalidCpio("short header"));
            }
            *f = hex_u32(&data[i..i + 8])?;
            i += 8;
        }
        let mode = fields[1];
        let filesize = fields[6] as usize;
        let namesize = fields[11] as usize;
        if i + namesize > data.len() {
            return Err(Stage0Error::InvalidCpio("short name"));
        }
        let name = &data[i..i + namesize];
        i += namesize;
        let name = core::str::from_utf8(name)
            .map_err(|_| Stage0Error::InvalidCpio("name utf8"))?
            .trim_end_matches('\0');
        i = align4(i);
        if name == "TRAILER!!!" {
            break;
        }
        if i + filesize > data.len() {
            return Err(Stage0Error::InvalidCpio("short data"));
        }
        let filedata = data[i..i + filesize].to_vec();
        i += filesize;
        i = align4(i);
        out.push(CpioEntry {
            path: name.to_string(),
            mode,
            data: filedata,
        });
    }
    Ok(out)
}

fn is_dir_mode(mode: u32) -> bool {
    (mode & 0o170000) == 0o040000
}

fn parent_paths(path: &str) -> impl Iterator<Item = &str> {
    let mut end = path.rfind('/');
    core::iter::from_fn(move || {
        let idx = end?;
        let parent = &path[..idx];
        end = parent.rfind('/');
        if parent.is_empty() {
            return None;
        }
        Some(parent)
    })
}

fn hex_u32(bytes: &[u8]) -> Result<u32, Stage0Error> {
    let mut v = 0u32;
    for &b in bytes {
        v = v.wrapping_shl(4);
        v |= match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a' + 10) as u32,
            b'A'..=b'F' => (b - b'A' + 10) as u32,
            _ => return Err(Stage0Error::InvalidCpio("hex")),
        };
    }
    Ok(v)
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

struct CpioBuilder {
    buf: Vec<u8>,
}

impl CpioBuilder {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn entry(&mut self, path: &str, mode: u32, data: &[u8]) -> Result<(), Stage0Error> {
        let name = trim_leading_slash(path)?;
        let namesize = name.len() + 1; // include NUL
        let filesize: u64 = data
            .len()
            .try_into()
            .map_err(|_| Stage0Error::Oversized(data.len() as u64))?;

        self.buf.extend_from_slice(b"070701");
        self.write_hex(0); // ino
        self.write_hex(mode);
        self.write_hex(0); // uid
        self.write_hex(0); // gid
        self.write_hex(1); // nlink
        self.write_hex(0); // mtime
        self.write_hex_u64(filesize)?;
        self.write_hex(0); // devmajor
        self.write_hex(0); // devminor
        self.write_hex(0); // rdevmajor
        self.write_hex(0); // rdevminor
        self.write_hex(namesize as u32);
        self.write_hex(0); // check

        self.buf.extend_from_slice(name.as_bytes());
        self.buf.push(0);
        self.pad();

        self.buf.extend_from_slice(data);
        self.pad();
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, Stage0Error> {
        self.entry("TRAILER!!!", 0o100644, &[])?;
        Ok(self.buf)
    }

    fn write_hex(&mut self, value: u32) {
        let s = format_hex(value);
        self.buf.extend_from_slice(s.as_bytes());
    }

    fn write_hex_u64(&mut self, value: u64) -> Result<(), Stage0Error> {
        if value > u32::MAX as u64 {
            return Err(Stage0Error::Oversized(value));
        }
        self.write_hex(value as u32);
        Ok(())
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }
}

fn format_hex(value: u32) -> String {
    let mut s = format!("{value:08x}");
    if s.len() < 8 {
        let mut padded = String::with_capacity(8);
        for _ in 0..(8 - s.len()) {
            padded.push('0');
        }
        padded.push_str(&s);
        s = padded;
    }
    s
}
