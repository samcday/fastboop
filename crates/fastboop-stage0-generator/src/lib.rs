#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod kernel;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use dtoolkit::fdt::Fdt;
use dtoolkit::model::{DeviceTree, DeviceTreeNode, DeviceTreeProperty};
use dtoolkit::{Node, Property};
use fastboop_core::{DeviceProfile, InjectMac, Personalization, RootfsProvider};

const MODULES_LOAD_PATH: &str = "etc/modules-load.d/fastboop-stage0.conf";
const MODULES_ROOT: &str = "lib/modules";
const INIT_BIN_PATH: &str = "init";
const BASE_REQUIRED_MODULES: &[&str] = &[
    "configfs",
    "libcomposite",
    "usb_f_fs",
    "ublk_drv",
    "overlay",
];
const MODULE_INDEX_FILES: &[&str] = &["modules.dep", "modules.builtin", "modules.order"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage0Error {
    MissingFile(String),
    EmptyPath,
    Oversized(u64),
    ParseError(&'static str),
    Overlay(String),
    InvalidCpio(&'static str),
    KernelFormat(&'static str),
    KernelDecode(&'static str),
}

#[derive(Default)]
pub struct Stage0Options {
    pub extra_modules: Vec<String>,
    pub dtb_override: Option<Vec<u8>>,
    pub dtbo_overlays: Vec<Vec<u8>>,
    pub enable_serial: bool,
    pub smoo_vendor: Option<u16>,
    pub smoo_product: Option<u16>,
    pub smoo_serial: Option<String>,
    pub personalization: Option<Personalization>,
}

/// Resulting artifacts and recommended kernel cmdline additions.
pub struct Stage0Build {
    pub kernel_image: Vec<u8>,
    pub kernel_path: String,
    pub init_path: String,
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

/// Build a minimal stage0 initrd containing fastboop stage0 as PID1 plus modules.
pub async fn build_stage0<P: RootfsProvider>(
    profile: &DeviceProfile,
    rootfs: &P,
    opts: &Stage0Options,
    extra_cmdline: Option<&str>,
    existing_cpio: Option<&[u8]>,
) -> Result<Stage0Build, Stage0Error> {
    tracing::debug!("build_stage0: detecting kernel");
    let kernel_path = detect_kernel(rootfs).await?;
    tracing::debug!(kernel_path = %kernel_path, "build_stage0: kernel detected");
    let kernel_image = rootfs
        .read_all(&kernel_path)
        .await
        .map_err(|_| Stage0Error::MissingFile(kernel_path.clone()))?;

    let init_path = INIT_BIN_PATH.to_string();

    let mut modules_dir = None;
    let mut modules_dep = ModulesDep::new();
    let mut module_paths = ModulePaths::new();
    let mut modules_builtin = BTreeSet::new();
    let needs_modules = !opts.extra_modules.is_empty() || !profile.stage0.kernel_modules.is_empty();
    if needs_modules {
        let dir = detect_modules_dir(rootfs).await?;
        let (dep, paths, builtin) = load_modules_metadata(rootfs, &dir).await?;
        modules_dir = Some(dir);
        modules_dep = dep;
        module_paths = paths;
        modules_builtin = builtin;
    }

    let dtb_bytes = if let Some(override_bytes) = &opts.dtb_override {
        override_bytes.clone()
    } else {
        let dtb_path = select_dtb(profile, rootfs).await?;
        rootfs
            .read_all(&dtb_path)
            .await
            .map_err(|_| Stage0Error::MissingFile(dtb_path.clone()))?
    };

    let kernel_image = kernel::normalize_kernel(profile, &kernel_image)?;
    let dtb_bytes = apply_dtbo_overlays(&dtb_bytes, &opts.dtbo_overlays)?;
    let dtb_bytes = apply_mac_injection(&dtb_bytes, &profile.stage0.inject_mac)?;
    let _dtb = Fdt::new(&dtb_bytes).map_err(|_| Stage0Error::ParseError("dtb"))?;

    let required_modules = collect_required_modules(profile, opts, &modules_dep);

    let mut image = if let Some(data) = existing_cpio {
        CpioImage::from_bytes(data)?
    } else {
        CpioImage::new()
    };
    image.ensure_dir("dev")?;
    image.ensure_dir("proc")?;
    image.ensure_dir("sys")?;
    image.ensure_dir("etc")?;
    image.ensure_dir("etc/modules-load.d")?;
    image.ensure_dir("lib")?;
    image.ensure_dir("lib/modules")?;

    if !image.has_path(INIT_BIN_PATH) {
        image.ensure_file(INIT_BIN_PATH, 0o100755, embedded_stage0_binary())?;
    }

    if !required_modules.is_empty() {
        let modules_dir = modules_dir
            .ok_or_else(|| Stage0Error::MissingFile("/lib/modules (modules directory)".into()))?;
        copy_module_indexes(rootfs, &modules_dir, &mut image).await?;

        for module in &required_modules {
            if modules_builtin.contains(module) {
                continue;
            }
            let (rel, path) = module_path_for(module, &module_paths, &modules_dir)?;
            let data = rootfs
                .read_all(&path)
                .await
                .map_err(|_| Stage0Error::MissingFile(path.clone()))?;
            let cpio_path = format!("{MODULES_ROOT}/{rel}");
            image.ensure_file(cpio_path.as_str(), 0o100644, &data)?;
        }
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
        cmdline_parts.push("plymouth.ignore-serial-consoles".to_string());
    }
    if let Some(vendor) = opts.smoo_vendor {
        cmdline_parts.push(format!("smoo.vendor=0x{vendor:04x}"));
    }
    if let Some(product) = opts.smoo_product {
        cmdline_parts.push(format!("smoo.product=0x{product:04x}"));
    }
    if let Some(serial) = opts.smoo_serial.as_ref() {
        let serial = serial.trim();
        if !serial.is_empty() {
            cmdline_parts.push(format!("smoo.serial={serial}"));
        }
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
        init_path,
        initrd: image.finish()?,
        dtb: dtb_bytes,
        kernel_cmdline_append: cmdline,
    })
}

fn embedded_stage0_binary() -> &'static [u8] {
    include_bytes!(env!("FASTBOOP_STAGE0_EMBED_PATH"))
}

async fn detect_kernel<P: RootfsProvider>(rootfs: &P) -> Result<String, Stage0Error> {
    if let Some(found) = find_kernel_in_modules(rootfs, "/lib/modules").await? {
        return Ok(found);
    }
    if let Some(found) = find_kernel_in_modules(rootfs, "/usr/lib/modules").await? {
        return Ok(found);
    }

    const CANDIDATES: &[&str] = &["/boot/vmlinuz", "/boot/Image", "/boot/Image.gz"];
    for cand in CANDIDATES {
        if rootfs.exists(cand).await.unwrap_or(false) {
            return Ok(cand.trim_start_matches('/').to_string());
        }
    }
    if let Some(found) = find_kernel_recursive(rootfs, "/boot", 3).await? {
        return Ok(found);
    }
    Err(Stage0Error::MissingFile("kernel image".into()))
}

async fn find_kernel_in_modules<P: RootfsProvider>(
    rootfs: &P,
    base: &str,
) -> Result<Option<String>, Stage0Error> {
    let mut entries = match rootfs.read_dir(base).await {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };
    entries.sort();
    for entry in entries {
        if entry.contains("rescue") {
            continue;
        }
        let candidate = format!("{base}/{entry}/vmlinuz");
        if rootfs.exists(&candidate).await.unwrap_or(false) {
            return Ok(Some(candidate.trim_start_matches('/').to_string()));
        }
    }
    Ok(None)
}

async fn detect_modules_dir<P: RootfsProvider>(rootfs: &P) -> Result<ModulesDir, Stage0Error> {
    let bases = ["/lib/modules", "/usr/lib/modules"];
    for base in &bases {
        if let Ok(mut entries) = rootfs.read_dir(base).await {
            entries.sort();
            if let Some(first) = entries.first() {
                return Ok(ModulesDir {
                    kver: first.clone(),
                    source_root: format!("{base}/{first}"),
                });
            }
        }
    }
    Err(Stage0Error::MissingFile(
        "/lib/modules or /usr/lib/modules".into(),
    ))
}

async fn find_kernel_recursive<P: RootfsProvider>(
    rootfs: &P,
    start: &str,
    max_depth: usize,
) -> Result<Option<String>, Stage0Error> {
    let mut stack = Vec::new();
    stack.push((start.trim_end_matches('/').to_string(), 0usize));
    while let Some((dir, depth)) = stack.pop() {
        let entries = match rootfs.read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        for name in entries {
            let mut path = dir.clone();
            path.push('/');
            path.push_str(&name);
            let is_dir = rootfs.read_dir(&path).await.is_ok();
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

async fn load_modules_metadata<P: RootfsProvider>(
    rootfs: &P,
    modules_dir: &ModulesDir,
) -> Result<(ModulesDep, ModulePaths, BTreeSet<String>), Stage0Error> {
    let dep_path = format!("{}/modules.dep", modules_dir.source_root);
    let dep_data = rootfs
        .read_all(&dep_path)
        .await
        .map_err(|_| Stage0Error::MissingFile(dep_path.clone()))?;
    let (modules_dep, module_paths) = parse_modules_dep(&dep_data);

    let builtin_path = format!("{}/modules.builtin", modules_dir.source_root);
    let builtin_data = rootfs.read_all(&builtin_path).await.unwrap_or_default();
    let modules_builtin = parse_modules_builtin(&builtin_data);

    Ok((modules_dep, module_paths, modules_builtin))
}

async fn copy_module_indexes<P: RootfsProvider>(
    rootfs: &P,
    modules_dir: &ModulesDir,
    image: &mut CpioImage,
) -> Result<(), Stage0Error> {
    for name in MODULE_INDEX_FILES {
        let source = format!("{}/{}", modules_dir.source_root, name);
        if !rootfs.exists(&source).await.unwrap_or(false) {
            continue;
        }
        let data = rootfs
            .read_all(&source)
            .await
            .map_err(|_| Stage0Error::MissingFile(source.clone()))?;
        let rel = format!("{}/{}", modules_dir.kver, name);
        let cpio_path = format!("{MODULES_ROOT}/{rel}");
        image.ensure_file(cpio_path.as_str(), 0o100644, &data)?;
    }
    Ok(())
}

async fn select_dtb<P: RootfsProvider>(
    profile: &DeviceProfile,
    rootfs: &P,
) -> Result<String, Stage0Error> {
    let name = profile.devicetree_name.trim_start_matches('/');
    let mut candidates = Vec::new();
    candidates.extend_from_slice(&[
        format!("/boot/dtb/{name}.dtb"),
        format!("/boot/{name}.dtb"),
        format!("/lib/firmware/{name}.dtb"),
        format!("/usr/lib/firmware/{name}.dtb"),
    ]);
    if let Ok(mods) = rootfs.read_dir("/usr/lib/modules").await {
        for m in mods {
            let base = format!("/usr/lib/modules/{m}/dtb");
            candidates.push(format!("{base}/{name}.dtb"));
            candidates.push(format!("{base}/{name}"));
            if let Ok(entries) = rootfs.read_dir(&base).await {
                for e in entries {
                    if e.ends_with(".dtb") && e.contains(name) {
                        candidates.push(format!("{base}/{e}"));
                    }
                }
            }
        }
    }
    for cand in candidates {
        if rootfs.exists(&cand).await.unwrap_or(false) {
            return Ok(cand.trim_start_matches('/').to_string());
        }
    }
    Err(Stage0Error::MissingFile(format!(
        "dtb for {}",
        profile.devicetree_name
    )))
}

fn apply_dtbo_overlays(base: &[u8], overlays: &[Vec<u8>]) -> Result<Vec<u8>, Stage0Error> {
    if overlays.is_empty() {
        return Ok(base.to_vec());
    }
    let base_fdt = Fdt::new(base).map_err(|_| Stage0Error::ParseError("dtb"))?;
    let mut tree = DeviceTree::from_fdt(&base_fdt).map_err(|_| Stage0Error::ParseError("dtb"))?;
    for overlay in overlays {
        let overlay_fdt = Fdt::new(overlay).map_err(|_| Stage0Error::ParseError("dtbo"))?;
        let mut overlay_tree =
            DeviceTree::from_fdt(&overlay_fdt).map_err(|_| Stage0Error::ParseError("dtbo"))?;
        normalize_overlay_phandles(&tree, &mut overlay_tree)?;
        apply_overlay_tree(&mut tree, &overlay_tree)?;
    }
    Ok(tree.to_dtb())
}

fn apply_overlay_tree(base: &mut DeviceTree, overlay: &DeviceTree) -> Result<(), Stage0Error> {
    for fragment in (&overlay.root).children() {
        let name = fragment.name();
        if !name.starts_with("fragment") {
            continue;
        }
        let target_path = match fragment.property("target-path") {
            Some(prop) => prop
                .as_str()
                .map_err(|_| Stage0Error::Overlay("invalid target-path".into()))?,
            None => {
                return Err(Stage0Error::Overlay(
                    "overlay fragment missing target-path".into(),
                ));
            }
        };
        if fragment.property("target").is_some() {
            return Err(Stage0Error::Overlay(
                "dtbo target phandles not supported".into(),
            ));
        }
        if !target_path.starts_with('/') {
            return Err(Stage0Error::Overlay(
                "overlay target-path must be absolute".into(),
            ));
        }
        let overlay_node = fragment
            .child("__overlay__")
            .ok_or_else(|| Stage0Error::Overlay("overlay fragment missing __overlay__".into()))?;
        let target_node = base.find_node_mut(target_path).ok_or_else(|| {
            Stage0Error::Overlay(format!("overlay target not found: {target_path}"))
        })?;
        merge_overlay_node(target_node, overlay_node);
    }
    Ok(())
}

fn merge_overlay_node(target: &mut DeviceTreeNode, overlay: &DeviceTreeNode) {
    for prop in overlay.properties() {
        if let Some(existing) = target.property_mut(prop.name()) {
            existing.set_value(prop.value());
        } else {
            target.add_property(DeviceTreeProperty::new(prop.name(), prop.value()));
        }
    }
    for child in overlay.children() {
        if let Some(target_child) = target.child_mut(child.name()) {
            merge_overlay_node(target_child, child);
        } else {
            target.add_child(child.clone());
        }
    }
}

fn normalize_overlay_phandles(
    base: &DeviceTree,
    overlay: &mut DeviceTree,
) -> Result<(), Stage0Error> {
    let used = collect_used_phandles(&base.root);
    let mut overlay_phandles = BTreeMap::new();
    let mut overlay_nodes = Vec::new();
    collect_overlay_phandles(
        &overlay.root,
        "/",
        &mut overlay_phandles,
        &mut overlay_nodes,
    )?;

    if overlay_phandles.is_empty() {
        return Ok(());
    }

    let fixups = find_node(&overlay.root, "/__local_fixups__").cloned();
    let mut next_phandle = used.iter().copied().max().unwrap_or(0).saturating_add(1);
    let mut mapping = BTreeMap::new();
    let mut used_all = used;

    for &old in overlay_phandles.keys() {
        let needs_remap = used_all.contains(&old) || mapping.contains_key(&old);
        if needs_remap {
            if fixups.is_none() {
                return Err(Stage0Error::Overlay(
                    "overlay phandle collision without __local_fixups__".into(),
                ));
            }
            while used_all.contains(&next_phandle) {
                next_phandle = next_phandle.saturating_add(1);
            }
            mapping.insert(old, next_phandle);
            used_all.insert(next_phandle);
            next_phandle = next_phandle.saturating_add(1);
        }
    }

    if !mapping.is_empty() {
        for (path, prop_names, old) in overlay_nodes {
            if let Some(new) = mapping.get(&old) {
                let node = overlay.find_node_mut(&path).ok_or_else(|| {
                    Stage0Error::Overlay(format!("phandle node not found: {path}"))
                })?;
                for prop_name in prop_names {
                    let prop = node.property_mut(&prop_name).ok_or_else(|| {
                        Stage0Error::Overlay(format!(
                            "phandle property not found: {path}:{prop_name}"
                        ))
                    })?;
                    prop.set_value(new.to_be_bytes());
                }
            }
        }

        if let Some(fixups_node) = fixups.as_ref() {
            apply_local_fixups(fixups_node, overlay, &mapping, "/")?;
        } else {
            return Err(Stage0Error::Overlay(
                "missing __local_fixups__ for phandle remap".into(),
            ));
        }
    }

    Ok(())
}

fn collect_used_phandles(node: &DeviceTreeNode) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    collect_used_phandles_recursive(node, &mut out);
    out
}

fn collect_used_phandles_recursive(node: &DeviceTreeNode, out: &mut BTreeSet<u32>) {
    if let Some(phandle) = node_phandle(node) {
        out.insert(phandle);
    }
    for child in node.children() {
        collect_used_phandles_recursive(child, out);
    }
}

fn collect_overlay_phandles(
    node: &DeviceTreeNode,
    path: &str,
    seen: &mut BTreeMap<u32, String>,
    nodes: &mut Vec<(String, Vec<String>, u32)>,
) -> Result<(), Stage0Error> {
    let mut props = Vec::new();
    let mut phandle_val = None;
    if let Some(prop) = node.property("phandle") {
        phandle_val = Some(
            prop.as_u32()
                .map_err(|_| Stage0Error::Overlay("invalid phandle value".into()))?,
        );
        props.push("phandle".to_string());
    }
    if let Some(prop) = node.property("linux,phandle") {
        let val = prop
            .as_u32()
            .map_err(|_| Stage0Error::Overlay("invalid linux,phandle value".into()))?;
        if let Some(existing) = phandle_val {
            if existing != val {
                return Err(Stage0Error::Overlay(
                    "phandle/linux,phandle mismatch".into(),
                ));
            }
        } else {
            phandle_val = Some(val);
        }
        props.push("linux,phandle".to_string());
    }
    if let Some(val) = phandle_val {
        if let Some(existing) = seen.get(&val) {
            return Err(Stage0Error::Overlay(format!(
                "duplicate overlay phandle {val} at {path} (seen at {existing})"
            )));
        }
        seen.insert(val, path.to_string());
        nodes.push((path.to_string(), props, val));
    }
    for child in node.children() {
        let child_path = if path == "/" {
            format!("/{0}", child.name())
        } else {
            format!("{path}/{0}", child.name())
        };
        collect_overlay_phandles(child, &child_path, seen, nodes)?;
    }
    Ok(())
}

fn apply_local_fixups(
    fixups_node: &DeviceTreeNode,
    overlay: &mut DeviceTree,
    mapping: &BTreeMap<u32, u32>,
    path: &str,
) -> Result<(), Stage0Error> {
    for prop in fixups_node.properties() {
        let target = overlay
            .find_node_mut(path)
            .ok_or_else(|| Stage0Error::Overlay(format!("fixup target not found: {path}")))?;
        let target_prop = target.property_mut(prop.name()).ok_or_else(|| {
            Stage0Error::Overlay(format!(
                "fixup property not found: {path}:{prop_name}",
                prop_name = prop.name()
            ))
        })?;
        let mut value = (&*target_prop).value().to_vec();
        for offset in parse_fixup_offsets(prop.value())? {
            let offset = usize::try_from(offset)
                .map_err(|_| Stage0Error::Overlay("fixup offset overflow".into()))?;
            let end = offset
                .checked_add(4)
                .ok_or_else(|| Stage0Error::Overlay("fixup offset overflow".into()))?;
            if end > value.len() {
                return Err(Stage0Error::Overlay("fixup offset out of bounds".into()));
            }
            let old = u32::from_be_bytes(value[offset..end].try_into().unwrap());
            if let Some(new) = mapping.get(&old) {
                value[offset..end].copy_from_slice(&new.to_be_bytes());
            }
        }
        target_prop.set_value(value);
    }

    for child in fixups_node.children() {
        let child_path = if path == "/" {
            format!("/{0}", child.name())
        } else {
            format!("{path}/{0}", child.name())
        };
        apply_local_fixups(child, overlay, mapping, &child_path)?;
    }
    Ok(())
}

fn parse_fixup_offsets(bytes: &[u8]) -> Result<Vec<u32>, Stage0Error> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Stage0Error::Overlay("invalid fixup offsets".into()));
    }
    let mut out = Vec::new();
    for chunk in bytes.chunks_exact(4) {
        let val = u32::from_be_bytes(chunk.try_into().unwrap());
        out.push(val);
    }
    Ok(out)
}

fn apply_mac_injection(dtb: &[u8], inject: &Option<InjectMac>) -> Result<Vec<u8>, Stage0Error> {
    let Some(inject) = inject else {
        return Ok(dtb.to_vec());
    };
    if inject.wifi.is_none() && inject.bluetooth.is_none() {
        return Ok(dtb.to_vec());
    }

    let fdt = Fdt::new(dtb).map_err(|_| Stage0Error::ParseError("dtb"))?;
    let mut tree = DeviceTree::from_fdt(&fdt).map_err(|_| Stage0Error::ParseError("dtb"))?;
    let seed = 0u64;

    if let Some(compat) = inject.wifi.as_deref() {
        let mac = mac_from_seed(seed, "wifi", compat);
        let node = find_node_by_compatible_mut(&mut tree.root, compat).ok_or_else(|| {
            Stage0Error::Overlay(format!("inject_mac wifi compatible not found: {compat}"))
        })?;
        node.add_property(DeviceTreeProperty::new("local-mac-address", mac.to_vec()));
    }

    if let Some(compat) = inject.bluetooth.as_deref() {
        let mac = mac_from_seed(seed, "bluetooth", compat);
        let mut lsb = mac;
        lsb.reverse();
        let node = find_node_by_compatible_mut(&mut tree.root, compat).ok_or_else(|| {
            Stage0Error::Overlay(format!(
                "inject_mac bluetooth compatible not found: {compat}"
            ))
        })?;
        node.add_property(DeviceTreeProperty::new("local-bd-address", lsb.to_vec()));
    }

    Ok(tree.to_dtb())
}

fn mac_from_seed(seed: u64, kind: &str, compat: &str) -> [u8; 6] {
    let mut hash = fnv1a64(seed.to_le_bytes().iter().copied());
    hash = fnv1a64_with_seed(hash, kind.as_bytes().iter().copied());
    hash = fnv1a64_with_seed(hash, compat.as_bytes().iter().copied());
    let mut mac = [0u8; 6];
    for (idx, b) in mac.iter_mut().enumerate() {
        *b = (hash >> (idx * 8)) as u8;
    }
    mac[0] &= 0xfe;
    mac[0] |= 0x02;
    mac
}

fn fnv1a64<I: IntoIterator<Item = u8>>(bytes: I) -> u64 {
    fnv1a64_with_seed(0xcbf29ce484222325, bytes)
}

fn fnv1a64_with_seed<I: IntoIterator<Item = u8>>(seed: u64, bytes: I) -> u64 {
    let mut hash = seed;
    for b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn find_node_by_compatible_mut<'a>(
    node: &'a mut DeviceTreeNode,
    compat: &str,
) -> Option<&'a mut DeviceTreeNode> {
    if node_has_compatible(node, compat) {
        return Some(node);
    }
    for child in node.children_mut() {
        if let Some(found) = find_node_by_compatible_mut(child, compat) {
            return Some(found);
        }
    }
    None
}

fn node_has_compatible(node: &DeviceTreeNode, compat: &str) -> bool {
    let Some(prop) = node.property("compatible") else {
        return false;
    };
    prop.as_str_list().any(|entry| entry == compat)
}

fn node_phandle(node: &DeviceTreeNode) -> Option<u32> {
    if let Some(prop) = node.property("phandle") {
        prop.as_u32().ok()
    } else if let Some(prop) = node.property("linux,phandle") {
        prop.as_u32().ok()
    } else {
        None
    }
}

fn find_node<'a>(root: &'a DeviceTreeNode, path: &str) -> Option<&'a DeviceTreeNode> {
    if !path.starts_with('/') {
        return None;
    }
    if path == "/" {
        return Some(root);
    }
    let mut current = root;
    for component in path.split('/').filter(|s| !s.is_empty()) {
        current = current.child(component)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtoolkit::fdt::Fdt;
    use dtoolkit::model::{DeviceTree, DeviceTreeNode};
    use dtoolkit::{Node, Property};

    #[test]
    fn mac_from_seed_sets_local_admin() {
        let mac = mac_from_seed(0, "wifi", "qcom,wcn3990-wifi");
        assert_eq!(mac[0] & 0x01, 0);
        assert_eq!(mac[0] & 0x02, 0x02);
    }

    #[test]
    fn inject_mac_updates_dtb() {
        let mut tree = DeviceTree::new();
        let bt_path = "/soc@0/geniqup@8c0000/serial@898000/bluetooth";
        let wifi_path = "/soc@0/wifi@18800000";
        ensure_path(&mut tree.root, bt_path);
        ensure_path(&mut tree.root, wifi_path);
        add_compatible(&mut tree, bt_path, "qcom,wcn3990-bt");
        add_compatible(&mut tree, wifi_path, "qcom,wcn3990-wifi");

        let dtb = tree.to_dtb();
        let inject = InjectMac {
            wifi: Some("qcom,wcn3990-wifi".to_string()),
            bluetooth: Some("qcom,wcn3990-bt".to_string()),
        };
        let out = apply_mac_injection(&dtb, &Some(inject)).unwrap();
        let fdt = Fdt::new(&out).unwrap();

        let wifi_node = fdt.find_node(wifi_path).unwrap();
        let wifi_prop = wifi_node.property("local-mac-address").unwrap();
        let expected_wifi = mac_from_seed(0, "wifi", "qcom,wcn3990-wifi");
        assert_eq!(wifi_prop.value(), expected_wifi);

        let bt_node = fdt.find_node(bt_path).unwrap();
        let bt_prop = bt_node.property("local-bd-address").unwrap();
        let mut expected_bt = mac_from_seed(0, "bluetooth", "qcom,wcn3990-bt");
        expected_bt.reverse();
        assert_eq!(bt_prop.value(), expected_bt);
    }

    fn add_compatible(tree: &mut DeviceTree, path: &str, compat: &str) {
        let node = tree
            .find_node_mut(path)
            .expect("node should exist for compat");
        let mut value = Vec::new();
        value.extend_from_slice(compat.as_bytes());
        value.push(0);
        node.add_property(DeviceTreeProperty::new("compatible", value));
    }

    fn ensure_path(root: &mut DeviceTreeNode, path: &str) {
        let mut current = root;
        for part in path.trim_start_matches('/').split('/') {
            let has_child = current.child_mut(part).is_some();
            if !has_child {
                current.add_child(DeviceTreeNode::new(part));
            }
            current = current.child_mut(part).expect("child should exist");
        }
    }
}

fn collect_required_modules(
    profile: &DeviceProfile,
    opts: &Stage0Options,
    modules_dep: &ModulesDep,
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

type ModulesDep = BTreeMap<String, Vec<String>>;
type ModulePaths = BTreeMap<String, String>;

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

fn trim_leading_slash(path: &str) -> Result<&str, Stage0Error> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(Stage0Error::EmptyPath);
    }
    Ok(trimmed)
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
