use super::{cmdline_value, mount_fs, path_to_string};
use anyhow::{Context, Result, anyhow, ensure};
use std::{
    ffi::OsStr,
    io,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug)]
pub(super) struct OstreeLayout {
    pub(super) deployment_rel: PathBuf,
    pub(super) stateroot_var_rel: PathBuf,
    pub(super) bind_boot: bool,
}

pub(super) fn detect_ostree_layout(newroot: &Path) -> Result<Option<OstreeLayout>> {
    let Some(ostree_target) = cmdline_value("ostree") else {
        return Ok(None);
    };

    let target_rel = normalize_stage0_path(&ostree_target)?;
    let target_path = newroot.join(&target_rel);
    let target_meta = std::fs::symlink_metadata(&target_path)
        .with_context(|| format!("lstat {}", target_path.display()))?;
    ensure!(
        target_meta.file_type().is_symlink(),
        "ostree target is not a symbolic link: {}",
        target_path.display()
    );

    let resolved = std::fs::canonicalize(&target_path)
        .with_context(|| format!("resolve ostree target {}", target_path.display()))?;
    ensure!(
        resolved.starts_with(newroot),
        "ostree deployment path escapes mounted root: {}",
        resolved.display()
    );
    let deployment_rel = resolved
        .strip_prefix(newroot)
        .map(Path::to_path_buf)
        .map_err(|_| {
            anyhow!(
                "failed to derive deployment-relative path from {}",
                resolved.display()
            )
        })?;

    let deployment_meta =
        std::fs::metadata(&resolved).with_context(|| format!("stat {}", resolved.display()))?;
    ensure!(
        deployment_meta.is_dir(),
        "ostree deployment is not a directory: {}",
        resolved.display()
    );

    let stateroot_var_rel = stateroot_var_rel_from_deployment(&deployment_rel)?;
    let stateroot_var = newroot.join(&stateroot_var_rel);
    let stateroot_var_meta = std::fs::metadata(&stateroot_var)
        .with_context(|| format!("stat {}", stateroot_var.display()))?;
    ensure!(
        stateroot_var_meta.is_dir(),
        "ostree stateroot /var is not a directory: {}",
        stateroot_var.display()
    );

    let bind_boot = should_bind_ostree_boot(newroot, &deployment_rel);

    Ok(Some(OstreeLayout {
        deployment_rel,
        stateroot_var_rel,
        bind_boot,
    }))
}

fn normalize_stage0_path(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    ensure!(!trimmed.is_empty(), "stage0 ostree setting is empty");

    let mut normalized = PathBuf::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                return Err(anyhow!(
                    "stage0 ostree setting must not contain '..': {trimmed}"
                ));
            }
            Component::Prefix(_) => {
                return Err(anyhow!(
                    "stage0 ostree setting has unsupported path prefix: {trimmed}"
                ));
            }
        }
    }

    ensure!(
        !normalized.as_os_str().is_empty(),
        "stage0 ostree setting resolved to an empty path"
    );
    Ok(normalized)
}

fn stateroot_var_rel_from_deployment(deployment_rel: &Path) -> Result<PathBuf> {
    let mut components = deployment_rel.components();

    let Some(Component::Normal(ostree_dir)) = components.next() else {
        return Err(anyhow!(
            "ostree deployment path has invalid layout: {}",
            deployment_rel.display()
        ));
    };
    ensure!(
        ostree_dir == OsStr::new("ostree"),
        "ostree deployment path must start with ostree/: {}",
        deployment_rel.display()
    );

    let Some(Component::Normal(deploy_dir)) = components.next() else {
        return Err(anyhow!(
            "ostree deployment path has invalid layout: {}",
            deployment_rel.display()
        ));
    };
    ensure!(
        deploy_dir == OsStr::new("deploy"),
        "ostree deployment path must include deploy/: {}",
        deployment_rel.display()
    );

    let Some(Component::Normal(stateroot)) = components.next() else {
        return Err(anyhow!(
            "ostree deployment path missing stateroot: {}",
            deployment_rel.display()
        ));
    };

    let Some(Component::Normal(deploy_leaf)) = components.next() else {
        return Err(anyhow!(
            "ostree deployment path missing deploy leaf: {}",
            deployment_rel.display()
        ));
    };
    ensure!(
        deploy_leaf == OsStr::new("deploy"),
        "ostree deployment path missing deploy/ segment: {}",
        deployment_rel.display()
    );

    let Some(Component::Normal(_deployment_entry)) = components.next() else {
        return Err(anyhow!(
            "ostree deployment path missing deployment entry: {}",
            deployment_rel.display()
        ));
    };
    ensure!(
        components.next().is_none(),
        "ostree deployment path has unexpected trailing segments: {}",
        deployment_rel.display()
    );

    let mut stateroot_var = PathBuf::from("ostree");
    stateroot_var.push("deploy");
    stateroot_var.push(stateroot);
    stateroot_var.push("var");
    Ok(stateroot_var)
}

fn should_bind_ostree_boot(newroot: &Path, deployment_rel: &Path) -> bool {
    let boot_loader = newroot.join("boot/loader");
    let deployment_boot = newroot.join(deployment_rel).join("boot");
    let loader_is_symlink = std::fs::symlink_metadata(&boot_loader)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false);
    let deployment_has_boot_dir = std::fs::metadata(&deployment_boot)
        .map(|meta| meta.is_dir())
        .unwrap_or(false);
    loader_is_symlink && deployment_has_boot_dir
}

pub(super) fn setup_ostree_runtime_mounts(layout: &OstreeLayout) -> Result<()> {
    let deployment_root = Path::new("/").join(&layout.deployment_rel);
    let deployment_sysroot = deployment_root.join("sysroot");
    let deployment_var = deployment_root.join("var");
    let stateroot_var = Path::new("/").join(&layout.stateroot_var_rel);

    let deployment_root_meta = std::fs::metadata(&deployment_root)
        .with_context(|| format!("stat {}", deployment_root.display()))?;
    ensure!(
        deployment_root_meta.is_dir(),
        "ostree deployment root is not a directory: {}",
        deployment_root.display()
    );

    match std::fs::metadata(&deployment_sysroot) {
        Ok(meta) => {
            ensure!(
                meta.is_dir(),
                "ostree deployment /sysroot is not a directory: {}",
                deployment_sysroot.display()
            );
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&deployment_sysroot)
                .with_context(|| format!("create {}", deployment_sysroot.display()))?;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("stat {}", deployment_sysroot.display()));
        }
    }

    let stateroot_var_meta = std::fs::metadata(&stateroot_var)
        .with_context(|| format!("stat {}", stateroot_var.display()))?;
    ensure!(
        stateroot_var_meta.is_dir(),
        "ostree stateroot /var not found: {}",
        stateroot_var.display()
    );

    let deployment_var_meta = std::fs::metadata(&deployment_var)
        .with_context(|| format!("stat {}", deployment_var.display()))?;
    ensure!(
        deployment_var_meta.is_dir(),
        "ostree deployment /var is not a directory: {}",
        deployment_var.display()
    );

    let deployment_sysroot_str = path_to_string(&deployment_sysroot)?;
    mount_fs(
        Some("/"),
        &deployment_sysroot_str,
        None,
        libc::MS_BIND as libc::c_ulong,
        None,
    )
    .context("bind mount physical root into deployment /sysroot")?;

    let stateroot_var_str = path_to_string(&stateroot_var)?;
    let deployment_var_str = path_to_string(&deployment_var)?;
    mount_fs(
        Some(&stateroot_var_str),
        &deployment_var_str,
        None,
        libc::MS_BIND as libc::c_ulong,
        None,
    )
    .context("bind mount stateroot /var into deployment /var")?;

    if layout.bind_boot {
        let deployment_boot = deployment_root.join("boot");
        let deployment_boot_meta = std::fs::metadata(&deployment_boot)
            .with_context(|| format!("stat {}", deployment_boot.display()))?;
        ensure!(
            deployment_boot_meta.is_dir(),
            "ostree deployment /boot is not a directory: {}",
            deployment_boot.display()
        );
        let deployment_boot_str = path_to_string(&deployment_boot)?;
        mount_fs(
            Some("/boot"),
            &deployment_boot_str,
            None,
            libc::MS_BIND as libc::c_ulong,
            None,
        )
        .context("bind mount /boot into deployment /boot")?;
    }

    mount_fs(
        Some("none"),
        &deployment_sysroot_str,
        None,
        libc::MS_PRIVATE as libc::c_ulong,
        None,
    )
    .context("make deployment /sysroot mount private")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_stage0_path_strips_root_prefix() {
        let path = normalize_stage0_path(" /ostree/boot.1/example ").unwrap();
        assert_eq!(path, PathBuf::from("ostree/boot.1/example"));
    }

    #[test]
    fn normalize_stage0_path_rejects_parent_components() {
        let err = normalize_stage0_path("/ostree/../etc").unwrap_err();
        assert!(
            err.to_string().contains("must not contain '..'"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn stateroot_var_rel_from_deployment_path_parses_expected_layout() {
        let rel = stateroot_var_rel_from_deployment(Path::new(
            "ostree/deploy/fedora/deploy/0123456789abcdef.0",
        ))
        .unwrap();
        assert_eq!(rel, PathBuf::from("ostree/deploy/fedora/var"));
    }

    #[test]
    fn stateroot_var_rel_from_deployment_path_rejects_unexpected_layout() {
        let err = stateroot_var_rel_from_deployment(Path::new("ostree/deploy/fedora/current"))
            .unwrap_err();
        assert!(
            err.to_string().contains("missing deploy"),
            "unexpected error: {err:#}"
        );
    }
}
