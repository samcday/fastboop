//! Command-line contract for a supplied initramfs containing smoo's dracut module.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::join_cmdline;

/// Inputs controlled by the host, alongside the image's own command line.
pub struct InitrdCmdline<'a> {
    pub device: Option<&'a str>,
    pub profile: Option<&'a str>,
    pub requested: Option<&'a str>,
    pub export_id: u32,
    pub mimic_fastboot: bool,
}

/// Build additions for the Android boot-image builder (which adds the device
/// command line separately). Reject conflicting root/transport arguments before
/// RAM boot, rather than relying on the guest's duplicate-argument precedence.
pub fn build_initrd_extra_cmdline(parts: InitrdCmdline<'_>) -> Result<String, String> {
    let extra = join_cmdline(parts.profile, parts.requested);
    let complete = join_cmdline(parts.device, Some(&extra));
    let required = [
        ("root", "/dev/smoo-root".to_string()),
        ("rd.smoo", "1".to_string()),
        ("rd.smoo.root", parts.export_id.to_string()),
        ("rd.smoo.cow", "1".to_string()),
        ("rd.smoo.force_root", "1".to_string()),
        (
            "rd.smoo.mimic_fastboot",
            u8::from(parts.mimic_fastboot).to_string(),
        ),
    ];
    let mut additions = Vec::new();
    for (key, value) in required {
        let mut matches = complete
            .split_ascii_whitespace()
            .filter(|arg| arg.split_once('=').map_or(*arg, |(key, _)| key) == key);
        match matches.next() {
            None => additions.push(format!("{key}={value}")),
            Some(arg) if arg == format!("{key}={value}") && matches.next().is_none() => {}
            Some(_) => {
                return Err(format!(
                    "boot: initrd requires a single {key}={value}; remove conflicting command-line arguments"
                ));
            }
        }
    }
    Ok(join_cmdline(Some(&extra), Some(&additions.join(" "))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_image_arguments_and_selects_the_host_export() {
        let cmdline = build_initrd_extra_cmdline(InitrdCmdline {
            device: Some("console=ttyMSM0"),
            profile: Some("root=/dev/smoo-root rd.smoo.cow.size=2G ostree=true"),
            requested: Some("pocketfed.liveboot=trial"),
            export_id: 42,
            mimic_fastboot: false,
        })
        .unwrap();
        assert!(!cmdline.contains("console=")); // outer builder adds this once
        assert_eq!(cmdline.matches("root=/dev/smoo-root").count(), 1);
        assert!(cmdline.contains("rd.smoo.root=42"));
        assert!(cmdline.contains("rd.smoo.mimic_fastboot=0"));
        assert!(cmdline.contains("rd.smoo.cow.size=2G ostree=true pocketfed.liveboot=trial"));
    }

    #[test]
    fn rejects_installed_root_wrong_export_and_disabled_cow() {
        for requested in [
            "root=LABEL=pfroot",
            "rd.smoo.root=7",
            "rd.smoo.cow=0",
            "rd.smoo=0",
            "rd.smoo.force_root=0",
            "rd.smoo.mimic_fastboot=0",
            "rd.smoo.root=42 rd.smoo.root=42",
        ] {
            assert!(
                build_initrd_extra_cmdline(InitrdCmdline {
                    device: None,
                    profile: None,
                    requested: Some(requested),
                    export_id: 42,
                    mimic_fastboot: true,
                })
                .is_err(),
                "{requested}"
            );
        }
    }
}
