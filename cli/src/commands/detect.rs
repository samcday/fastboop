use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Args;
use fastboop_core::DeviceProfile;
use fastboop_environment_std::{NativeDetectConfig, detect_native_fastboot};

#[derive(Args)]
pub struct DetectArgs {
    /// Restrict probing to this device profile id.
    #[arg(long)]
    pub device_profile: Option<String>,

    /// Channel artifact (path or HTTP(S) URL) whose DevPros define the matching pool.
    #[arg(long, value_name = "CHANNEL")]
    pub channel: Option<PathBuf>,

    /// Wait up to N seconds for a matching device (0 = infinite). Disabled by default.
    #[arg(long)]
    pub wait: Option<u64>,
}

pub async fn run_detect(args: DetectArgs) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    drop(rx);

    let detected = detect_native_fastboot(
        NativeDetectConfig {
            device_profile: args.device_profile,
            channel: args.channel,
            wait: args.wait.map(Duration::from_secs),
        },
        tx,
    )
    .await;

    for device in detected? {
        print_detected(&device.profile, device.vid, device.pid);
    }
    Ok(())
}

fn print_detected(profile: &DeviceProfile, vid: u16, pid: u16) {
    let name = profile.display_name.as_deref().unwrap_or("unknown");
    println!(
        "{:04x}:{:04x} profile={} name=\"{}\"",
        vid, pid, profile.id, name
    );
}
