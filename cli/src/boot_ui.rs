use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BootPhase {
    #[default]
    Preparing,
    WaitingForDevice,
    DeviceDetected,
    BuildingStage0,
    BuildingBootImage,
    Downloading,
    Booting,
    WaitingForSmoo,
    Serving,
    Finished,
    Failed,
}

impl BootPhase {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::WaitingForDevice => "waiting-for-device",
            Self::DeviceDetected => "device-detected",
            Self::BuildingStage0 => "building-stage0",
            Self::BuildingBootImage => "building-bootimg",
            Self::Downloading => "fastboot-download",
            Self::Booting => "fastboot-boot",
            Self::WaitingForSmoo => "waiting-for-smoo",
            Self::Serving => "serving",
            Self::Finished => "finished",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug)]
pub enum BootEvent {
    Phase {
        phase: BootPhase,
        detail: String,
    },
    Log(String),
    SmooStatus {
        active: bool,
        export_count: u32,
        session_id: u64,
    },
    #[allow(dead_code)]
    GibbloxStats {
        hit_rate_pct: u64,
        fill_rate_pct: u64,
        cached_blocks: u64,
        total_blocks: u64,
    },
    Finished,
    Failed(String),
}

pub fn timestamp_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day = secs % 86_400;
    let h = day / 3_600;
    let m = (day % 3_600) / 60;
    let s = day % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
