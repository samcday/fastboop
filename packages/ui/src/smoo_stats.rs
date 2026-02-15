use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use dioxus::prelude::*;

use alloc::sync::Arc;

const SMOO_STATS_CSS: Asset = asset!("/assets/styling/smoo_stats.css");

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SmooStatsSnapshot {
    pub connected: bool,
    pub total_ios: u64,
    pub total_bytes_up: u64,
    pub total_bytes_down: u64,
}

#[derive(Clone, Debug)]
pub struct SmooStatsHandle {
    connected: Arc<AtomicBool>,
    total_ios: Arc<AtomicU64>,
    total_bytes_up: Arc<AtomicU64>,
    total_bytes_down: Arc<AtomicU64>,
}

impl SmooStatsHandle {
    pub fn new() -> Self {
        Self {
            connected: Arc::new(AtomicBool::new(false)),
            total_ios: Arc::new(AtomicU64::new(0)),
            total_bytes_up: Arc::new(AtomicU64::new(0)),
            total_bytes_down: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::Relaxed);
    }

    pub fn add_deltas(&self, ios_delta: u64, bytes_up_delta: u64, bytes_down_delta: u64) {
        if ios_delta > 0 {
            self.total_ios.fetch_add(ios_delta, Ordering::Relaxed);
        }
        if bytes_up_delta > 0 {
            self.total_bytes_up
                .fetch_add(bytes_up_delta, Ordering::Relaxed);
        }
        if bytes_down_delta > 0 {
            self.total_bytes_down
                .fetch_add(bytes_down_delta, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> SmooStatsSnapshot {
        SmooStatsSnapshot {
            connected: self.connected.load(Ordering::Relaxed),
            total_ios: self.total_ios.load(Ordering::Relaxed),
            total_bytes_up: self.total_bytes_up.load(Ordering::Relaxed),
            total_bytes_down: self.total_bytes_down.load(Ordering::Relaxed),
        }
    }
}

impl Default for SmooStatsHandle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SmooStatsViewModel {
    pub connected: bool,
    pub total_ios: u64,
    pub total_bytes_up: u64,
    pub total_bytes_down: u64,
    pub ewma_iops: f64,
    pub ewma_up_bps: f64,
    pub ewma_down_bps: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SmooStatsAccumulator {
    previous: SmooStatsSnapshot,
    ewma_iops: f64,
    ewma_up_bps: f64,
    ewma_down_bps: f64,
}

impl SmooStatsAccumulator {
    pub fn new(initial: SmooStatsSnapshot) -> Self {
        Self {
            previous: initial,
            ewma_iops: 0.0,
            ewma_up_bps: 0.0,
            ewma_down_bps: 0.0,
        }
    }

    pub fn update(&mut self, snapshot: SmooStatsSnapshot, dt_seconds: f64) -> SmooStatsViewModel {
        let dt = dt_seconds.max(0.001);
        let io_delta = snapshot.total_ios.saturating_sub(self.previous.total_ios) as f64;
        let up_delta = snapshot
            .total_bytes_up
            .saturating_sub(self.previous.total_bytes_up) as f64;
        let down_delta = snapshot
            .total_bytes_down
            .saturating_sub(self.previous.total_bytes_down) as f64;

        let inst_iops = io_delta / dt;
        let inst_up_bps = up_delta / dt;
        let inst_down_bps = down_delta / dt;
        let alpha = 1.0 - (-dt / 5.0).exp();

        self.ewma_iops += alpha * (inst_iops - self.ewma_iops);
        self.ewma_up_bps += alpha * (inst_up_bps - self.ewma_up_bps);
        self.ewma_down_bps += alpha * (inst_down_bps - self.ewma_down_bps);
        self.previous = snapshot;

        SmooStatsViewModel {
            connected: snapshot.connected,
            total_ios: snapshot.total_ios,
            total_bytes_up: snapshot.total_bytes_up,
            total_bytes_down: snapshot.total_bytes_down,
            ewma_iops: self.ewma_iops,
            ewma_up_bps: self.ewma_up_bps,
            ewma_down_bps: self.ewma_down_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmooTransportCounters {
    pub ios_up: u64,
    pub ios_down: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

pub fn apply_transport_counters(
    stats: &SmooStatsHandle,
    previous: &mut SmooTransportCounters,
    current: SmooTransportCounters,
) {
    let ios_delta = current
        .ios_up
        .saturating_sub(previous.ios_up)
        .saturating_add(current.ios_down.saturating_sub(previous.ios_down));
    let bytes_up_delta = current.bytes_up.saturating_sub(previous.bytes_up);
    let bytes_down_delta = current.bytes_down.saturating_sub(previous.bytes_down);

    stats.add_deltas(ios_delta, bytes_up_delta, bytes_down_delta);
    *previous = current;
}

pub async fn run_smoo_stats_view_loop<Sleep, SleepFut, Now, Stop, Emit>(
    stats_handle: SmooStatsHandle,
    mut sleep: Sleep,
    mut now_seconds: Now,
    mut should_stop: Stop,
    mut emit: Emit,
) where
    Sleep: FnMut() -> SleepFut,
    SleepFut: Future<Output = ()>,
    Now: FnMut() -> f64,
    Stop: FnMut() -> bool,
    Emit: FnMut(SmooStatsViewModel),
{
    let mut previous_ts = now_seconds();
    let mut accumulator = SmooStatsAccumulator::new(stats_handle.snapshot());

    loop {
        if should_stop() {
            break;
        }

        sleep().await;

        let now_ts = now_seconds();
        let dt = (now_ts - previous_ts).max(0.001);
        let snapshot = stats_handle.snapshot();
        emit(accumulator.update(snapshot, dt));
        previous_ts = now_ts;
    }
}

fn stylesheet_href(asset: &Asset, flatpak_path: &str) -> String {
    if cfg!(flatpak_runtime_paths) {
        flatpak_path.to_string()
    } else {
        asset.to_string()
    }
}

fn human_bytes_per_sec(bps: f64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
    if !bps.is_finite() || bps <= 0.0 {
        return "0 B/s".to_string();
    }
    let mut value = bps;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[component]
pub fn SmooStatsPanel(stats: SmooStatsViewModel) -> Element {
    let smoo_stats_css = stylesheet_href(&SMOO_STATS_CSS, "/assets/styling/smoo_stats.css");
    let status_text = if stats.connected {
        "Connected"
    } else {
        "Waiting"
    };
    let status_class = if stats.connected {
        "smoo-stats__status smoo-stats__status--ok"
    } else {
        "smoo-stats__status"
    };

    rsx! {
        document::Link { rel: "stylesheet", href: smoo_stats_css }

        div { class: "smoo-stats",
            div { class: "smoo-stats__header",
                p { class: "smoo-stats__eyebrow", "SMOO host" }
                p { class: status_class, "{status_text}" }
            }
            div { class: "smoo-stats__grid",
                StatCard {
                    label: "EWMA IOPS (5s)".to_string(),
                    value: format!("{:.1}", stats.ewma_iops),
                }
                StatCard {
                    label: "Up throughput".to_string(),
                    value: human_bytes_per_sec(stats.ewma_up_bps),
                }
                StatCard {
                    label: "Down throughput".to_string(),
                    value: human_bytes_per_sec(stats.ewma_down_bps),
                }
                StatCard {
                    label: "Total I/Os".to_string(),
                    value: stats.total_ios.to_string(),
                }
                StatCard {
                    label: "Total up".to_string(),
                    value: stats.total_bytes_up.to_string(),
                }
                StatCard {
                    label: "Total down".to_string(),
                    value: stats.total_bytes_down.to_string(),
                }
            }
        }
    }
}

#[component]
fn StatCard(label: String, value: String) -> Element {
    rsx! {
        div { class: "smoo-stats__card",
            p { class: "smoo-stats__label", "{label}" }
            p { class: "smoo-stats__value", "{value}" }
        }
    }
}
