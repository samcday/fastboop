use dioxus::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

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

fn stylesheet_href(asset: &Asset, flatpak_path: &str) -> String {
    if std::env::var_os("FLATPAK_ID").is_some() {
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
