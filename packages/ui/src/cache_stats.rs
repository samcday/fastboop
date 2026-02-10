use dioxus::prelude::*;

const CACHE_STATS_CSS: Asset = asset!("/assets/styling/cache_stats.css");

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CacheStatsViewModel {
    pub total_blocks: u64,
    pub cached_blocks: u64,
    pub total_hits: u64,
    pub total_misses: u64,
}

impl CacheStatsViewModel {
    pub fn hit_rate(&self) -> f64 {
        let total = self.total_hits + self.total_misses;
        if total == 0 {
            return 0.0;
        }
        (self.total_hits as f64 / total as f64) * 100.0
    }

    pub fn fill_rate(&self) -> f64 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        (self.cached_blocks as f64 / self.total_blocks as f64) * 100.0
    }
}

fn stylesheet_href(asset: &Asset, flatpak_path: &str) -> String {
    if std::env::var_os("FLATPAK_ID").is_some() {
        flatpak_path.to_string()
    } else {
        asset.to_string()
    }
}

#[component]
pub fn CacheStatsPanel(stats: CacheStatsViewModel) -> Element {
    let cache_stats_css = stylesheet_href(&CACHE_STATS_CSS, "/assets/styling/cache_stats.css");

    rsx! {
        document::Link { rel: "stylesheet", href: cache_stats_css }

        div { class: "cache-stats",
            div { class: "cache-stats__header",
                p { class: "cache-stats__eyebrow", "Rootfs cache" }
                p { class: "cache-stats__title", "Cache stats" }
            }

            div { class: "cache-stats__grid",
                StatCard {
                    label: "Cached blocks".to_string(),
                    value: stats.cached_blocks.to_string(),
                }
                StatCard {
                    label: "Cache fill".to_string(),
                    value: format!("{:.1}%", stats.fill_rate()),
                }
                StatCard {
                    label: "Hit rate".to_string(),
                    value: format!("{:.1}%", stats.hit_rate()),
                }
                StatCard {
                    label: "Hits".to_string(),
                    value: stats.total_hits.to_string(),
                }
                StatCard {
                    label: "Misses".to_string(),
                    value: stats.total_misses.to_string(),
                }
                StatCard {
                    label: "Total blocks".to_string(),
                    value: stats.total_blocks.to_string(),
                }
            }
        }
    }
}

#[component]
fn StatCard(label: String, value: String) -> Element {
    rsx! {
        div { class: "cache-stats__card",
            p { class: "cache-stats__label", "{label}" }
            p { class: "cache-stats__value", "{value}" }
        }
    }
}
