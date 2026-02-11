use dioxus::prelude::*;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};

use views::{DevicePage, Home, SessionStore};

mod gibblox_worker;
mod views;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[route("/")]
    Home {},
    #[route("/device/:session_id")]
    DevicePage { session_id: String },
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    init_tracing();

    #[cfg(target_arch = "wasm32")]
    if smoo_host_web_worker::run_if_worker() {
        return;
    }

    #[cfg(target_arch = "wasm32")]
    if gibblox_worker::run_if_worker() {
        return;
    }

    dioxus::launch(App);
}

fn init_tracing() {
    let max_level = requested_log_level().unwrap_or(Level::INFO);
    let _ = tracing_subscriber::registry()
        .with(WASMLayer::new(
            WASMLayerConfigBuilder::default()
                .set_max_level(max_level)
                .set_report_logs_in_timings(true)
                .build(),
        ))
        .try_init();
}

fn requested_log_level() -> Option<Level> {
    let window = web_sys::window()?;

    if let Ok(search) = window.location().search() {
        if let Some(level) = parse_level_from_query(&search) {
            return Some(level);
        }
    }

    None
}

fn parse_level_from_query(search: &str) -> Option<Level> {
    let query = search.strip_prefix('?').unwrap_or(search);
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key == "log" {
            return parse_level_str(value);
        }
    }
    None
}

fn parse_level_str(input: &str) -> Option<Level> {
    if input.eq_ignore_ascii_case("trace") {
        return Some(Level::TRACE);
    }
    if input.eq_ignore_ascii_case("debug") {
        return Some(Level::DEBUG);
    }
    if input.eq_ignore_ascii_case("info") {
        return Some(Level::INFO);
    }
    if input.eq_ignore_ascii_case("warn") {
        return Some(Level::WARN);
    }
    if input.eq_ignore_ascii_case("error") {
        return Some(Level::ERROR);
    }
    None
}

#[component]
fn App() -> Element {
    let sessions = use_signal(Vec::new);
    use_context_provider(|| -> SessionStore { sessions });

    // Build cool things ✌️

    rsx! {
        // Global app resources
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }

        Router::<Route> {}
    }
}
