use dioxus::prelude::*;
use js_sys::Reflect;
use std::sync::OnceLock;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
use url::Url;
use wasm_bindgen::JsValue;

use views::{DevicePage, Home, SessionStore};

mod channel_source;
mod gibblox_worker;
mod views;

const LOG_LEVEL_HINT_KEY: &str = "__FASTBOOP_LOG_LEVEL";
const CHANNEL_QUERY_KEY: &str = "channel";
static STARTUP_CHANNEL: OnceLock<Result<String, StartupChannelError>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct StartupChannelError {
    pub(crate) title: &'static str,
    pub(crate) details: String,
    pub(crate) launch_hint: String,
}

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

    let startup_channel = match global_query_channel() {
        Some(channel) => validate_web_channel_url(&channel),
        None => Err(missing_web_channel_error(
            "fastboop-web requires a channel URL query parameter: ?channel=<url>",
        )),
    };
    if let Err(err) = &startup_channel {
        tracing::warn!(details = %err.details, "startup channel validation failed");
    }
    let _ = STARTUP_CHANNEL.set(startup_channel);

    dioxus::launch(App);
}

pub(crate) fn startup_channel() -> Result<String, StartupChannelError> {
    STARTUP_CHANNEL.get().cloned().unwrap_or_else(|| {
        Err(missing_web_channel_error(
            "web startup channel state was not initialized",
        ))
    })
}

fn validate_web_channel_url(channel: &str) -> Result<String, StartupChannelError> {
    Url::parse(channel).map_err(|err| invalid_web_channel_error(channel, &err.to_string()))?;
    Ok(channel.to_string())
}

fn missing_web_channel_error(details: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Missing launch channel",
        details: details.to_string(),
        launch_hint:
            "Open fastboop-web with ?channel=<url> so fastboop can boot from an explicit channel."
                .to_string(),
    }
}

fn invalid_web_channel_error(channel: &str, parse_error: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Invalid launch channel",
        details: format!("channel '{channel}' is not a valid URL: {parse_error}"),
        launch_hint:
            "Open fastboop-web with a full URL like ?channel=https://example.invalid/path.ero"
                .to_string(),
    }
}

fn init_tracing() {
    let requested = requested_log_level().unwrap_or(Level::INFO);
    set_global_log_level_hint(requested);
    let targets = Targets::new()
        .with_default(Level::INFO)
        .with_target("fastboop", requested)
        .with_target("fastboop_", requested)
        .with_target("gibblox", requested)
        .with_target("gibblox_", requested)
        .with_target("smoo", requested)
        .with_target("smoo_", requested);
    let _ = tracing_subscriber::registry()
        .with(WASMLayer::new(
            WASMLayerConfigBuilder::default()
                .set_max_level(Level::TRACE)
                .set_report_logs_in_timings(true)
                .build(),
        ))
        .with(targets)
        .try_init();
}

fn requested_log_level() -> Option<Level> {
    if let Some(level) = global_log_level_hint() {
        return Some(level);
    }

    if let Some(search) = global_location_search() {
        if let Some(level) = parse_level_from_query(&search) {
            return Some(level);
        }
    }

    None
}

pub(crate) fn global_log_level_hint() -> Option<Level> {
    let global = js_sys::global();
    let value = Reflect::get(&global, &JsValue::from_str(LOG_LEVEL_HINT_KEY)).ok()?;
    let text = value.as_string()?;
    parse_level_str(&text)
}

fn set_global_log_level_hint(level: Level) {
    let global = js_sys::global();
    let _ = Reflect::set(
        &global,
        &JsValue::from_str(LOG_LEVEL_HINT_KEY),
        &JsValue::from_str(level_query_value(level)),
    );
}

fn level_query_value(level: Level) -> &'static str {
    match level {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
    }
}

fn global_location_search() -> Option<String> {
    let global = js_sys::global();
    let location = Reflect::get(&global, &JsValue::from_str("location")).ok()?;
    let search = Reflect::get(&location, &JsValue::from_str("search")).ok()?;
    search.as_string()
}

fn parse_level_from_query(search: &str) -> Option<Level> {
    query_param(search, "log").and_then(|value| parse_level_str(&value))
}

pub(crate) fn query_param(search: &str, key: &str) -> Option<String> {
    let query = search.strip_prefix('?').unwrap_or(search);
    for pair in query.split('&') {
        let Some((param_key, param_value)) = pair.split_once('=') else {
            continue;
        };
        if param_key != key {
            continue;
        }
        return decode_query_component(param_value).or_else(|| Some(param_value.to_string()));
    }
    None
}

fn decode_query_component(value: &str) -> Option<String> {
    js_sys::decode_uri_component(value)
        .ok()
        .and_then(|decoded| decoded.as_string())
}

pub(crate) fn global_query_param(key: &str) -> Option<String> {
    global_location_search().and_then(|search| query_param(&search, key))
}

pub(crate) fn global_query_channel() -> Option<String> {
    global_query_param(CHANNEL_QUERY_KEY)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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
