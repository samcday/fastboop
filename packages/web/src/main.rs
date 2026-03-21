use dioxus::prelude::*;
use fastboop_core::{read_channel_stream_head, CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES};
#[cfg(not(target_arch = "wasm32"))]
use gibblox_core::BlockByteReader;
use gibblox_core::{BlockReader, ReadContext};
#[cfg(not(target_arch = "wasm32"))]
use gibblox_http::HttpReader;
#[cfg(target_arch = "wasm32")]
use gibblox_web_file::WebFileReader;
use js_sys::Reflect;
#[cfg(target_arch = "wasm32")]
use js_sys::Uint8Array;
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
#[cfg(target_arch = "wasm32")]
use std::collections::BTreeMap;
#[cfg(target_arch = "wasm32")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
use url::Url;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{Headers, Request, RequestInit, RequestMode, Response, WorkerGlobalScope};

use views::{DevicePage, Home, SessionStore};

mod channel_source;
mod gibblox_worker;
mod views;

const LOG_LEVEL_HINT_KEY: &str = "__FASTBOOP_LOG_LEVEL";
const CHANNEL_QUERY_KEY: &str = "channel";
#[cfg(target_arch = "wasm32")]
const WEB_FILE_CHANNEL_PREFIX: &str = "web-file://";
static STARTUP_CHANNEL: OnceLock<Result<String, StartupChannelError>> = OnceLock::new();
#[cfg(target_arch = "wasm32")]
static WEB_FILE_CHANNEL_COUNTER: AtomicU64 = AtomicU64::new(1);

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpPreflightMode {
    PriorityAndRange,
    RangeOnly,
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static WEB_FILE_CHANNEL_REGISTRY: RefCell<BTreeMap<String, web_sys::File>> =
        const { RefCell::new(BTreeMap::new()) };
}

#[derive(Clone, Debug)]
pub(crate) struct StartupChannelError {
    pub(crate) title: &'static str,
    pub(crate) details: String,
    pub(crate) launch_hint: String,
}

#[derive(Clone, Debug)]
pub(crate) struct StartupChannelIntake {
    pub(crate) exact_total_bytes: u64,
    pub(crate) stream_head: fastboop_core::ChannelStreamHead,
}

impl StartupChannelIntake {
    pub(crate) fn has_artifact_payload(&self) -> bool {
        self.stream_head.consumed_bytes < self.exact_total_bytes
    }
}

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[route("/?:channel")]
    Home { channel: Option<String> },
    #[route("/device/:session_id?:channel")]
    DevicePage { session_id: String, channel: Option<String> },
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();

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

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) async fn preflight_startup_channel(channel: &str) -> Result<(), StartupChannelError> {
    load_startup_channel_intake(channel).await.map(|_| ())
}

pub(crate) async fn load_startup_channel_intake(
    channel: &str,
) -> Result<StartupChannelIntake, StartupChannelError> {
    #[cfg(target_arch = "wasm32")]
    if let Some(file) = resolve_web_file_channel(channel) {
        let reader =
            WebFileReader::new(file, gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE).map_err(|err| {
                invalid_web_channel_error(channel, &format!("open web file reader: {err}"))
            })?;
        let exact_total_bytes = reader.size_bytes();
        return read_startup_channel_intake(channel, &reader, exact_total_bytes).await;
    }

    let url =
        Url::parse(channel).map_err(|err| invalid_web_channel_error(channel, &err.to_string()))?;

    #[cfg(target_arch = "wasm32")]
    {
        return load_wasm_http_startup_channel_intake(channel, &url).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let reader = HttpReader::new(url.clone(), gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
            .await
            .map_err(|err| {
                invalid_web_channel_error(channel, &format!("open HTTP reader for {url}: {err}"))
            })?;
        let exact_total_bytes = reader.size_bytes();
        let reader = BlockByteReader::new(reader, gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
            .map_err(|err| {
                invalid_web_channel_error(
                    channel,
                    &format!("open HTTP block view for {url}: {err}"),
                )
            })?;

        read_startup_channel_intake(channel, &reader, exact_total_bytes).await
    }
}

#[cfg(target_arch = "wasm32")]
async fn load_wasm_http_startup_channel_intake(
    channel: &str,
    url: &Url,
) -> Result<StartupChannelIntake, StartupChannelError> {
    let (mode, exact_total_bytes) = preflight_wasm_http_channel(url)
        .await
        .map_err(|reason| invalid_web_channel_error(channel, &reason))?;

    if exact_total_bytes == 0 {
        return Err(invalid_web_channel_error(
            channel,
            "channel stream is empty",
        ));
    }

    let scan_cap = core::cmp::min(
        CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES as u64,
        exact_total_bytes,
    ) as usize;
    let prefix = read_wasm_http_channel_prefix(url, scan_cap, exact_total_bytes, mode)
        .await
        .map_err(|reason| invalid_web_channel_error(channel, &reason))?;
    let stream_head = read_channel_stream_head(prefix.as_slice(), exact_total_bytes)
        .map_err(|err| invalid_web_channel_error(channel, &err.to_string()))?;

    let intake = StartupChannelIntake {
        exact_total_bytes,
        stream_head,
    };

    if intake.stream_head.warning_count > 0 {
        tracing::warn!(
            warning_count = intake.stream_head.warning_count,
            consumed_bytes = intake.stream_head.consumed_bytes,
            channel,
            "channel stream stopped after valid records due trailing bytes"
        );
    }

    Ok(intake)
}

async fn read_startup_channel_intake<R>(
    channel: &str,
    reader: &R,
    exact_total_bytes: u64,
) -> Result<StartupChannelIntake, StartupChannelError>
where
    R: BlockReader + ?Sized,
{
    if exact_total_bytes == 0 {
        return Err(invalid_web_channel_error(
            channel,
            "channel stream is empty",
        ));
    }

    let scan_cap = core::cmp::min(
        CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES as u64,
        exact_total_bytes,
    ) as usize;
    let prefix = read_channel_prefix(reader, scan_cap, exact_total_bytes)
        .await
        .map_err(|err| invalid_web_channel_error(channel, &err))?;
    let stream_head = read_channel_stream_head(prefix.as_slice(), exact_total_bytes)
        .map_err(|err| invalid_web_channel_error(channel, &err.to_string()))?;

    let intake = StartupChannelIntake {
        exact_total_bytes,
        stream_head,
    };

    if intake.stream_head.warning_count > 0 {
        tracing::warn!(
            warning_count = intake.stream_head.warning_count,
            consumed_bytes = intake.stream_head.consumed_bytes,
            channel,
            "channel stream stopped after valid records due trailing bytes"
        );
    }

    Ok(intake)
}

#[cfg(target_arch = "wasm32")]
async fn preflight_wasm_http_channel(url: &Url) -> Result<(HttpPreflightMode, u64), String> {
    match probe_wasm_http_channel_size(url, HttpPreflightMode::PriorityAndRange).await {
        Ok(size_bytes) => Ok((HttpPreflightMode::PriorityAndRange, size_bytes)),
        Err(priority_err) => {
            tracing::warn!(
                %url,
                error = %priority_err,
                "HTTP startup preflight with Priority+Range failed, retrying with Range-only"
            );
            let size_bytes = probe_wasm_http_channel_size(url, HttpPreflightMode::RangeOnly)
                .await
                .map_err(|range_err| {
                    format!(
                        "HTTP startup preflight failed for both Priority+Range and Range-only requests (priority+range: {priority_err}; range-only: {range_err})"
                    )
                })?;
            tracing::warn!(
                %url,
                "HTTP startup preflight downgraded to Range-only mode because Priority header is not accepted"
            );
            Ok((HttpPreflightMode::RangeOnly, size_bytes))
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn probe_wasm_http_channel_size(url: &Url, mode: HttpPreflightMode) -> Result<u64, String> {
    let response = send_wasm_http_range_request(url, 0, 0, mode)
        .await
        .map_err(|err| format!("probe request failed: {err}"))?;
    let status = response.status();
    if status != 206 {
        return Err(format!(
            "probe response status {status} (expected 206 Partial Content)"
        ));
    }
    let headers = response.headers();
    let content_range = read_header_value(&headers, "Content-Range")?
        .ok_or_else(|| "probe response missing Content-Range header".to_string())?;
    let total = parse_content_range_total(&content_range)
        .ok_or_else(|| format!("invalid Content-Range header '{content_range}'"))?;
    Ok(total)
}

#[cfg(target_arch = "wasm32")]
async fn read_wasm_http_channel_prefix(
    url: &Url,
    scan_cap: usize,
    exact_total_bytes: u64,
    mode: HttpPreflightMode,
) -> Result<Vec<u8>, String> {
    let prefix_len = core::cmp::min(scan_cap as u64, exact_total_bytes) as usize;
    if prefix_len == 0 {
        return Ok(Vec::new());
    }
    let end = (prefix_len - 1) as u64;
    let response = send_wasm_http_range_request(url, 0, end, mode).await?;
    let status = response.status();
    if status != 206 {
        return Err(format!(
            "prefix response status {status} (expected 206 Partial Content)"
        ));
    }
    let content_range = read_header_value(&response.headers(), "Content-Range")?
        .ok_or_else(|| "prefix response missing Content-Range header".to_string())?;
    let (start, response_end, _) = parse_content_range(&content_range)
        .ok_or_else(|| format!("invalid Content-Range header '{content_range}'"))?;
    if start != 0 || response_end != end {
        return Err(format!(
            "prefix content-range mismatch: got bytes {start}-{response_end}, expected bytes 0-{end}"
        ));
    }

    let body = response_bytes(response)
        .await
        .map_err(|err| format!("read prefix response body: {err}"))?;
    if body.len() != prefix_len {
        return Err(format!(
            "prefix body length mismatch: got {}, expected {prefix_len}",
            body.len()
        ));
    }
    Ok(body)
}

#[cfg(target_arch = "wasm32")]
async fn send_wasm_http_range_request(
    url: &Url,
    start: u64,
    end: u64,
    mode: HttpPreflightMode,
) -> Result<Response, String> {
    let init = RequestInit::new();
    init.set_method("GET");
    init.set_mode(RequestMode::Cors);
    let headers = Headers::new().map_err(js_value_to_string)?;
    headers
        .append("Range", &format!("bytes={start}-{end}"))
        .map_err(js_value_to_string)?;
    if mode == HttpPreflightMode::PriorityAndRange {
        headers
            .append("Priority", "u=0, i")
            .map_err(js_value_to_string)?;
    }
    init.set_headers(&headers);
    let request =
        Request::new_with_str_and_init(url.as_str(), &init).map_err(js_value_to_string)?;
    let promise = if let Some(window) = web_sys::window() {
        window.fetch_with_request(&request)
    } else if let Ok(worker) = js_sys::global().dyn_into::<WorkerGlobalScope>() {
        worker.fetch_with_request(&request)
    } else {
        return Err("no fetch-capable web global scope".to_string());
    };
    let js_response = JsFuture::from(promise).await.map_err(js_value_to_string)?;
    js_response
        .dyn_into::<Response>()
        .map_err(js_value_to_string)
}

#[cfg(target_arch = "wasm32")]
async fn response_bytes(response: Response) -> Result<Vec<u8>, String> {
    let promise = response.array_buffer().map_err(js_value_to_string)?;
    let array_buffer = JsFuture::from(promise).await.map_err(js_value_to_string)?;
    let array = Uint8Array::new(&array_buffer);
    Ok(array.to_vec())
}

#[cfg(target_arch = "wasm32")]
fn read_header_value(headers: &Headers, name: &str) -> Result<Option<String>, String> {
    headers.get(name).map_err(js_value_to_string)
}

#[cfg(target_arch = "wasm32")]
fn parse_content_range_total(hdr: &str) -> Option<u64> {
    parse_content_range(hdr).and_then(|(_, _, total)| total)
}

#[cfg(target_arch = "wasm32")]
fn parse_content_range(hdr: &str) -> Option<(u64, u64, Option<u64>)> {
    let hdr = hdr.trim().strip_prefix("bytes ")?;
    let (span, total) = hdr.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    let total = if total == "*" {
        None
    } else {
        Some(total.parse::<u64>().ok()?)
    };
    Some((start, end, total))
}

#[cfg(target_arch = "wasm32")]
fn js_value_to_string(value: JsValue) -> String {
    js_sys::JSON::stringify(&value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn register_web_file_channel(file: web_sys::File) -> String {
    let channel_id = WEB_FILE_CHANNEL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let channel_key = channel_id.to_string();
    WEB_FILE_CHANNEL_REGISTRY.with(|registry| {
        registry.borrow_mut().insert(channel_key.clone(), file);
    });
    format!("{WEB_FILE_CHANNEL_PREFIX}{channel_key}")
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn unregister_web_file_channel(channel: &str) {
    let Some(channel_key) = channel.strip_prefix(WEB_FILE_CHANNEL_PREFIX) else {
        return;
    };
    WEB_FILE_CHANNEL_REGISTRY.with(|registry| {
        registry.borrow_mut().remove(channel_key);
    });
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn resolve_web_file_channel(channel: &str) -> Option<web_sys::File> {
    let channel_key = channel.strip_prefix(WEB_FILE_CHANNEL_PREFIX)?;
    WEB_FILE_CHANNEL_REGISTRY.with(|registry| registry.borrow().get(channel_key).cloned())
}

fn validate_web_channel_url(channel: &str) -> Result<String, StartupChannelError> {
    Url::parse(channel).map_err(|err| invalid_web_channel_error(channel, &err.to_string()))?;
    Ok(channel.to_string())
}

async fn read_channel_prefix<R>(
    reader: &R,
    scan_cap: usize,
    exact_total_bytes: u64,
) -> Result<Vec<u8>, String>
where
    R: BlockReader + ?Sized,
{
    let block_size = usize::try_from(reader.block_size())
        .map_err(|_| format!("channel block size {} is invalid", reader.block_size()))?;
    if block_size == 0 {
        return Err("channel block size is zero".to_string());
    }

    let prefix_len = core::cmp::min(scan_cap as u64, exact_total_bytes) as usize;
    if prefix_len == 0 {
        return Ok(Vec::new());
    }

    let blocks_to_read = prefix_len.div_ceil(block_size);
    let mut scratch = vec![0u8; blocks_to_read * block_size];
    let mut read = reader
        .read_blocks(0, &mut scratch, ReadContext::FOREGROUND)
        .await
        .map_err(|err| format!("read channel prefix: {err}"))?;
    read = core::cmp::min(read, prefix_len);
    scratch.truncate(read);
    Ok(scratch)
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

fn invalid_web_channel_error(channel: &str, reason: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Invalid launch channel",
        details: format!("channel '{channel}' is invalid or unreadable: {reason}"),
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
