use dioxus::prelude::*;
use fastboop_core::read_channel_stream_head_from_reader;
use gibblox_core::{BlockByteReader, BlockReader};
use gibblox_file::FileReader;
use gibblox_http::HttpReader;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tracing_subscriber::EnvFilter;
use url::Url;

static STARTUP_CHANNEL: OnceLock<Result<Option<String>, StartupChannelError>> = OnceLock::new();

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

#[derive(Clone, Debug)]
pub(crate) enum DesktopChannelLocation {
    Http(Url),
    File(PathBuf),
}

impl DesktopChannelLocation {
    pub(crate) fn file_name(&self) -> Option<String> {
        match self {
            Self::Http(url) => url
                .path_segments()
                .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back())
                .map(str::to_string),
            Self::File(path) => path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string),
        }
    }
}

pub(crate) struct OpenedDesktopChannel {
    pub(crate) reader: Arc<dyn BlockReader>,
    pub(crate) exact_total_bytes: u64,
    pub(crate) location: DesktopChannelLocation,
}

impl StartupChannelIntake {
    pub(crate) fn has_artifact_payload(&self) -> bool {
        self.stream_head.consumed_bytes < self.exact_total_bytes
    }
}

use views::{DevicePage, Home, SessionStore};

mod stage0_binary;
mod views;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[route("/")]
    Home {},
    #[route("/device/:session_id")]
    DevicePage { session_id: String },
}

const MAIN_CSS: Asset = asset!("/assets/main.css");
const NATIVE_HANDLER_SCHEME: &str = "fastboop";
const NATIVE_HANDLER_BOOT_AUTHORITY: &str = "boot";

fn stylesheet_href(asset: &Asset, flatpak_path: &str) -> String {
    if std::env::var_os("FLATPAK_ID").is_some() {
        flatpak_path.to_string()
    } else {
        asset.to_string()
    }
}

fn main() {
    init_tracing();

    let startup_channel = parse_channel_from_args();
    if let Err(err) = &startup_channel {
        eprintln!("{}", err.details);
    }
    let _ = STARTUP_CHANNEL.set(startup_channel);

    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new().with_window(
                dioxus::desktop::WindowBuilder::new()
                    .with_title("fastboop")
                    .with_inner_size(dioxus::desktop::LogicalSize::new(1180.0, 820.0)),
            ),
        )
        .launch(App);
}

pub(crate) fn startup_channel() -> Result<Option<String>, StartupChannelError> {
    STARTUP_CHANNEL.get().cloned().unwrap_or_else(|| {
        Err(missing_desktop_channel_error(
            "desktop startup channel state was not initialized",
        ))
    })
}

pub(crate) async fn preflight_startup_channel(channel: &str) -> Result<(), StartupChannelError> {
    load_startup_channel_intake(channel).await.map(|_| ())
}

pub(crate) async fn load_startup_channel_intake(
    channel: &str,
) -> Result<StartupChannelIntake, StartupChannelError> {
    let opened = open_desktop_channel(channel).await?;
    read_startup_channel_intake(channel, opened.reader.as_ref(), opened.exact_total_bytes).await
}

pub(crate) async fn open_desktop_channel(
    channel: &str,
) -> Result<OpenedDesktopChannel, StartupChannelError> {
    let location = parse_desktop_channel_location(channel)?;
    let (reader, exact_total_bytes) = match &location {
        DesktopChannelLocation::Http(url) => {
            let reader = HttpReader::new(url.clone(), gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
                .await
                .map_err(|err| {
                    invalid_desktop_channel_error(
                        channel,
                        &format!("open HTTP reader for {url}: {err}"),
                    )
                })?;
            let exact_total_bytes = reader.size_bytes();
            let reader = BlockByteReader::new(reader, gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
                .map_err(|err| {
                    invalid_desktop_channel_error(
                        channel,
                        &format!("open HTTP block view for {url}: {err}"),
                    )
                })?;
            (Arc::new(reader) as Arc<dyn BlockReader>, exact_total_bytes)
        }
        DesktopChannelLocation::File(path) => {
            let reader = FileReader::open(path, gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
                .map_err(|err| {
                    invalid_desktop_channel_error(
                        channel,
                        &format!("open file reader for {}: {err}", path.display()),
                    )
                })?;
            let exact_total_bytes = reader.size_bytes();
            (Arc::new(reader) as Arc<dyn BlockReader>, exact_total_bytes)
        }
    };

    Ok(OpenedDesktopChannel {
        reader,
        exact_total_bytes,
        location,
    })
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
        return Err(invalid_desktop_channel_error(
            channel,
            "channel stream is empty",
        ));
    }

    let stream_head = read_channel_stream_head_from_reader(reader, exact_total_bytes)
        .await
        .map_err(|err| invalid_desktop_channel_error(channel, &err.to_string()))?;

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

fn parse_channel_from_args() -> Result<Option<String>, StartupChannelError> {
    let args = env::args().collect::<Vec<_>>();
    parse_channel_from_arg_slice(&args[1..])
}

fn parse_channel_from_arg_slice(args: &[String]) -> Result<Option<String>, StartupChannelError> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();

        if let Some(value) = arg.strip_prefix("--channel=") {
            let value = value.trim();
            if value.is_empty() {
                return Err(missing_desktop_channel_error(
                    "--channel=<url-or-path> value is empty",
                ));
            }
            return parse_startup_channel_value(value).map(Some);
        }

        if arg == "--channel" {
            let value = args.get(index + 1).ok_or_else(|| {
                missing_desktop_channel_error(
                    "--channel requires a channel argument: --channel=<url-or-path> or --channel <url-or-path>",
                )
            })?;
            let value = value.trim();
            if value.is_empty() {
                return Err(missing_desktop_channel_error("--channel value is empty"));
            }
            return parse_startup_channel_value(value).map(Some);
        }

        if is_native_handler_url(arg.trim()) {
            return parse_startup_channel_value(arg.trim()).map(Some);
        }

        index += 1;
    }

    Ok(None)
}

fn parse_startup_channel_value(value: &str) -> Result<String, StartupChannelError> {
    let value = value.trim();
    if is_native_handler_url(value) {
        let url = Url::parse(value)
            .map_err(|err| invalid_native_handler_url_error(value, &err.to_string()))?;
        return extract_native_handler_channel(value, &url);
    }

    validate_desktop_channel(value)
}

fn validate_desktop_channel(channel: &str) -> Result<String, StartupChannelError> {
    parse_desktop_channel_location(channel)?;
    Ok(channel.trim().to_string())
}

fn parse_desktop_channel_location(
    channel: &str,
) -> Result<DesktopChannelLocation, StartupChannelError> {
    let channel = channel.trim();
    if channel.is_empty() {
        return Err(missing_desktop_channel_error("channel location is empty"));
    }

    if let Ok(url) = Url::parse(channel) {
        return match url.scheme() {
            "http" | "https" => Ok(DesktopChannelLocation::Http(url)),
            "file" => url
                .to_file_path()
                .map(DesktopChannelLocation::File)
                .map_err(|_| {
                    invalid_desktop_channel_error(
                        channel,
                        "file:// URL is not a valid local file path",
                    )
                }),
            scheme => Err(invalid_desktop_channel_error(
                channel,
                &format!(
                    "unsupported channel scheme '{scheme}'; use HTTP(S), file://, or a local path"
                ),
            )),
        };
    }

    Ok(DesktopChannelLocation::File(PathBuf::from(channel)))
}

fn extract_native_handler_channel(source: &str, url: &Url) -> Result<String, StartupChannelError> {
    if url.host_str() != Some(NATIVE_HANDLER_BOOT_AUTHORITY) {
        return Err(invalid_native_handler_url_error(
            source,
            "expected fastboop://boot?channel=<url>",
        ));
    }

    let channel = url
        .query_pairs()
        .find_map(|(name, value)| (name == "channel").then(|| value.into_owned()))
        .ok_or_else(|| {
            invalid_native_handler_url_error(source, "missing channel query parameter")
        })?;
    let channel = channel.trim();
    if channel.is_empty() {
        return Err(invalid_native_handler_url_error(
            source,
            "channel query parameter is empty",
        ));
    }

    validate_desktop_channel(channel)
}

fn is_native_handler_url(value: &str) -> bool {
    value
        .split_once(':')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case(NATIVE_HANDLER_SCHEME))
}

fn missing_desktop_channel_error(details: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Missing launch channel",
        details: details.to_string(),
        launch_hint: "Choose a local channel file, enter a channel URL/path, or launch with --channel=<url-or-path>."
            .to_string(),
    }
}

fn invalid_desktop_channel_error(channel: &str, reason: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Invalid launch channel",
        details: format!("channel '{channel}' is invalid or unreadable: {reason}"),
        launch_hint: "Use an HTTP(S) URL, file:// URL, or local channel path.".to_string(),
    }
}

fn invalid_native_handler_url_error(link: &str, reason: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Invalid fastboop link",
        details: format!("fastboop link '{link}' is invalid: {reason}"),
        launch_hint:
            "Open fastboop links like fastboop://boot?channel=https%3A%2F%2Fexample.invalid%2Fpath.ero"
                .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Option<String>, StartupChannelError> {
        let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        parse_channel_from_arg_slice(&args)
    }

    #[test]
    fn allows_missing_startup_channel() {
        let channel = parse_args(&[]).unwrap();

        assert_eq!(channel, None);
    }

    #[test]
    fn parses_channel_flag() {
        let channel = parse_args(&["--channel", "https://example.invalid/channel.ero"]).unwrap();

        assert_eq!(
            channel,
            Some("https://example.invalid/channel.ero".to_string())
        );
    }

    #[test]
    fn parses_local_channel_path() {
        let channel = parse_args(&["--channel", "/tmp/channel.ero"]).unwrap();

        assert_eq!(channel, Some("/tmp/channel.ero".to_string()));
    }

    #[test]
    fn parses_native_handler_url() {
        let channel =
            parse_args(&["fastboop://boot?channel=https%3A%2F%2Fexample.invalid%2Fchannel.ero"])
                .unwrap();

        assert_eq!(
            channel,
            Some("https://example.invalid/channel.ero".to_string())
        );
    }

    #[test]
    fn rejects_native_handler_url_without_channel() {
        let err = parse_args(&["fastboop://boot"]).unwrap_err();

        assert_eq!(err.title, "Invalid fastboop link");
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

#[component]
fn App() -> Element {
    let main_css = stylesheet_href(&MAIN_CSS, "/assets/main.css");
    let sessions = use_signal(Vec::new);
    use_context_provider(|| -> SessionStore { sessions });

    // Build cool things ✌️

    rsx! {
        // Global app resources
        document::Link { rel: "stylesheet", href: main_css }

        Router::<Route> {}
    }
}
