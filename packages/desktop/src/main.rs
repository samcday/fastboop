use dioxus::prelude::*;
use std::env;
use std::sync::OnceLock;
use tracing_subscriber::EnvFilter;
use url::Url;

static STARTUP_CHANNEL: OnceLock<Result<String, StartupChannelError>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct StartupChannelError {
    pub(crate) title: &'static str,
    pub(crate) details: String,
    pub(crate) launch_hint: String,
}

use views::{DevicePage, Home, SessionStore};

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

    dioxus::launch(App);
}

pub(crate) fn startup_channel() -> Result<String, StartupChannelError> {
    STARTUP_CHANNEL.get().cloned().unwrap_or_else(|| {
        Err(missing_desktop_channel_error(
            "desktop startup channel state was not initialized",
        ))
    })
}

fn parse_channel_from_args() -> Result<String, StartupChannelError> {
    let args = env::args().collect::<Vec<_>>();
    let mut index = 1;
    while index < args.len() {
        let arg = args[index].as_str();

        if let Some(value) = arg.strip_prefix("--channel=") {
            let value = value.trim();
            if value.is_empty() {
                return Err(missing_desktop_channel_error(
                    "--channel=<url> value is empty",
                ));
            }
            return validate_desktop_channel_url(value);
        }

        if arg == "--channel" {
            let value = args.get(index + 1).ok_or_else(|| {
                missing_desktop_channel_error(
                    "--channel requires a URL argument: --channel=<url> or --channel <url>",
                )
            })?;
            let value = value.trim();
            if value.is_empty() {
                return Err(missing_desktop_channel_error("--channel value is empty"));
            }
            return validate_desktop_channel_url(value);
        }

        index += 1;
    }

    Err(missing_desktop_channel_error(
        "fastboop-desktop requires --channel=<url> or --channel <url>",
    ))
}

fn validate_desktop_channel_url(channel: &str) -> Result<String, StartupChannelError> {
    Url::parse(channel).map_err(|err| invalid_desktop_channel_error(channel, &err.to_string()))?;
    Ok(channel.to_string())
}

fn missing_desktop_channel_error(details: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Missing launch channel",
        details: details.to_string(),
        launch_hint:
            "Launch with --channel=<url> (or --channel <url>) so fastboop can boot from an explicit channel."
                .to_string(),
    }
}

fn invalid_desktop_channel_error(channel: &str, parse_error: &str) -> StartupChannelError {
    StartupChannelError {
        title: "Invalid launch channel",
        details: format!("channel '{channel}' is not a valid URL: {parse_error}"),
        launch_hint: "Launch with a full URL like --channel=https://example.invalid/path.ero"
            .to_string(),
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
