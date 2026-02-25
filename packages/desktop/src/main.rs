use dioxus::prelude::*;
use std::env;
use std::sync::OnceLock;
use tracing_subscriber::EnvFilter;

static CHANNEL: OnceLock<String> = OnceLock::new();

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

    let channel = match parse_channel_from_args() {
        Ok(channel) => channel,
        Err(err) => {
            eprintln!(
                "fastboop-desktop requires a channel URL: --channel=<url> or --channel <url>"
            );
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let _ = CHANNEL.set(channel);

    dioxus::launch(App);
}

pub(crate) fn boot_channel() -> String {
    CHANNEL
        .get()
        .cloned()
        .expect("desktop boot channel must be initialized before app launch")
}

fn parse_channel_from_args() -> anyhow::Result<String> {
    let args = env::args().collect::<Vec<_>>();
    let mut index = 1;
    while index < args.len() {
        let arg = args[index].as_str();

        if let Some(value) = arg.strip_prefix("--channel=") {
            let value = value.trim();
            if value.is_empty() {
                anyhow::bail!("--channel=<url> value is empty");
            }
            return Ok(value.to_string());
        }

        if arg == "--channel" {
            let value = args.get(index + 1).ok_or_else(|| {
                anyhow::anyhow!(
                    "--channel requires a URL argument: --channel=<url> or --channel <url>"
                )
            })?;
            let value = value.trim();
            if value.is_empty() {
                anyhow::bail!("--channel value is empty");
            }
            return Ok(value.to_string());
        }

        index += 1;
    }

    anyhow::bail!("missing required --channel argument")
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
