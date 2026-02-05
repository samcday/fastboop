use dioxus::prelude::*;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};

use views::Home;

mod views;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[route("/")]
    Home {},
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    init_tracing();
    dioxus::launch(App);
}

fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(WASMLayer::new(
            WASMLayerConfigBuilder::default()
                .set_max_level(Level::TRACE)
                .set_report_logs_in_timings(true)
                .build(),
        ))
        .try_init();
}

#[component]
fn App() -> Element {
    // Build cool things ✌️

    rsx! {
        // Global app resources
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }

        Router::<Route> {}
    }
}
