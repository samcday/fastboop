#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("fastboop-web-single-page-example is intended for wasm32; see its README.md");
}

#[cfg(target_arch = "wasm32")]
fn main() {
    wasm::main();
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::cell::RefCell;

    use anyhow::{Context as _, Result, anyhow, bail};
    use fastboop_core::builtin::builtin_profiles;
    use fastboop_core::device::{DeviceHandle as _, profile_filters};
    use fastboop_core::prober::probe_candidates;
    use fastboop_core::{DeviceProfile, FastbootBoot};
    use fastboop_environment_web::{
        WebBootConfig, WebBootEnvironment, WebBootStage0Config, WebSelectedFastbootDevice,
        WebSmooHostEvent, WebSmooHostOptions, WebSmooHostPhase, WebUsbDeviceHandle, request_device,
        run_gibblox_worker_if_needed, run_smoo_host_worker_if_needed, run_web_smoo_host,
    };
    use futures_util::StreamExt as _;
    use tracing::Level;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
    use url::Url;
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use wasm_bindgen_futures::{JsFuture, spawn_local};
    use web_sys::{Document, Element, HtmlButtonElement, HtmlInputElement};

    const LOG_LEVEL_HINT_KEY: &str = "__FASTBOOP_LOG_LEVEL";

    thread_local! {
        static SELECTED_DEVICE: RefCell<Option<SelectedDevice>> = const { RefCell::new(None) };
    }

    #[derive(Clone)]
    struct SelectedDevice {
        handle: WebUsbDeviceHandle,
        profile: DeviceProfile,
    }

    pub fn main() {
        console_error_panic_hook::set_once();
        init_tracing();

        if run_smoo_host_worker_if_needed() {
            return;
        }
        if run_gibblox_worker_if_needed() {
            return;
        }

        if let Err(err) = wire_page() {
            set_status(format!("initialization failed: {err:#}"));
        } else {
            set_status(
                "Ready. Put the device in fastboot mode, then click Detect device.\n\
                 Rootfs and stage0 URLs may be relative to this page or absolute HTTP(S) URLs.",
            );
        }
    }

    fn wire_page() -> Result<()> {
        set_button_enabled("boot-device", false);

        install_click_handler("detect-device", move |_| {
            set_button_enabled("detect-device", false);
            set_button_enabled("boot-device", false);
            spawn_local(async move {
                match detect_selected_device().await {
                    Ok(()) => {
                        set_button_enabled("detect-device", true);
                        set_button_enabled("boot-device", true);
                    }
                    Err(err) => {
                        set_button_enabled("detect-device", true);
                        append_status(format!("detect failed: {err:#}"));
                    }
                }
            });
        })?;

        install_click_handler("boot-device", move |_| {
            set_button_enabled("boot-device", false);
            spawn_local(async move {
                if let Err(err) = boot_selected_device().await {
                    set_button_enabled("boot-device", true);
                    append_status(format!("boot failed: {err:#}"));
                }
            });
        })?;

        Ok(())
    }

    async fn detect_selected_device() -> Result<()> {
        set_status("Loading built-in device profiles...");
        let profiles = builtin_profiles().map_err(|err| anyhow!("load built-in DevPros: {err}"))?;
        let filters = profile_filters(&profiles);
        if filters.is_empty() {
            bail!("built-in DevPros did not produce any WebUSB fastboot filters");
        }

        append_status(format!(
            "Requesting WebUSB access for {} fastboot VID/PID filters...",
            filters.len()
        ));
        let handle = request_device(&filters)
            .await
            .map_err(|err| anyhow!("request WebUSB device: {err}"))?;
        let vid = handle.vid();
        let pid = handle.pid();
        append_status(format!(
            "Probing {vid:04x}:{pid:04x} with built-in DevPros..."
        ));

        let candidates = [handle.clone()];
        let reports = probe_candidates(&profiles, &candidates).await;
        close_webusb_device(&handle).await;

        let profile_id = reports
            .iter()
            .flat_map(|report| report.attempts.iter())
            .find(|attempt| attempt.result.is_ok())
            .map(|attempt| attempt.profile_id.as_str())
            .ok_or_else(|| anyhow!("no built-in DevPro probe matched {vid:04x}:{pid:04x}"))?;
        let profile = profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
            .ok_or_else(|| anyhow!("probe returned unknown DevPro id '{profile_id}'"))?;
        let display_name = profile
            .display_name
            .clone()
            .unwrap_or_else(|| profile.id.clone());

        SELECTED_DEVICE.with(|selected| {
            selected.replace(Some(SelectedDevice {
                handle,
                profile: profile.clone(),
            }));
        });

        append_status(format!(
            "Detected {display_name} ({}) on {vid:04x}:{pid:04x}. Ready to boot.",
            profile.id
        ));
        Ok(())
    }

    async fn boot_selected_device() -> Result<()> {
        let selected = SELECTED_DEVICE
            .with(|selected| selected.borrow().clone())
            .ok_or_else(|| anyhow!("no detected device is selected"))?;
        let channel = absolute_url(input_value("channel-url")?.as_str())?;
        let stage0_url = absolute_url(input_value("stage0-url")?.as_str())?;
        let cmdline_append = optional_input_value("cmdline")?;
        let serial = checkbox_checked("serial")?;

        append_status(format!(
            "Preparing stage0 for {} from {channel}",
            selected.profile.id
        ));
        let initial_device = selected.handle.device();
        let selected_device =
            WebSelectedFastbootDevice::new(selected.handle.clone(), selected.profile.clone());
        let mut env = WebBootEnvironment::new(WebBootConfig {
            stage0: WebBootStage0Config {
                channel: channel.clone(),
                boot_profile: None,
                cmdline_append,
                serial,
                stage0_asset_url: Some(stage0_url),
                smoo_max_io: None,
            },
        })
        .with_selected_device(selected_device);

        let prepared = env
            .prepare_boot()
            .await
            .context("prepare web boot payload")?;
        let runtime = env
            .runtime_for_export(&prepared.export)
            .context("prepare web smoo runtime")?;
        append_status(format!(
            "Built boot image ({} bytes) for rootfs identity {} ({} bytes).",
            prepared.boot_image.len(),
            runtime.identity,
            runtime.size_bytes
        ));

        append_status("Opening fastboot transport...");
        let mut fastboot = env
            .connect_fastboot()
            .await
            .context("open selected WebUSB fastboot transport")?;

        append_status("Issuing fastboot download + boot...");
        FastbootBoot::new(&prepared.boot_image)
            .run(&mut fastboot)
            .await
            .map_err(|err| anyhow!("fastboot handoff failed: {err}"))?;
        let _ = fastboot.shutdown().await;

        append_status("Boot command sent. Starting smoo host worker...");
        let (tx, mut rx) = futures_channel::mpsc::unbounded();
        spawn_local(async move {
            while let Some(event) = rx.next().await {
                forward_smoo_event(event);
            }
            append_status("smoo event stream closed");
        });
        run_web_smoo_host(initial_device, runtime, WebSmooHostOptions::default(), tx)
            .await
            .context("run web smoo host")
    }

    async fn close_webusb_device(handle: &WebUsbDeviceHandle) {
        let device = handle.device();
        if device.opened() {
            let _ = JsFuture::from(device.close()).await;
        }
    }

    fn forward_smoo_event(event: WebSmooHostEvent) {
        match event {
            WebSmooHostEvent::Phase { phase, detail } => match phase {
                WebSmooHostPhase::WaitingForSmoo => {
                    append_status(format!("smoo waiting: {detail}"))
                }
                WebSmooHostPhase::Serving => append_status(format!("smoo serving: {detail}")),
            },
            WebSmooHostEvent::Log(line) => append_status(format!("smoo: {line}")),
            WebSmooHostEvent::Status {
                active,
                ios_up,
                ios_down,
                bytes_up,
                bytes_down,
            } => {
                tracing::debug!(
                    active,
                    ios_up,
                    ios_down,
                    bytes_up,
                    bytes_down,
                    "smoo host status"
                );
            }
        }
    }

    fn install_click_handler(
        id: &'static str,
        mut handler: impl FnMut(web_sys::Event) + 'static,
    ) -> Result<()> {
        let button = button(id)?;
        let closure =
            Closure::wrap(Box::new(move |event: web_sys::Event| handler(event))
                as Box<dyn FnMut(web_sys::Event)>);
        button
            .add_event_listener_with_callback("click", closure.as_ref().unchecked_ref())
            .map_err(|err| {
                anyhow!(
                    "install click handler for #{id}: {}",
                    js_value_to_string(&err)
                )
            })?;
        closure.forget();
        Ok(())
    }

    fn input_value(id: &'static str) -> Result<String> {
        let value = input(id)?.value().trim().to_string();
        if value.is_empty() {
            bail!("#{id} is empty");
        }
        Ok(value)
    }

    fn optional_input_value(id: &'static str) -> Result<Option<String>> {
        Ok(match input(id)?.value().trim() {
            "" => None,
            value => Some(value.to_string()),
        })
    }

    fn checkbox_checked(id: &'static str) -> Result<bool> {
        Ok(input(id)?.checked())
    }

    fn absolute_url(value: &str) -> Result<String> {
        let value = value.trim();
        if value.is_empty() {
            bail!("URL is empty");
        }
        if let Ok(url) = Url::parse(value) {
            return Ok(url.to_string());
        }

        let href = web_sys::window()
            .ok_or_else(|| anyhow!("window is unavailable"))?
            .location()
            .href()
            .map_err(|err| anyhow!("read page URL: {}", js_value_to_string(&err)))?;
        let base = Url::parse(&href).with_context(|| format!("parse page URL '{href}'"))?;
        base.join(value)
            .map(|url| url.to_string())
            .with_context(|| format!("resolve URL '{value}' relative to '{href}'"))
    }

    fn set_button_enabled(id: &'static str, enabled: bool) {
        if let Ok(button) = button(id) {
            button.set_disabled(!enabled);
        }
    }

    fn set_status(message: impl AsRef<str>) {
        if let Ok(status) = element("status") {
            status.set_text_content(Some(message.as_ref()));
        }
    }

    fn append_status(message: impl AsRef<str>) {
        let message = message.as_ref();
        tracing::info!(message, "example status");
        if let Ok(status) = element("status") {
            let current = status.text_content().unwrap_or_default();
            let next = if current.trim().is_empty() || current.trim() == "idle" {
                message.to_string()
            } else {
                format!("{current}\n{message}")
            };
            status.set_text_content(Some(&next));
        }
    }

    fn button(id: &'static str) -> Result<HtmlButtonElement> {
        element(id)?
            .dyn_into::<HtmlButtonElement>()
            .map_err(|_| anyhow!("#{id} is not a button"))
    }

    fn input(id: &'static str) -> Result<HtmlInputElement> {
        element(id)?
            .dyn_into::<HtmlInputElement>()
            .map_err(|_| anyhow!("#{id} is not an input"))
    }

    fn element(id: &'static str) -> Result<Element> {
        document()?
            .get_element_by_id(id)
            .ok_or_else(|| anyhow!("missing #{id}"))
    }

    fn document() -> Result<Document> {
        web_sys::window()
            .and_then(|window| window.document())
            .ok_or_else(|| anyhow!("document is unavailable"))
    }

    fn init_tracing() {
        set_global_log_level_hint("info");
        let targets = Targets::new()
            .with_default(Level::INFO)
            .with_target("fastboop", Level::INFO)
            .with_target("fastboop_", Level::INFO)
            .with_target("gibblox", Level::INFO)
            .with_target("gibblox_", Level::INFO)
            .with_target("smoo", Level::INFO)
            .with_target("smoo_", Level::INFO);
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

    fn set_global_log_level_hint(level: &str) {
        let _ = js_sys::Reflect::set(
            &js_sys::global(),
            &JsValue::from_str(LOG_LEVEL_HINT_KEY),
            &JsValue::from_str(level),
        );
    }

    fn js_value_to_string(value: &JsValue) -> String {
        js_sys::JSON::stringify(value)
            .ok()
            .and_then(|value| value.as_string())
            .unwrap_or_else(|| format!("{value:?}"))
    }
}
