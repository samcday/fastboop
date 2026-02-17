use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Reflect};
#[cfg(target_arch = "wasm32")]
use std::cell::Cell;
#[cfg(target_arch = "wasm32")]
use std::collections::VecDeque;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::closure::Closure;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{
    ReadableStreamDefaultReader, Serial, SerialOptions, SerialPort, SerialPortFilter,
    SerialPortInfo, SerialPortRequestOptions,
};

#[cfg(target_arch = "wasm32")]
use super::device_boot::spawn_detached;

#[cfg(target_arch = "wasm32")]
const SERIAL_LOG_MAX_LINES: usize = 2000;
#[cfg(target_arch = "wasm32")]
const SERIAL_LOG_MAX_BYTES: usize = 512 * 1024;
#[cfg(target_arch = "wasm32")]
const SERIAL_ACCESS_DENIED_TOKEN: &str = "Failed to open serial port.";
#[cfg(target_arch = "wasm32")]
const DEVICE_PERMISSIONS_URL: &str = "https://fastboop.win/device-permissions";

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct SerialLogBuffer {
    lines: VecDeque<String>,
    pending: String,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
}

#[cfg(target_arch = "wasm32")]
impl SerialLogBuffer {
    fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            pending: String::new(),
            bytes: 0,
            max_lines,
            max_bytes,
        }
    }

    fn clear(&mut self) {
        self.lines.clear();
        self.pending.clear();
        self.bytes = 0;
    }

    fn push_status(&mut self, message: impl Into<String>) {
        self.push_line(format!("[host] {}", message.into()));
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        self.pending.push_str(&normalized);

        while let Some(newline) = self.pending.find('\n') {
            let mut line = self.pending.drain(..=newline).collect::<String>();
            if line.ends_with('\n') {
                line.pop();
            }
            self.push_line(line);
        }

        if self.pending.len() > 4096 {
            let line = std::mem::take(&mut self.pending);
            self.push_line(line);
        }
    }

    fn push_line(&mut self, line: impl Into<String>) {
        let line = line.into();
        self.bytes = self.bytes.saturating_add(line.len() + 1);
        self.lines.push_back(line);

        while self.lines.len() > self.max_lines || self.bytes > self.max_bytes {
            let Some(front) = self.lines.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(front.len() + 1);
        }
    }

    fn render_text(&self) -> String {
        if self.lines.is_empty() && self.pending.is_empty() {
            return String::new();
        }
        let mut rendered = String::with_capacity(self.bytes + self.pending.len());
        for line in &self.lines {
            rendered.push_str(line);
            rendered.push('\n');
        }
        if !self.pending.is_empty() {
            rendered.push_str(self.pending.as_str());
        }
        rendered
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, PartialEq)]
enum WebSerialState {
    Idle,
    Connecting,
    Connected,
    Disconnected,
    Error(String),
}

#[cfg(target_arch = "wasm32")]
#[component]
pub fn SerialLogPanel(device_vid: u16, device_pid: u16) -> Element {
    let state = use_signal(|| WebSerialState::Idle);
    let logs = use_signal(|| SerialLogBuffer::new(SERIAL_LOG_MAX_LINES, SERIAL_LOG_MAX_BYTES));

    let stop_flag = use_signal(|| Option::<Rc<Cell<bool>>>::None);
    let active_port = use_signal(|| Option::<SerialPort>::None);
    let serial_api = use_signal(|| Option::<Serial>::None);
    let connect_listener = use_signal(|| Option::<Closure<dyn FnMut(JsValue)>>::None);
    let access_denied_hint = use_signal(|| false);
    let initialized = use_signal(|| false);

    {
        let mut initialized = initialized;
        let mut serial_api = serial_api;
        let mut connect_listener = connect_listener;
        let mut state = state;
        let mut logs = logs;
        let stop_flag = stop_flag;
        let active_port = active_port;
        let access_denied_hint = access_denied_hint;
        use_effect(move || {
            if initialized() {
                return;
            }
            initialized.set(true);

            let serial = match navigator_serial() {
                Ok(serial) => serial,
                Err(err) => {
                    state.set(WebSerialState::Error(err.to_string()));
                    logs.write()
                        .push_status(format!("WebSerial unavailable: {err}"));
                    return;
                }
            };
            serial_api.set(Some(serial.clone()));

            let state_for_event = state;
            let mut logs_for_event = logs;
            let stop_flag_for_event = stop_flag;
            let active_port_for_event = active_port;
            let access_denied_for_event = access_denied_hint;
            let listener = Closure::<dyn FnMut(JsValue)>::new(move |event: JsValue| {
                let Some(port) = serial_connect_event_port(&event) else {
                    return;
                };
                if !serial_port_matches_device(&port, device_vid, device_pid) {
                    return;
                }
                if matches!(
                    state_for_event(),
                    WebSerialState::Connecting | WebSerialState::Connected
                ) {
                    return;
                }
                logs_for_event
                    .write()
                    .push_status("Matching serial gadget connected; opening stream.");
                start_serial_stream(
                    port,
                    state_for_event,
                    logs_for_event,
                    stop_flag_for_event,
                    active_port_for_event,
                    access_denied_for_event,
                );
            });
            let _ = serial
                .add_event_listener_with_callback("connect", listener.as_ref().unchecked_ref());
            connect_listener.set(Some(listener));

            let state_for_ports = state;
            let mut logs_for_ports = logs;
            let stop_flag_for_ports = stop_flag;
            let active_port_for_ports = active_port;
            let access_denied_for_ports = access_denied_hint;
            spawn_detached(async move {
                let Ok(Some(port)) =
                    matching_authorized_port(&serial, device_vid, device_pid).await
                else {
                    return;
                };
                if matches!(
                    state_for_ports(),
                    WebSerialState::Connecting | WebSerialState::Connected
                ) {
                    return;
                }
                logs_for_ports
                    .write()
                    .push_status("Found previously-authorized serial gadget; opening stream.");
                start_serial_stream(
                    port,
                    state_for_ports,
                    logs_for_ports,
                    stop_flag_for_ports,
                    active_port_for_ports,
                    access_denied_for_ports,
                );
            });
        });
    }

    {
        let mut stop_flag = stop_flag;
        let mut active_port = active_port;
        let mut serial_api = serial_api;
        let mut connect_listener = connect_listener;
        use_drop(move || {
            if let Some(flag) = stop_flag.write().take() {
                flag.set(true);
            }
            if let Some(port) = active_port.write().take() {
                spawn_detached(async move {
                    let _ = close_serial_port(&port).await;
                });
            }
            if let (Some(serial), Some(listener)) =
                (serial_api.write().take(), connect_listener.write().take())
            {
                let _ = serial.remove_event_listener_with_callback(
                    "connect",
                    listener.as_ref().unchecked_ref(),
                );
            }
        });
    }

    let on_connect = {
        let state = state;
        let mut logs = logs;
        let serial_api = serial_api;
        move |_| {
            if matches!(
                state(),
                WebSerialState::Connecting | WebSerialState::Connected
            ) {
                return;
            }
            logs.write().push_status("Requesting serial port...");

            let mut state_for_task = state;
            let mut logs_for_task = logs;
            let stop_flag_for_task = stop_flag;
            let active_port_for_task = active_port;
            let access_denied_for_task = access_denied_hint;
            let serial = serial_api()
                .or_else(|| navigator_serial().ok())
                .ok_or_else(|| anyhow::anyhow!("WebSerial API unavailable"));
            spawn_detached(async move {
                let serial = match serial {
                    Ok(serial) => serial,
                    Err(err) => {
                        state_for_task.set(WebSerialState::Error(err.to_string()));
                        logs_for_task.write().push_status(err.to_string());
                        return;
                    }
                };

                let port = match request_serial_port(&serial, device_vid, device_pid).await {
                    Ok(port) => port,
                    Err(err) => {
                        logs_for_task
                            .write()
                            .push_status(format!("Serial port request failed: {err}"));
                        state_for_task.set(WebSerialState::Error(err.to_string()));
                        return;
                    }
                };
                start_serial_stream(
                    port,
                    state_for_task,
                    logs_for_task,
                    stop_flag_for_task,
                    active_port_for_task,
                    access_denied_for_task,
                );
            });
        }
    };

    let on_disconnect = {
        let mut state = state;
        let mut stop_flag = stop_flag;
        let mut active_port = active_port;
        let mut logs = logs;
        move |_| {
            if let Some(flag) = stop_flag.write().take() {
                flag.set(true);
            }
            if let Some(port) = active_port.write().take() {
                spawn_detached(async move {
                    let _ = close_serial_port(&port).await;
                });
            }
            logs.write().push_status("Disconnect requested.");
            state.set(WebSerialState::Disconnected);
        }
    };

    let mut logs_for_clear = logs;
    let on_clear = move |_: MouseEvent| {
        logs_for_clear.write().clear();
    };

    let status_text = match state() {
        WebSerialState::Idle => "Idle",
        WebSerialState::Connecting => "Connecting",
        WebSerialState::Connected => "Connected",
        WebSerialState::Disconnected => "Disconnected",
        WebSerialState::Error(_) => "Error",
    };
    let status_class = match state() {
        WebSerialState::Connected => "serial-logs__status serial-logs__status--ok",
        WebSerialState::Error(_) => "serial-logs__status serial-logs__status--err",
        WebSerialState::Connecting => "serial-logs__status serial-logs__status--warn",
        _ => "serial-logs__status",
    };
    let error_message = match state() {
        WebSerialState::Error(message) => Some(message),
        _ => None,
    };
    let show_access_denied_hint = access_denied_hint();
    let rendered_logs = logs.read().render_text();

    rsx! {
        div { class: "serial-logs",
            div { class: "serial-logs__header",
                p { class: "serial-logs__title", "Device serial output" }
                p { class: status_class, "{status_text}" }
            }
            p { class: "serial-logs__hint", "Use this stream for stage0 kernel and early userspace logs over CDC-ACM." }

            if matches!(state(), WebSerialState::Idle | WebSerialState::Disconnected | WebSerialState::Error(_)) {
                button {
                    class: "serial-logs__connect",
                    onclick: on_connect,
                    "Connect for logs"
                }

                if show_access_denied_hint {
                    p { class: "serial-logs__error",
                        "Chrome can see the serial gadget but cannot open it (host access denied). Configure host permissions and retry. "
                        a {
                            href: DEVICE_PERMISSIONS_URL,
                            target: "_blank",
                            rel: "noopener noreferrer",
                            "Open permission guide"
                        }
                    }
                }
            }

            if matches!(state(), WebSerialState::Connecting) {
                p { class: "serial-logs__hint", "Waiting for browser serial permission..." }
            }

            if matches!(state(), WebSerialState::Connected | WebSerialState::Connecting) {
                button {
                    class: "serial-logs__disconnect",
                    onclick: on_disconnect,
                    "Disconnect"
                }
            }

            if let Some(error_message) = error_message {
                p { class: "serial-logs__error", "{error_message}" }
            }

            div { class: "serial-logs__actions",
                button { class: "serial-logs__clear", onclick: on_clear, "Clear" }
            }

            pre { class: "serial-logs__output", "{rendered_logs}" }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[component]
pub fn SerialLogPanel(device_vid: u16, device_pid: u16) -> Element {
    let _ = (device_vid, device_pid);
    rsx! {
        div { class: "serial-logs",
            div { class: "serial-logs__header",
                p { class: "serial-logs__title", "Device serial output" }
                p { class: "serial-logs__status", "Unavailable" }
            }
            p { class: "serial-logs__hint", "WebSerial only works in browser wasm builds." }
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn request_serial_port(
    serial: &Serial,
    device_vid: u16,
    device_pid: u16,
) -> anyhow::Result<SerialPort> {
    let filters = Array::new();
    let filter = SerialPortFilter::new();
    filter.set_usb_vendor_id(device_vid);
    filter.set_usb_product_id(device_pid);
    filters.push(filter.as_ref());

    let options = SerialPortRequestOptions::new();
    options.set_filters(filters.as_ref());
    let value = JsFuture::from(serial.request_port_with_options(&options))
        .await
        .map_err(|err| anyhow::anyhow!("requestPort failed: {err:?}"))?;
    let port = value
        .dyn_into::<SerialPort>()
        .map_err(|_| anyhow::anyhow!("requestPort did not return SerialPort"))?;
    if !serial_port_matches_device(&port, device_vid, device_pid) {
        return Err(anyhow::anyhow!(
            "requestPort returned a serial device that did not match {device_vid:04x}:{device_pid:04x}"
        ));
    }
    Ok(port)
}

#[cfg(target_arch = "wasm32")]
async fn open_serial_port(port: &SerialPort) -> anyhow::Result<()> {
    let options = SerialOptions::new(115_200);
    JsFuture::from(port.open(&options))
        .await
        .map_err(|err| anyhow::anyhow!("open() failed: {err:?}"))?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn close_serial_port(port: &SerialPort) -> anyhow::Result<()> {
    JsFuture::from(port.close())
        .await
        .map_err(|err| anyhow::anyhow!("close() failed: {err:?}"))?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn stream_serial_port(
    port: &SerialPort,
    stop: Rc<Cell<bool>>,
    logs: &mut Signal<SerialLogBuffer>,
) -> anyhow::Result<()> {
    let reader = ReadableStreamDefaultReader::new(&port.readable())
        .map_err(|err| anyhow::anyhow!("failed to create stream reader: {err:?}"))?;
    loop {
        if stop.get() {
            break;
        }

        let value = JsFuture::from(reader.read())
            .await
            .map_err(|err| anyhow::anyhow!("reader.read() failed: {err:?}"))?;
        let done = Reflect::get(value.as_ref(), &JsValue::from_str("done"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if done {
            break;
        }

        let chunk = Reflect::get(value.as_ref(), &JsValue::from_str("value"))
            .map_err(|err| anyhow::anyhow!("reader result missing value: {err:?}"))?;
        if chunk.is_null() || chunk.is_undefined() {
            continue;
        }
        let bytes = js_sys::Uint8Array::new(chunk.as_ref()).to_vec();
        if !bytes.is_empty() {
            logs.write().push_bytes(bytes.as_slice());
        }
    }
    let _ = JsFuture::from(reader.cancel()).await;
    reader.release_lock();
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn start_serial_stream(
    port: SerialPort,
    mut state: Signal<WebSerialState>,
    mut logs: Signal<SerialLogBuffer>,
    mut stop_flag: Signal<Option<Rc<Cell<bool>>>>,
    mut active_port: Signal<Option<SerialPort>>,
    mut access_denied_hint: Signal<bool>,
) {
    if let Some(flag) = stop_flag.write().take() {
        flag.set(true);
    }
    if let Some(existing_port) = active_port.write().take() {
        spawn_detached(async move {
            let _ = close_serial_port(&existing_port).await;
        });
    }

    let stop = Rc::new(Cell::new(false));
    stop_flag.set(Some(stop.clone()));
    active_port.set(Some(port.clone()));
    access_denied_hint.set(false);
    state.set(WebSerialState::Connecting);

    spawn_detached(async move {
        if let Err(err) = open_serial_port(&port).await {
            let message = err.to_string();
            logs.write()
                .push_status(format!("Failed to open serial port: {message}"));
            state.set(WebSerialState::Error(message.clone()));
            if message.contains(SERIAL_ACCESS_DENIED_TOKEN) {
                access_denied_hint.set(true);
            }
            active_port.write().take();
            stop_flag.write().take();
            return;
        }

        logs.write()
            .push_status("Connected. Streaming device logs.");
        state.set(WebSerialState::Connected);

        let stream_result = stream_serial_port(&port, stop.clone(), &mut logs).await;
        let _ = close_serial_port(&port).await;
        active_port.write().take();
        stop_flag.write().take();

        if stop.get() {
            logs.write().push_status("Disconnected.");
            state.set(WebSerialState::Disconnected);
            return;
        }

        match stream_result {
            Ok(()) => {
                logs.write().push_status("Serial stream closed by device.");
                state.set(WebSerialState::Disconnected);
            }
            Err(err) => {
                logs.write()
                    .push_status(format!("Serial stream error: {err}"));
                state.set(WebSerialState::Error(err.to_string()));
            }
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn serial_connect_event_port(event: &JsValue) -> Option<SerialPort> {
    Reflect::get(event, &JsValue::from_str("port"))
        .ok()?
        .dyn_into::<SerialPort>()
        .ok()
}

#[cfg(target_arch = "wasm32")]
fn serial_port_matches_device(port: &SerialPort, device_vid: u16, device_pid: u16) -> bool {
    let info: SerialPortInfo = port.get_info();
    info.get_usb_vendor_id() == Some(device_vid) && info.get_usb_product_id() == Some(device_pid)
}

#[cfg(target_arch = "wasm32")]
async fn matching_authorized_port(
    serial: &Serial,
    device_vid: u16,
    device_pid: u16,
) -> anyhow::Result<Option<SerialPort>> {
    let values = JsFuture::from(serial.get_ports())
        .await
        .map_err(|err| anyhow::anyhow!("navigator.serial.getPorts failed: {err:?}"))?;
    let ports = Array::from(&values);
    for value in ports.iter() {
        let Ok(port) = value.dyn_into::<SerialPort>() else {
            continue;
        };
        if serial_port_matches_device(&port, device_vid, device_pid) {
            return Ok(Some(port));
        }
    }
    Ok(None)
}

#[cfg(target_arch = "wasm32")]
fn navigator_serial() -> anyhow::Result<Serial> {
    let window = web_sys::window().ok_or_else(|| anyhow::anyhow!("window unavailable"))?;
    Reflect::get(window.navigator().as_ref(), &JsValue::from_str("serial"))
        .map_err(|err| anyhow::anyhow!("navigator.serial unavailable: {err:?}"))?
        .dyn_into::<Serial>()
        .map_err(|_| anyhow::anyhow!("navigator.serial has unexpected type"))
}
