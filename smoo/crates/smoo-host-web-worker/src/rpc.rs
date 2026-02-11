use crate::api::{HostWorkerConfig, HostWorkerEvent};
use crate::runner::{
    WorkerRuntime, init_runtime, mark_session_stopped, start_session, stop_session,
};
use futures_channel::{mpsc, oneshot};
use gibblox_blockreader_messageport::MessagePortBlockReaderClient;
use js_sys::{Array, Object, Reflect};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    DedicatedWorkerGlobalScope, HtmlScriptElement, MessageChannel, MessageEvent, MessagePort, Usb,
    UsbDevice, Worker, WorkerOptions, WorkerType,
};

use crate::api::HostWorkerState;
use tracing::{debug, info, warn};

const WORKER_NAME: &str = "fastboop-smoo-host-worker";
const READY_CMD: &str = "smoo_host_worker_ready";
const BOOTSTRAP_CMD: &str = "smoo_host_worker_bootstrap";

pub struct HostWorker {
    _worker: Worker,
    rpc_port: MessagePort,
    pending: Arc<Mutex<BTreeMap<u32, oneshot::Sender<Result<JsValue, String>>>>>,
    next_id: Cell<u32>,
    state: Cell<HostWorkerState>,
    events_rx: RefCell<Option<mpsc::UnboundedReceiver<HostWorkerEvent>>>,
    _rpc_on_message: Closure<dyn FnMut(MessageEvent)>,
    _rpc_on_error: Closure<dyn FnMut(web_sys::Event)>,
}

impl HostWorker {
    pub async fn spawn(
        block_source: MessagePortBlockReaderClient,
        cfg: HostWorkerConfig,
    ) -> Result<Self, String> {
        let script_url = append_current_query_to_script_url(current_module_script_url()?);
        let worker_opts = WorkerOptions::new();
        worker_opts.set_type(WorkerType::Module);
        worker_opts.set_name(WORKER_NAME);
        let worker = Worker::new_with_options(&script_url, &worker_opts)
            .map_err(|err| format!("start smoo host worker: {}", js_value_to_string(err)))?;

        wait_for_worker_ready(&worker).await?;

        let channel = MessageChannel::new().map_err(|err| {
            format!(
                "create message channel for smoo host worker: {}",
                js_value_to_string(err)
            )
        })?;
        let rpc_port = channel.port1();
        let bootstrap = Object::new();
        set_prop(
            &bootstrap,
            "cmd",
            JsValue::from_str(BOOTSTRAP_CMD),
            "build smoo host worker bootstrap",
        )?;
        set_prop(
            &bootstrap,
            "port",
            channel.port2().clone().into(),
            "build smoo host worker bootstrap",
        )?;
        let transfer = Array::new();
        transfer.push(channel.port2().as_ref());
        worker
            .post_message_with_transfer(&bootstrap.into(), transfer.as_ref())
            .map_err(|err| {
                format!(
                    "send smoo host worker bootstrap: {}",
                    js_value_to_string(err)
                )
            })?;

        let (event_tx, event_rx) = mpsc::unbounded();
        let pending: Arc<Mutex<BTreeMap<u32, oneshot::Sender<Result<JsValue, String>>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let pending_for_message = pending.clone();
        let event_tx_for_message = event_tx.clone();
        let state = Cell::new(HostWorkerState::Idle);
        let state_for_message = state.clone();

        let rpc_on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();
            if let Some(id) = get_u32_field(&data, "id") {
                let tx = pending_for_message
                    .lock()
                    .ok()
                    .and_then(|mut map| map.remove(&id));
                let Some(tx) = tx else {
                    return;
                };
                if get_bool_field(&data, "ok").unwrap_or(false) {
                    let _ = tx.send(Ok(data));
                } else {
                    let _ = tx.send(Err(get_string_field(&data, "error")
                        .unwrap_or_else(|| "worker rpc command failed".to_string())));
                }
                return;
            }

            let Some(kind) = get_string_field(&data, "event") else {
                return;
            };
            let event = match kind.as_str() {
                "starting" => Some(HostWorkerEvent::Starting),
                "transport_connected" => Some(HostWorkerEvent::TransportConnected),
                "configured" => Some(HostWorkerEvent::Configured),
                "counters" => Some(HostWorkerEvent::Counters {
                    ios_up: get_u64_field(&data, "ios_up").unwrap_or(0),
                    ios_down: get_u64_field(&data, "ios_down").unwrap_or(0),
                    bytes_up: get_u64_field(&data, "bytes_up").unwrap_or(0),
                    bytes_down: get_u64_field(&data, "bytes_down").unwrap_or(0),
                }),
                "session_changed" => Some(HostWorkerEvent::SessionChanged {
                    previous: get_u64_field(&data, "previous").unwrap_or(0),
                    current: get_u64_field(&data, "current").unwrap_or(0),
                }),
                "transport_lost" => {
                    state_for_message.set(HostWorkerState::Idle);
                    Some(HostWorkerEvent::TransportLost)
                }
                "error" => Some(HostWorkerEvent::Error {
                    message: get_string_field(&data, "message")
                        .unwrap_or_else(|| "unknown worker error".to_string()),
                }),
                "stopped" => {
                    state_for_message.set(HostWorkerState::Idle);
                    Some(HostWorkerEvent::Stopped)
                }
                _ => None,
            };
            if let Some(event) = event {
                let _ = event_tx_for_message.unbounded_send(event);
            }
        });
        rpc_port.set_onmessage(Some(rpc_on_message.as_ref().unchecked_ref()));

        let pending_for_error = pending.clone();
        let event_tx_for_error = event_tx.clone();
        let rpc_on_error =
            Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
                if let Ok(mut map) = pending_for_error.lock() {
                    let senders: Vec<_> = std::mem::take(&mut *map).into_values().collect();
                    for sender in senders {
                        let _ = sender.send(Err(format!(
                            "worker message port error: {}",
                            js_value_to_string(event.clone().into())
                        )));
                    }
                }
                let _ = event_tx_for_error.unbounded_send(HostWorkerEvent::Error {
                    message: format!(
                        "worker message port error: {}",
                        js_value_to_string(event.into())
                    ),
                });
            });
        rpc_port.set_onmessageerror(Some(rpc_on_error.as_ref().unchecked_ref()));
        rpc_port.start();

        let host = Self {
            _worker: worker,
            rpc_port,
            pending,
            next_id: Cell::new(1),
            state,
            events_rx: RefCell::new(Some(event_rx)),
            _rpc_on_message: rpc_on_message,
            _rpc_on_error: rpc_on_error,
        };

        let init_payload = Object::new();
        set_prop(
            &init_payload,
            "status_retry_attempts",
            JsValue::from_f64(cfg.status_retry_attempts as f64),
            "build init payload",
        )?;
        set_prop(
            &init_payload,
            "heartbeat_interval_ms",
            JsValue::from_f64(cfg.heartbeat_interval_ms as f64),
            "build init payload",
        )?;
        set_prop(
            &init_payload,
            "size_bytes",
            JsValue::from_str(&cfg.size_bytes.to_string()),
            "build init payload",
        )?;
        set_prop(
            &init_payload,
            "identity",
            JsValue::from_str(&cfg.identity),
            "build init payload",
        )?;
        set_prop(
            &init_payload,
            "interface",
            JsValue::from_f64(cfg.transport.interface as f64),
            "build init payload",
        )?;
        put_optional_u8(&init_payload, "interrupt_in", cfg.transport.interrupt_in)?;
        put_optional_u8(&init_payload, "interrupt_out", cfg.transport.interrupt_out)?;
        put_optional_u8(&init_payload, "bulk_in", cfg.transport.bulk_in)?;
        put_optional_u8(&init_payload, "bulk_out", cfg.transport.bulk_out)?;

        let gibblox_port = block_source.into_port();
        host.request_with_transfer("init", init_payload.into(), Some(gibblox_port.into()))
            .await?;
        Ok(host)
    }

    pub async fn start(&self, device: UsbDevice) -> Result<(), String> {
        if self.state.get() != HostWorkerState::Idle {
            return Err("host worker is not idle".to_string());
        }
        self.request("start", build_device_selector_payload(&device)?.into())
            .await?;
        self.state.set(HostWorkerState::Running);
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), String> {
        if self.state.get() != HostWorkerState::Running {
            return Err("host worker is not running".to_string());
        }
        self.request("stop", Object::new().into()).await?;
        Ok(())
    }

    pub fn state(&self) -> HostWorkerState {
        self.state.get()
    }

    pub fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<HostWorkerEvent>> {
        self.events_rx.borrow_mut().take()
    }

    async fn request(&self, cmd: &str, payload: JsValue) -> Result<JsValue, String> {
        self.request_with_transfer(cmd, payload, None).await
    }

    async fn request_with_transfer(
        &self,
        cmd: &str,
        payload: JsValue,
        transfer: Option<JsValue>,
    ) -> Result<JsValue, String> {
        let id = self.next_id.get();
        self.next_id.set(id.saturating_add(1));
        let msg = Object::new();
        set_prop(
            &msg,
            "id",
            JsValue::from_f64(id as f64),
            "build worker rpc request",
        )?;
        set_prop(
            &msg,
            "cmd",
            JsValue::from_str(cmd),
            "build worker rpc request",
        )?;
        set_prop(&msg, "payload", payload, "build worker rpc request")?;

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| "worker pending map lock poisoned".to_string())?;
            pending.insert(id, tx);
        }

        let post_result = if let Some(transfer) = transfer {
            let arr = Array::new();
            arr.push(&transfer);
            self.rpc_port
                .post_message_with_transferable(&msg.into(), arr.as_ref())
        } else {
            self.rpc_port.post_message(&msg.into())
        };
        if let Err(err) = post_result {
            if let Ok(mut pending) = self.pending.lock() {
                let _ = pending.remove(&id);
            }
            return Err(format!(
                "post worker rpc request: {}",
                js_value_to_string(err)
            ));
        }

        rx.await
            .map_err(|_| "worker rpc response channel closed".to_string())?
    }
}

pub fn run_if_worker() -> bool {
    let Ok(scope) = js_sys::global().dyn_into::<DedicatedWorkerGlobalScope>() else {
        return false;
    };
    if scope.name() != WORKER_NAME {
        return false;
    }
    info!("smoo host worker mode: installing RPC handler");

    let runtime = Rc::new(RefCell::new(WorkerRuntime::new()));
    let runtime_for_handler = runtime.clone();
    let scope_for_handler = scope.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let data = event.data();
        let Some(cmd) = get_string_field(&data, "cmd") else {
            return;
        };
        if cmd != BOOTSTRAP_CMD {
            return;
        }
        let ports = event.ports();
        if ports.length() == 0 {
            let _ = post_error_to_scope(&scope_for_handler, "bootstrap missing RPC MessagePort");
            return;
        }
        let Ok(rpc_port) = ports.get(0).dyn_into::<MessagePort>() else {
            let _ = post_error_to_scope(
                &scope_for_handler,
                "bootstrap transfer[0] is not MessagePort",
            );
            return;
        };
        install_worker_rpc(
            scope_for_handler.clone(),
            runtime_for_handler.clone(),
            rpc_port,
        );
    });
    scope.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();

    let _ = post_ready_to_scope(&scope);
    true
}

fn install_worker_rpc(
    scope: DedicatedWorkerGlobalScope,
    runtime: Rc<RefCell<WorkerRuntime>>,
    rpc_port: MessagePort,
) {
    let port_for_message = rpc_port.clone();
    let runtime_for_message = runtime.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let data = event.data();
        let id = get_u32_field(&data, "id").unwrap_or(0);
        let Some(cmd) = get_string_field(&data, "cmd") else {
            let _ = post_response_err(&port_for_message, id, "missing command");
            return;
        };
        let payload = Reflect::get(&data, &JsValue::from_str("payload")).unwrap_or(JsValue::NULL);
        let ports = event.ports();
        let transfer_port = if ports.length() > 0 {
            ports.get(0).dyn_into::<MessagePort>().ok()
        } else {
            None
        };
        let port_for_task = port_for_message.clone();
        let runtime_for_task = runtime_for_message.clone();
        spawn_local(async move {
            let result = handle_worker_command(
                runtime_for_task,
                cmd,
                payload,
                transfer_port,
                port_for_task.clone(),
            )
            .await;
            match result {
                Ok(()) => {
                    let _ = post_response_ok(&port_for_task, id);
                }
                Err(err) => {
                    let _ = post_response_err(&port_for_task, id, &err);
                }
            }
        });
    });
    rpc_port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(move |_event: web_sys::Event| {});
    rpc_port.set_onmessageerror(Some(on_error.as_ref().unchecked_ref()));
    rpc_port.start();
    on_message.forget();
    on_error.forget();

    let _ = post_ready_to_scope(&scope);
}

async fn handle_worker_command(
    runtime: Rc<RefCell<WorkerRuntime>>,
    cmd: String,
    payload: JsValue,
    transfer_port: Option<MessagePort>,
    event_port: MessagePort,
) -> Result<(), String> {
    debug!(command = %cmd, "smoo host worker received command");
    match cmd.as_str() {
        "init" => {
            let gibblox_port = transfer_port
                .ok_or_else(|| "init command missing gibblox MessagePort transfer".to_string())?;
            let cfg = parse_init_payload(&payload)?;
            init_runtime(&mut runtime.borrow_mut(), cfg, gibblox_port).await
        }
        "start" => {
            let device = resolve_worker_usb_device(&payload).await?;
            let event_port_for_emit = event_port.clone();
            let runtime_for_exit = runtime.clone();
            start_session(
                &mut runtime.borrow_mut(),
                device,
                move |event| {
                    let _ = post_event(&event_port_for_emit, event);
                },
                move || {
                    mark_session_stopped(&mut runtime_for_exit.borrow_mut());
                },
            )
            .await
        }
        "stop" => stop_session(&mut runtime.borrow_mut()),
        _ => Err(format!("unsupported worker command: {cmd}")),
    }
}

fn parse_init_payload(payload: &JsValue) -> Result<HostWorkerConfig, String> {
    let status_retry_attempts = get_u32_field(payload, "status_retry_attempts")
        .ok_or_else(|| "init payload missing status_retry_attempts".to_string())?
        as usize;
    let heartbeat_interval_ms = get_u32_field(payload, "heartbeat_interval_ms")
        .ok_or_else(|| "init payload missing heartbeat_interval_ms".to_string())?;
    let size_bytes = get_u64_field(payload, "size_bytes")
        .ok_or_else(|| "init payload missing size_bytes".to_string())?;
    let identity = get_string_field(payload, "identity")
        .ok_or_else(|| "init payload missing identity".to_string())?;
    let interface = get_u32_field(payload, "interface")
        .ok_or_else(|| "init payload missing interface".to_string())? as u8;

    Ok(HostWorkerConfig {
        transport: smoo_host_webusb::WebUsbTransportConfig {
            interface,
            interrupt_in: get_u32_field(payload, "interrupt_in").map(|v| v as u8),
            interrupt_out: get_u32_field(payload, "interrupt_out").map(|v| v as u8),
            bulk_in: get_u32_field(payload, "bulk_in").map(|v| v as u8),
            bulk_out: get_u32_field(payload, "bulk_out").map(|v| v as u8),
        },
        status_retry_attempts,
        heartbeat_interval_ms,
        size_bytes,
        identity,
    })
}

fn build_device_selector_payload(device: &UsbDevice) -> Result<Object, String> {
    let payload = Object::new();
    set_prop(
        &payload,
        "vid",
        JsValue::from_f64(device.vendor_id() as f64),
        "build start payload",
    )?;
    set_prop(
        &payload,
        "pid",
        JsValue::from_f64(device.product_id() as f64),
        "build start payload",
    )?;
    if let Some(serial) = usb_serial_number(device) {
        set_prop(
            &payload,
            "serial",
            JsValue::from_str(&serial),
            "build start payload",
        )?;
    }
    Ok(payload)
}

async fn resolve_worker_usb_device(payload: &JsValue) -> Result<UsbDevice, String> {
    let vid = get_u32_field(payload, "vid");
    let preferred_pid = get_u32_field(payload, "pid");
    let preferred_serial = get_string_field(payload, "serial");

    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .map_err(|_| "worker global scope unavailable".to_string())?;
    let usb_value = Reflect::get(scope.navigator().as_ref(), &JsValue::from_str("usb"))
        .map_err(|err| format!("navigator.usb unavailable: {}", js_value_to_string(err)))?;
    let usb: Usb = usb_value
        .dyn_into()
        .map_err(|_| "navigator.usb has unexpected type".to_string())?;
    let values = JsFuture::from(usb.get_devices()).await.map_err(|err| {
        format!(
            "navigator.usb.getDevices failed: {}",
            js_value_to_string(err)
        )
    })?;
    let devices = Array::from(&values);

    let mut all_devices: Vec<UsbDevice> = Vec::new();
    let mut vid_matches: Vec<UsbDevice> = Vec::new();
    let mut pid_matches: Vec<UsbDevice> = Vec::new();
    let mut serial_matches: Vec<UsbDevice> = Vec::new();

    for value in devices.iter() {
        let Ok(device) = value.dyn_into::<UsbDevice>() else {
            continue;
        };
        all_devices.push(device.clone());
        if let Some(vid) = vid {
            if device.vendor_id() as u32 == vid {
                vid_matches.push(device.clone());
                if let Some(pid) = preferred_pid {
                    if device.product_id() as u32 == pid {
                        pid_matches.push(device.clone());
                    }
                }
            }
            if let Some(serial) = preferred_serial.as_deref() {
                if usb_serial_number(&device).as_deref() == Some(serial) {
                    serial_matches.push(device.clone());
                }
            }
        }
    }

    if let Some(device) = serial_matches.into_iter().next() {
        return Ok(device);
    }
    if let Some(device) = pid_matches.into_iter().next() {
        return Ok(device);
    }
    if let Some(device) = vid_matches.into_iter().next() {
        return Ok(device);
    }

    if let Some(device) = all_devices.into_iter().next() {
        return Ok(device);
    }

    Err("no authorized usb devices available in worker".to_string())
}

fn usb_serial_number(device: &UsbDevice) -> Option<String> {
    let serial = Reflect::get(device.as_ref(), &JsValue::from_str("serialNumber"))
        .ok()?
        .as_string()?;
    let serial = serial.trim();
    if serial.is_empty() {
        None
    } else {
        Some(serial.to_string())
    }
}

fn wait_for_worker_ready(worker: &Worker) -> impl std::future::Future<Output = Result<(), String>> {
    let (tx, rx) = oneshot::channel::<Result<(), String>>();
    let tx = Rc::new(RefCell::new(Some(tx)));
    let tx_for_message = tx.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let data = event.data();
        if get_string_field(&data, "cmd").as_deref() != Some(READY_CMD) {
            return;
        }
        if let Some(tx) = tx_for_message.borrow_mut().take() {
            let _ = tx.send(Ok(()));
        }
    });
    worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();

    async move {
        rx.await
            .map_err(|_| "worker ready channel closed".to_string())?
    }
}

fn post_event(port: &MessagePort, event: HostWorkerEvent) -> Result<(), String> {
    let value = Object::new();
    set_prop(
        &value,
        "event",
        JsValue::from_str(event.event_name()),
        "build worker event",
    )?;
    match event {
        HostWorkerEvent::Counters {
            ios_up,
            ios_down,
            bytes_up,
            bytes_down,
        } => {
            set_prop(
                &value,
                "ios_up",
                JsValue::from_str(&ios_up.to_string()),
                "build worker event",
            )?;
            set_prop(
                &value,
                "ios_down",
                JsValue::from_str(&ios_down.to_string()),
                "build worker event",
            )?;
            set_prop(
                &value,
                "bytes_up",
                JsValue::from_str(&bytes_up.to_string()),
                "build worker event",
            )?;
            set_prop(
                &value,
                "bytes_down",
                JsValue::from_str(&bytes_down.to_string()),
                "build worker event",
            )?;
        }
        HostWorkerEvent::SessionChanged { previous, current } => {
            set_prop(
                &value,
                "previous",
                JsValue::from_str(&previous.to_string()),
                "build worker event",
            )?;
            set_prop(
                &value,
                "current",
                JsValue::from_str(&current.to_string()),
                "build worker event",
            )?;
        }
        HostWorkerEvent::Error { message } => {
            set_prop(
                &value,
                "message",
                JsValue::from_str(&message),
                "build worker event",
            )?;
        }
        _ => {}
    }
    port.post_message(&value.into())
        .map_err(|err| format!("post worker event: {}", js_value_to_string(err)))
}

fn post_response_ok(port: &MessagePort, id: u32) -> Result<(), String> {
    let response = Object::new();
    set_prop(
        &response,
        "id",
        JsValue::from_f64(id as f64),
        "build worker response",
    )?;
    set_prop(
        &response,
        "ok",
        JsValue::from_bool(true),
        "build worker response",
    )?;
    port.post_message(&response.into())
        .map_err(|err| format!("post worker response: {}", js_value_to_string(err)))
}

fn post_response_err(port: &MessagePort, id: u32, message: &str) -> Result<(), String> {
    let response = Object::new();
    set_prop(
        &response,
        "id",
        JsValue::from_f64(id as f64),
        "build worker response",
    )?;
    set_prop(
        &response,
        "ok",
        JsValue::from_bool(false),
        "build worker response",
    )?;
    set_prop(
        &response,
        "error",
        JsValue::from_str(message),
        "build worker response",
    )?;
    port.post_message(&response.into())
        .map_err(|err| format!("post worker response: {}", js_value_to_string(err)))
}

fn post_ready_to_scope(scope: &DedicatedWorkerGlobalScope) -> Result<(), String> {
    let response = Object::new();
    set_prop(
        &response,
        "cmd",
        JsValue::from_str(READY_CMD),
        "build worker ready response",
    )?;
    scope
        .post_message(&response.into())
        .map_err(|err| format!("post worker ready response: {}", js_value_to_string(err)))
}

fn post_error_to_scope(scope: &DedicatedWorkerGlobalScope, message: &str) -> Result<(), String> {
    warn!(%message, "smoo host worker bootstrap error");
    let response = Object::new();
    set_prop(
        &response,
        "cmd",
        JsValue::from_str("error"),
        "build worker error response",
    )?;
    set_prop(
        &response,
        "error",
        JsValue::from_str(message),
        "build worker error response",
    )?;
    scope
        .post_message(&response.into())
        .map_err(|err| format!("post worker error response: {}", js_value_to_string(err)))
}

fn current_module_script_url() -> Result<String, String> {
    let window = web_sys::window().ok_or_else(|| "window is unavailable".to_string())?;
    let document = window
        .document()
        .ok_or_else(|| "document is unavailable".to_string())?;
    let scripts = document.scripts();

    let mut candidate = None;
    for index in 0..scripts.length() {
        let Some(script) = scripts.item(index) else {
            continue;
        };
        let Ok(script) = script.dyn_into::<HtmlScriptElement>() else {
            continue;
        };
        let src = script.src();
        if src.ends_with(".js") && src.contains("fastboop-web") {
            candidate = Some(src);
        }
    }

    candidate.ok_or_else(|| "failed to determine fastboop web module script URL".to_string())
}

fn append_current_query_to_script_url(mut script_url: String) -> String {
    if script_url.contains('?') {
        return script_url;
    }
    if let Some(level) = global_log_level_hint_text() {
        script_url.push_str("?log=");
        script_url.push_str(&level);
        return script_url;
    }
    let Some(window) = web_sys::window() else {
        return script_url;
    };
    let Ok(location) = Reflect::get(window.as_ref(), &JsValue::from_str("location")) else {
        return script_url;
    };
    let Ok(search_value) = Reflect::get(&location, &JsValue::from_str("search")) else {
        return script_url;
    };
    let Some(search) = search_value.as_string() else {
        return script_url;
    };
    if search.is_empty() {
        return script_url;
    }
    script_url.push_str(&search);
    script_url
}

fn global_log_level_hint_text() -> Option<String> {
    let global = js_sys::global();
    let value = Reflect::get(&global, &JsValue::from_str("__FASTBOOP_LOG_LEVEL")).ok()?;
    value.as_string()
}

fn put_optional_u8(obj: &Object, key: &str, value: Option<u8>) -> Result<(), String> {
    if let Some(value) = value {
        set_prop(
            obj,
            key,
            JsValue::from_f64(value as f64),
            "build init payload",
        )
    } else {
        Ok(())
    }
}

fn set_prop(target: &Object, key: &str, value: JsValue, context: &str) -> Result<(), String> {
    Reflect::set(target.as_ref(), &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|err| format!("{context}: {}", js_value_to_string(err)))
}

fn get_string_field(target: &JsValue, key: &str) -> Option<String> {
    Reflect::get(target, &JsValue::from_str(key))
        .ok()
        .and_then(|value| value.as_string())
}

fn get_u32_field(target: &JsValue, key: &str) -> Option<u32> {
    Reflect::get(target, &JsValue::from_str(key))
        .ok()
        .and_then(|value| value.as_f64())
        .and_then(f64_to_u32)
}

fn get_u64_field(target: &JsValue, key: &str) -> Option<u64> {
    let value = Reflect::get(target, &JsValue::from_str(key)).ok()?;
    if let Some(text) = value.as_string() {
        return text.parse::<u64>().ok();
    }
    value.as_f64().and_then(f64_to_u64)
}

fn get_bool_field(target: &JsValue, key: &str) -> Option<bool> {
    Reflect::get(target, &JsValue::from_str(key))
        .ok()
        .and_then(|value| value.as_bool())
}

fn f64_to_u32(value: f64) -> Option<u32> {
    if value.is_finite() && value >= 0.0 && value <= u32::MAX as f64 {
        Some(value as u32)
    } else {
        None
    }
}

fn f64_to_u64(value: f64) -> Option<u64> {
    if value.is_finite() && value >= 0.0 && value <= u64::MAX as f64 {
        Some(value as u64)
    } else {
        None
    }
}

fn js_value_to_string(value: JsValue) -> String {
    js_sys::JSON::stringify(&value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}
