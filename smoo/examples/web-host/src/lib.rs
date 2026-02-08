#[cfg(not(target_arch = "wasm32"))]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(target_arch = "wasm32")]
mod wasm_host {
    use futures_util::future::{AbortHandle, Abortable};
    use smoo_host_blocksource_http::HttpBlockSource;
    use smoo_host_core::{
        BlockSource, BlockSourceHandle, CountingTransport, HostIoPumpHandle, SmooHost,
        TransportCounters, control::ConfigExportsV0, heartbeat_once, register_export,
        start_host_io_pump,
    };
    use smoo_host_webusb::{WebUsbTransport, WebUsbTransportConfig};
    use std::{cell::RefCell, collections::BTreeMap, io, rc::Rc, sync::OnceLock};
    use tracing::{Level, info, warn};
    use tracing_subscriber::{
        filter::LevelFilter,
        fmt::{self, format},
        layer::SubscriberExt,
        prelude::*,
        registry::Registry,
        reload,
    };
    use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
    use wasm_bindgen::JsCast;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::spawn_local;
    use web_sys::window;

    type CountingWebUsbTransport = CountingTransport<WebUsbTransport>;

    #[wasm_bindgen]
    pub fn set_log_sink(callback: js_sys::Function) {
        init_tracing();
        LOG_SINK.with(|cell| {
            *cell.borrow_mut() = Some(callback);
        });
    }

    #[wasm_bindgen]
    pub fn set_log_level(level: String) -> Result<(), JsValue> {
        init_tracing();
        let filter = parse_level_filter(&level)?;
        let handle = TRACING_HANDLE
            .get()
            .ok_or_else(|| JsValue::from_str("tracing not initialised"))?;
        handle
            .filter
            .modify(|current| *current = filter)
            .map_err(|err| JsValue::from_str(&format!("update log level: {err}")))?;
        Ok(())
    }

    #[wasm_bindgen]
    pub fn counters_snapshot() -> Option<CounterSnapshot> {
        ACTIVE_COUNTERS.with(|cell| {
            cell.borrow().as_ref().map(|counters| {
                let snap = counters.snapshot();
                CounterSnapshot {
                    bytes_up: snap.bytes_up,
                    bytes_down: snap.bytes_down,
                }
            })
        })
    }

    #[wasm_bindgen]
    pub struct CounterSnapshot {
        bytes_up: u64,
        bytes_down: u64,
    }

    #[wasm_bindgen]
    impl CounterSnapshot {
        pub fn bytes_up(&self) -> u64 {
            self.bytes_up
        }

        pub fn bytes_down(&self) -> u64 {
            self.bytes_down
        }
    }

    #[wasm_bindgen]
    pub async fn start(device: web_sys::UsbDevice, backing_url: String) -> Result<(), JsValue> {
        console_error_panic_hook::set_once();
        init_tracing();
        set_active_counters(None);

        let url = url::Url::parse(&backing_url)
            .map_err(|err| JsValue::from_str(&format!("parse backing URL: {err}")))?;
        let block_size = 512u32;
        let source = HttpBlockSource::new(url.clone(), block_size)
            .await
            .map_err(to_js_err)?;
        let total_blocks = source.total_blocks().await.map_err(to_js_err)?;
        let size_bytes = total_blocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| JsValue::from_str("backing size overflow"))?;

        let mut sources = BTreeMap::new();
        let mut entries = Vec::new();
        let identity = format!("http:{url}");
        register_export(
            &mut sources,
            &mut entries,
            BlockSourceHandle::new(source, identity.clone()),
            identity,
            block_size,
            size_bytes,
        )
        .map_err(to_js_err)?;
        let payload = ConfigExportsV0::from_slice(&entries)
            .map_err(|err| JsValue::from_str(&format!("build CONFIG_EXPORTS: {err:?}")))?;

        let transport_config = WebUsbTransportConfig::default();
        let state = Rc::new(RefCell::new(Some(
            start_session(
                device.clone(),
                transport_config,
                sources.clone(),
                payload.clone(),
            )
            .await?,
        )));
        let restart_in_progress = Rc::new(RefCell::new(false));
        let next_restart_ms = Rc::new(RefCell::new(0.0));
        schedule_host_loop(
            state,
            device,
            sources,
            payload,
            transport_config,
            restart_in_progress,
            next_restart_ms,
        )?;
        Ok(())
    }

    #[derive(Clone)]
    struct TracingHandle {
        filter: reload::Handle<LevelFilter, Registry>,
    }

    thread_local! {
        static ACTIVE_COUNTERS: RefCell<Option<TransportCounters>> = RefCell::new(None);
        static LOG_SINK: RefCell<Option<js_sys::Function>> = RefCell::new(None);
    }

    static TRACING_HANDLE: OnceLock<TracingHandle> = OnceLock::new();

    struct HostState {
        host: SmooHost<BlockSourceHandle>,
        control: CountingWebUsbTransport,
        pump_handle: HostIoPumpHandle,
        pump_abort: AbortHandle,
        session_id: u64,
        last_heartbeat_ms: f64,
    }

    async fn start_session(
        device: web_sys::UsbDevice,
        transport_config: WebUsbTransportConfig,
        sources: BTreeMap<u32, BlockSourceHandle>,
        payload: ConfigExportsV0,
    ) -> Result<HostState, JsValue> {
        let transport = WebUsbTransport::new(device, transport_config)
            .await
            .map_err(to_js_err)?;
        let counting = CountingTransport::new(transport);
        let control = counting.clone();
        let counters = counting.counters();
        set_active_counters(Some(counters));

        let (pump_handle, request_rx, pump_task) = start_host_io_pump(counting);
        let (abort_handle, abort_reg) = AbortHandle::new_pair();
        let pump_abort = abort_handle.clone();
        let pump_future = Abortable::new(pump_task, abort_reg);
        spawn_local(async move {
            match pump_future.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!(%err, "pump exited");
                }
                Err(_) => {
                    info!("pump task aborted");
                }
            }
        });

        let mut host = SmooHost::new(pump_handle.clone(), request_rx, sources);
        let ident = host.setup(&control).await.map_err(to_js_err)?;
        info!(version = %format!("{}.{}", ident.major, ident.minor), "IDENT");
        host.configure_exports_v0(&control, &payload)
            .await
            .map_err(to_js_err)?;

        let status = heartbeat_once(&control)
            .await
            .map_err(|err| JsValue::from_str(&format!("initial heartbeat failed: {err}")))?;
        info!(
            session = format_args!("0x{:016x}", status.session_id),
            exports = status.export_count,
            "SMOO_STATUS ok"
        );

        Ok(HostState {
            host,
            control,
            pump_handle,
            pump_abort,
            session_id: status.session_id,
            last_heartbeat_ms: now_ms().unwrap_or(0.0),
        })
    }

    fn teardown_state(state: &mut Option<HostState>) {
        if let Some(ctx) = state.take() {
            set_active_counters(None);
            let pump = ctx.pump_handle.clone();
            let abort = ctx.pump_abort;
            spawn_local(async move {
                let _ = pump.shutdown().await;
            });
            abort.abort();
        }
    }

    fn spawn_session_restart(
        state: Rc<RefCell<Option<HostState>>>,
        restart_flag: Rc<RefCell<bool>>,
        next_restart_ms: Rc<RefCell<f64>>,
        device: web_sys::UsbDevice,
        sources: BTreeMap<u32, BlockSourceHandle>,
        payload: ConfigExportsV0,
        transport_config: WebUsbTransportConfig,
    ) {
        if *restart_flag.borrow() {
            return;
        }
        *restart_flag.borrow_mut() = true;
        if let Some(now) = now_ms() {
            *next_restart_ms.borrow_mut() = now + 1000.0;
        }
        let restart_flag_clone = restart_flag.clone();
        let next_restart_ms_clone = next_restart_ms.clone();
        spawn_local(async move {
            teardown_state(&mut state.borrow_mut());
            match start_session(device, transport_config, sources, payload).await {
                Ok(new_state) => {
                    state.replace(Some(new_state));
                }
                Err(err) => {
                    warn!(?err, "session restart failed");
                }
            }
            *restart_flag_clone.borrow_mut() = false;
            if state.borrow().is_none() {
                if let Some(now) = now_ms() {
                    *next_restart_ms_clone.borrow_mut() = now + 1000.0;
                }
            }
        });
    }

    fn init_tracing() {
        let _ = TRACING_HANDLE.get_or_init(|| {
            let (filter_layer, filter_handle) = reload::Layer::new(LevelFilter::INFO);
            let wasm_layer = WASMLayer::new(
                WASMLayerConfigBuilder::default()
                    .set_max_level(Level::TRACE)
                    .set_report_logs_in_timings(true)
                    .build(),
            );
            let fmt_layer = fmt::layer()
                .event_format(
                    format::format()
                        .compact()
                        .with_level(true)
                        .with_target(false)
                        .without_time(),
                )
                .with_ansi(false)
                .with_writer(UiMakeWriter);

            Registry::default()
                .with(filter_layer)
                .with(wasm_layer)
                .with(fmt_layer)
                .init();

            TracingHandle {
                filter: filter_handle,
            }
        });
    }

    fn parse_level_filter(level: &str) -> Result<LevelFilter, JsValue> {
        match level.to_ascii_lowercase().as_str() {
            "trace" => Ok(LevelFilter::TRACE),
            "debug" => Ok(LevelFilter::DEBUG),
            "info" => Ok(LevelFilter::INFO),
            "warn" | "warning" => Ok(LevelFilter::WARN),
            "error" => Ok(LevelFilter::ERROR),
            other => Err(JsValue::from_str(&format!("unknown log level '{other}'"))),
        }
    }

    fn set_active_counters(counters: Option<TransportCounters>) {
        ACTIVE_COUNTERS.with(|cell| {
            *cell.borrow_mut() = counters;
        });
    }

    fn schedule_host_loop(
        state: Rc<RefCell<Option<HostState>>>,
        device: web_sys::UsbDevice,
        sources: BTreeMap<u32, BlockSourceHandle>,
        payload: ConfigExportsV0,
        transport_config: WebUsbTransportConfig,
        restart_in_progress: Rc<RefCell<bool>>,
        next_restart_ms: Rc<RefCell<f64>>,
    ) -> Result<(), JsValue> {
        let win = window().ok_or_else(|| JsValue::from_str("window unavailable"))?;
        let cb_state = state.clone();
        let raf_cb: Rc<RefCell<Option<Closure<dyn FnMut(f64)>>>> = Rc::new(RefCell::new(None));
        let raf_cb_clone = raf_cb.clone();
        *raf_cb_clone.borrow_mut() = Some(Closure::wrap(Box::new(move |_ts: f64| {
            let inner_state = cb_state.clone();
            let restart_flag = restart_in_progress.clone();
            let next_restart_ms = next_restart_ms.clone();
            let device = device.clone();
            let sources = sources.clone();
            let payload = payload.clone();
            let raf_cb_inner = raf_cb.clone();
            spawn_local(async move {
                let now = now_ms();
                let mut heartbeat = None;
                let mut request_restart = false;
                {
                    let mut guard = inner_state.borrow_mut();
                    if guard.is_none() && !*restart_flag.borrow() {
                        if now.map_or(true, |ts| ts >= *next_restart_ms.borrow()) {
                            request_restart = true;
                        }
                    }
                    if let Some(ctx) = guard.as_mut() {
                        if let Err(err) = ctx.host.run_once().await {
                            warn!(%err, "host loop error");
                        }
                        if let Some(ts) = now {
                            if ts - ctx.last_heartbeat_ms >= 1000.0 {
                                ctx.last_heartbeat_ms = ts;
                                heartbeat = Some((ctx.control.clone(), ctx.session_id));
                            }
                        }
                    }
                };
                if let Some((control, expected_session)) = heartbeat {
                    match heartbeat_once(&control).await {
                        Ok(status) => {
                            info!(
                                session = format_args!("0x{:016x}", status.session_id),
                                exports = status.export_count,
                                "heartbeat ok"
                            );
                            if status.session_id != expected_session {
                                info!(
                                    previous = format_args!("0x{expected_session:016x}"),
                                    current = format_args!("0x{:016x}", status.session_id),
                                    "session changed; restarting"
                                );
                                request_restart = true;
                            }
                        }
                        Err(err) => {
                            warn!(%err, "heartbeat error");
                            request_restart = true;
                        }
                    }
                }
                if request_restart {
                    spawn_session_restart(
                        inner_state.clone(),
                        restart_flag.clone(),
                        next_restart_ms.clone(),
                        device.clone(),
                        sources.clone(),
                        payload.clone(),
                        transport_config,
                    );
                }
                if let Some(win) = window() {
                    if let Some(cb) = raf_cb_inner.borrow().as_ref() {
                        let _ = win.request_animation_frame(cb.as_ref().unchecked_ref());
                    }
                }
            });
        }) as Box<dyn FnMut(f64)>));
        if let Some(cb) = raf_cb_clone.borrow().as_ref() {
            win.request_animation_frame(cb.as_ref().unchecked_ref())
                .map_err(JsValue::from)?;
        }
        Ok(())
    }

    fn now_ms() -> Option<f64> {
        let window = window()?;
        let perf = window.performance()?;
        Some(perf.now())
    }

    #[derive(Clone)]
    struct UiMakeWriter;

    impl<'a> fmt::MakeWriter<'a> for UiMakeWriter {
        type Writer = UiWriter;

        fn make_writer(&'a self) -> Self::Writer {
            UiWriter::default()
        }
    }

    #[derive(Default)]
    struct UiWriter {
        buf: String,
    }

    impl io::Write for UiWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.push_str(&String::from_utf8_lossy(buf));
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if !self.buf.is_empty() {
                emit_log_line(&self.buf);
                self.buf.clear();
            }
            Ok(())
        }
    }

    impl Drop for UiWriter {
        fn drop(&mut self) {
            if !self.buf.is_empty() {
                emit_log_line(&self.buf);
            }
        }
    }

    fn emit_log_line(line: &str) {
        LOG_SINK.with(|cell| {
            if let Some(cb) = cell.borrow().as_ref() {
                let _ = cb.call1(&JsValue::NULL, &JsValue::from_str(line));
            }
        });
    }

    fn to_js_err(err: impl core::fmt::Display) -> JsValue {
        JsValue::from_str(&err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_host::start;

#[cfg(not(target_arch = "wasm32"))]
#[wasm_bindgen]
pub async fn start(
    _device: wasm_bindgen::JsValue,
    _backing_url: String,
) -> Result<(), wasm_bindgen::JsValue> {
    Err(wasm_bindgen::JsValue::from_str(
        "web-host is only available for wasm32 targets",
    ))
}
