use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use futures_channel::mpsc::UnboundedSender;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebSmooHostEvent {
    Phase {
        phase: WebSmooHostPhase,
        detail: String,
    },
    Log(String),
    Status {
        active: bool,
        ios_up: u64,
        ios_down: u64,
        bytes_up: u64,
        bytes_down: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebSmooHostPhase {
    WaitingForSmoo,
    Serving,
}

#[derive(Clone, Copy, Debug)]
pub struct WebSmooHostOptions {
    pub status_retry_attempts: usize,
    pub heartbeat_interval: Duration,
}

impl Default for WebSmooHostOptions {
    fn default() -> Self {
        Self {
            status_retry_attempts: 5,
            heartbeat_interval: Duration::from_secs(1),
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{Result, anyhow, bail};
    use futures_channel::mpsc::UnboundedSender;
    use futures_util::StreamExt;
    use gloo_timers::future::sleep;
    use smoo_host_web_worker::{HostWorker, HostWorkerConfig, HostWorkerEvent, HostWorkerState};
    use web_sys::UsbDevice;

    use crate::boot::WebBootRuntime;
    use crate::smoo::{WebSmooHostEvent, WebSmooHostOptions, WebSmooHostPhase};

    const STATUS_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

    pub fn run_if_worker() -> bool {
        smoo_host_web_worker::run_if_worker()
    }

    pub async fn run_web_smoo_host(
        initial_device: UsbDevice,
        runtime: WebBootRuntime,
        options: WebSmooHostOptions,
        events: UnboundedSender<WebSmooHostEvent>,
    ) -> Result<()> {
        emit(
            &events,
            WebSmooHostEvent::Phase {
                phase: WebSmooHostPhase::WaitingForSmoo,
                detail: "starting web smoo host worker".to_string(),
            },
        );

        let reader_client = runtime
            .local_reader_bridge
            .create_reader()
            .await
            .map_err(|err| anyhow!("attach local channel reader bridge: {err}"))?;
        let host = HostWorker::spawn(
            reader_client,
            HostWorkerConfig {
                status_retry_attempts: options.status_retry_attempts,
                heartbeat_interval_ms: options.heartbeat_interval.as_millis() as u32,
                size_bytes: runtime.size_bytes,
                identity: runtime.identity.clone(),
                ..HostWorkerConfig::default()
            },
        )
        .await
        .map_err(|err| anyhow!("spawn host worker failed: {err}"))?;
        let mut host_events = host
            .take_event_receiver()
            .ok_or_else(|| anyhow!("host worker events receiver unavailable"))?;

        loop {
            if host.state() == HostWorkerState::Idle {
                if let Err(err) = host.start(initial_device.clone()).await {
                    emit(
                        &events,
                        WebSmooHostEvent::Log(format!(
                            "starting host worker session failed: {err}"
                        )),
                    );
                    sleep(STATUS_RETRY_INTERVAL).await;
                    continue;
                }
            }

            let Some(event) = host_events.next().await else {
                bail!("host worker event stream closed")
            };

            match event {
                HostWorkerEvent::Starting => emit(
                    &events,
                    WebSmooHostEvent::Phase {
                        phase: WebSmooHostPhase::WaitingForSmoo,
                        detail: "starting smoo host session".to_string(),
                    },
                ),
                HostWorkerEvent::TransportConnected | HostWorkerEvent::Configured => emit(
                    &events,
                    WebSmooHostEvent::Phase {
                        phase: WebSmooHostPhase::Serving,
                        detail: "smoo gadget connected".to_string(),
                    },
                ),
                HostWorkerEvent::Counters {
                    ios_up,
                    ios_down,
                    bytes_up,
                    bytes_down,
                } => emit(
                    &events,
                    WebSmooHostEvent::Status {
                        active: true,
                        ios_up,
                        ios_down,
                        bytes_up,
                        bytes_down,
                    },
                ),
                HostWorkerEvent::SessionChanged { previous, current } => {
                    emit(
                        &events,
                        WebSmooHostEvent::Log(format!(
                            "web smoo session changed from 0x{previous:016x} to 0x{current:016x}; waiting to restart"
                        )),
                    );
                    emit_waiting(&events, "web smoo session changed; waiting to restart");
                }
                HostWorkerEvent::TransportLost => {
                    emit(
                        &events,
                        WebSmooHostEvent::Log(
                            "smoo web transport lost; waiting to restart".to_string(),
                        ),
                    );
                    emit_waiting(&events, "smoo web transport lost; waiting to restart");
                }
                HostWorkerEvent::Error { message } => emit(&events, WebSmooHostEvent::Log(message)),
                HostWorkerEvent::Stopped => {
                    emit_waiting(&events, "smoo host worker stopped; waiting to restart");
                    sleep(STATUS_RETRY_INTERVAL).await;
                }
            }
        }
    }

    fn emit_waiting(events: &UnboundedSender<WebSmooHostEvent>, detail: &str) {
        emit(
            events,
            WebSmooHostEvent::Phase {
                phase: WebSmooHostPhase::WaitingForSmoo,
                detail: detail.to_string(),
            },
        );
        emit(
            events,
            WebSmooHostEvent::Status {
                active: false,
                ios_up: 0,
                ios_down: 0,
                bytes_up: 0,
                bytes_down: 0,
            },
        );
    }

    fn emit(events: &UnboundedSender<WebSmooHostEvent>, event: WebSmooHostEvent) {
        let _ = events.unbounded_send(event);
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
pub fn run_if_worker() -> bool {
    false
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn run_web_smoo_host(
    _initial_device: (),
    _runtime: crate::boot::WebBootRuntime,
    _options: WebSmooHostOptions,
    _events: UnboundedSender<WebSmooHostEvent>,
) -> Result<()> {
    anyhow::bail!("web smoo host is only available on wasm32 targets")
}
