#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use futures_util::future::FutureExt;
use smoo_host_core::control::{ConfigExportsV0, read_status};
use smoo_host_core::{
    BlockSource, BlockSourceHandle, ControlTransport, HostErrorKind, HostIoPumpTask, SmooHost,
    Transport, TransportErrorKind, start_host_io_pump,
};
use smoo_proto::{ConfigExport, SmooStatusV0};

pub use smoo_host_core::ExportIdentity;

#[derive(Clone, Debug)]
pub struct HostSessionConfig {
    pub status_retry_attempts: usize,
}

impl Default for HostSessionConfig {
    fn default() -> Self {
        Self {
            status_retry_attempts: 5,
        }
    }
}

pub struct HostSession {
    sources: BTreeMap<u32, BlockSourceHandle>,
    config: HostSessionConfig,
}

impl HostSession {
    pub fn new(
        sources: BTreeMap<u32, BlockSourceHandle>,
        config: HostSessionConfig,
    ) -> Result<Self, HostSessionError> {
        if sources.is_empty() {
            return Err(HostSessionError::with_message(
                HostSessionErrorKind::InvalidConfiguration,
                "host session requires at least one export",
            ));
        }
        if config.status_retry_attempts == 0 {
            return Err(HostSessionError::with_message(
                HostSessionErrorKind::InvalidConfiguration,
                "status_retry_attempts must be greater than zero",
            ));
        }
        Ok(Self { sources, config })
    }

    pub async fn start<T, C>(
        self,
        transport: T,
        control: &mut C,
    ) -> Result<HostSessionTask<T>, HostSessionError>
    where
        T: Transport + Clone + Send + Sync + 'static,
        C: ControlTransport + Sync,
    {
        let (pump_handle, request_rx, pump_task) = start_host_io_pump(transport.clone());
        let mut host = SmooHost::new(pump_handle.clone(), request_rx, self.sources.clone());

        let setup_result = setup_session(&mut host, control, &self.sources, &self.config).await;
        let session_id = match setup_result {
            Ok(session_id) => session_id,
            Err(err) => {
                let _ = pump_handle.shutdown().await;
                let _ = pump_task.await;
                return Err(err);
            }
        };

        let state = Arc::new(SessionState::new(session_id));
        let driver = Box::pin(run_session(
            self,
            host,
            pump_handle,
            pump_task,
            state.clone(),
        ));

        Ok(HostSessionTask {
            state,
            driver,
            _transport: PhantomData,
        })
    }
}

pub struct HostSessionTask<T>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    state: Arc<SessionState>,
    driver: Pin<Box<dyn Future<Output = HostSessionFinish> + 'static>>,
    _transport: PhantomData<T>,
}

impl<T> HostSessionTask<T>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    pub fn stop(&mut self) {
        self.state.stop_requested.store(true, Ordering::Relaxed);
    }

    pub async fn heartbeat<C>(&self, control: &mut C) -> Result<SmooStatusV0, HostSessionError>
    where
        C: ControlTransport + Sync,
    {
        let status = read_status(control).await.map_err(map_transport_error)?;
        let expected = self.state.expected_session_id.load(Ordering::Relaxed);
        if status.session_id != expected {
            self.state
                .observed_session_id
                .store(status.session_id, Ordering::Relaxed);
            self.state.session_changed.store(true, Ordering::Relaxed);
        }
        Ok(status)
    }
}

impl<T> Future for HostSessionTask<T>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    type Output = HostSessionFinish;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: `HostSessionTask` does not project pinned fields by address.
        let this = unsafe { self.get_unchecked_mut() };
        this.driver.as_mut().poll(cx)
    }
}

pub struct HostSessionFinish {
    pub session: HostSession,
    pub outcome: Result<HostSessionOutcome, HostSessionError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSessionOutcome {
    Stopped,
    TransportLost,
    SessionChanged { previous: u64, current: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSessionErrorKind {
    InvalidConfiguration,
    SessionClosed,
    Transport,
    BlockSource,
    InvalidRequest,
    Unsupported,
    NotReady,
    Internal,
}

#[derive(Clone, Debug)]
pub struct HostSessionError {
    kind: HostSessionErrorKind,
    message: Option<String>,
}

impl HostSessionError {
    pub const fn new(kind: HostSessionErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: HostSessionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub const fn kind(&self) -> HostSessionErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for HostSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {msg}", self.kind),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

struct SessionState {
    stop_requested: AtomicBool,
    session_changed: AtomicBool,
    expected_session_id: AtomicU64,
    observed_session_id: AtomicU64,
}

impl SessionState {
    fn new(session_id: u64) -> Self {
        Self {
            stop_requested: AtomicBool::new(false),
            session_changed: AtomicBool::new(false),
            expected_session_id: AtomicU64::new(session_id),
            observed_session_id: AtomicU64::new(session_id),
        }
    }
}

async fn run_session(
    session: HostSession,
    mut host: SmooHost<BlockSourceHandle>,
    pump_handle: smoo_host_core::HostIoPumpHandle,
    mut pump_task: HostIoPumpTask,
    state: Arc<SessionState>,
) -> HostSessionFinish {
    let outcome = loop {
        if state.stop_requested.load(Ordering::Relaxed) {
            break Ok(HostSessionOutcome::Stopped);
        }

        if state.session_changed.load(Ordering::Relaxed) {
            let previous = state.expected_session_id.load(Ordering::Relaxed);
            let current = state.observed_session_id.load(Ordering::Relaxed);
            break Ok(HostSessionOutcome::SessionChanged { previous, current });
        }

        let next_host = host.run_until_event().fuse();
        let next_pump = poll_pump_task(&mut pump_task).fuse();
        futures_util::pin_mut!(next_host, next_pump);
        futures_util::select_biased! {
            host_result = next_host => {
                match host_result {
                    Ok(()) => {}
                    Err(err) => match err.kind() {
                        HostErrorKind::Transport => break Ok(HostSessionOutcome::TransportLost),
                        HostErrorKind::Unsupported | HostErrorKind::InvalidRequest => {}
                        _ => break Err(map_host_error(err)),
                    }
                }
            }
            pump_result = next_pump => {
                match pump_result {
                    Ok(()) => break Ok(HostSessionOutcome::TransportLost),
                    Err(err) => {
                        if err.kind() == TransportErrorKind::Disconnected {
                            break Ok(HostSessionOutcome::TransportLost);
                        }
                        break Err(map_transport_error(err));
                    }
                }
            }
        }
    };

    let _ = pump_handle.shutdown().await;
    let _ = pump_task.await;

    HostSessionFinish { session, outcome }
}

async fn setup_session<C>(
    host: &mut SmooHost<BlockSourceHandle>,
    control: &mut C,
    sources: &BTreeMap<u32, BlockSourceHandle>,
    config: &HostSessionConfig,
) -> Result<u64, HostSessionError>
where
    C: ControlTransport + Sync,
{
    let _ident = host.setup(control).await.map_err(map_host_error)?;

    let payload = build_config_payload(sources).await?;
    host.configure_exports_v0(control, &payload)
        .await
        .map_err(map_host_error)?;

    fetch_status_with_retry(control, config.status_retry_attempts).await
}

async fn build_config_payload(
    sources: &BTreeMap<u32, BlockSourceHandle>,
) -> Result<ConfigExportsV0, HostSessionError> {
    let mut entries = Vec::with_capacity(sources.len());
    for (export_id, source) in sources {
        let block_size = source.block_size();
        if block_size == 0 {
            return Err(HostSessionError::with_message(
                HostSessionErrorKind::InvalidConfiguration,
                "block size must be non-zero",
            ));
        }
        let total_blocks = source.total_blocks().await.map_err(map_block_error)?;
        let size_bytes = total_blocks.checked_mul(block_size as u64).ok_or_else(|| {
            HostSessionError::with_message(
                HostSessionErrorKind::InvalidConfiguration,
                "export size overflow",
            )
        })?;
        entries.push(ConfigExport {
            export_id: *export_id,
            block_size,
            size_bytes,
        });
    }
    ConfigExportsV0::from_slice(&entries).map_err(|err| {
        HostSessionError::with_message(HostSessionErrorKind::InvalidConfiguration, err.to_string())
    })
}

async fn fetch_status_with_retry<C>(
    control: &mut C,
    attempts: usize,
) -> Result<u64, HostSessionError>
where
    C: ControlTransport + Sync,
{
    let mut remaining = attempts;
    loop {
        match read_status(control).await {
            Ok(status) => return Ok(status.session_id),
            Err(err) => {
                remaining = remaining.saturating_sub(1);
                if remaining == 0 {
                    return Err(map_transport_error(err));
                }
            }
        }
    }
}

fn map_transport_error(err: smoo_host_core::TransportError) -> HostSessionError {
    HostSessionError::with_message(HostSessionErrorKind::Transport, err.to_string())
}

fn map_block_error(err: smoo_host_core::BlockSourceError) -> HostSessionError {
    HostSessionError::with_message(HostSessionErrorKind::BlockSource, err.to_string())
}

fn map_host_error(err: smoo_host_core::HostError) -> HostSessionError {
    let kind = match err.kind() {
        HostErrorKind::Transport => HostSessionErrorKind::Transport,
        HostErrorKind::BlockSource => HostSessionErrorKind::BlockSource,
        HostErrorKind::InvalidRequest => HostSessionErrorKind::InvalidRequest,
        HostErrorKind::Unsupported => HostSessionErrorKind::Unsupported,
        HostErrorKind::NotReady => HostSessionErrorKind::NotReady,
    };
    HostSessionError::with_message(kind, err.to_string())
}

async fn poll_pump_task(task: &mut HostIoPumpTask) -> smoo_host_core::TransportResult<()> {
    futures_util::future::poll_fn(|cx| Pin::new(&mut *task).poll(cx)).await
}
