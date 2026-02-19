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
use futures_util::FutureExt;
use smoo_host_core::control::{ConfigExportsV0, read_status};
use smoo_host_core::{
    BlockSource, BlockSourceHandle, ControlTransport, HostErrorKind, SmooHost, Transport,
};
use smoo_proto::{ConfigExport, SmooStatusV0};

pub use smoo_host_core::ExportIdentity;

pub const DEFAULT_HEARTBEAT_MISS_BUDGET: u32 = 5;

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
        let mut host = SmooHost::new(transport, self.sources.clone());

        let setup_result = setup_session(&mut host, control, &self.sources, &self.config).await;
        let session_id = match setup_result {
            Ok(session_id) => session_id,
            Err(err) => return Err(err),
        };

        let state = Arc::new(SessionState::new(session_id));
        let driver = Box::pin(run_session(self, host, state.clone()));

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

impl<T> Unpin for HostSessionTask<T> where T: Transport + Clone + Send + Sync + 'static {}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSessionDriveConfig {
    pub heartbeat_miss_budget: u32,
}

impl Default for HostSessionDriveConfig {
    fn default() -> Self {
        Self {
            heartbeat_miss_budget: DEFAULT_HEARTBEAT_MISS_BUDGET,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostSessionDriveEvent {
    HeartbeatStatus {
        status: SmooStatusV0,
    },
    HeartbeatRecovered {
        missed_heartbeats: u32,
    },
    HeartbeatMiss {
        error: HostSessionError,
        missed_heartbeats: u32,
        budget: u32,
    },
    HeartbeatMissBudgetExhausted {
        missed_heartbeats: u32,
        budget: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostSessionDriveOutcome {
    Shutdown,
    TransportLost,
    SessionChanged { previous: u64, current: u64 },
    Failed(HostSessionError),
}

pub async fn drive_host_session<T, C, Shutdown, Tick, TickFuture, OnEvent>(
    mut task: HostSessionTask<T>,
    mut control: C,
    shutdown: Shutdown,
    mut heartbeat_tick: Tick,
    config: HostSessionDriveConfig,
    mut on_event: OnEvent,
) -> HostSessionDriveOutcome
where
    T: Transport + Clone + Send + Sync + 'static,
    C: ControlTransport + Sync,
    Shutdown: Future<Output = ()>,
    Tick: FnMut() -> TickFuture,
    TickFuture: Future<Output = ()>,
    OnEvent: FnMut(HostSessionDriveEvent),
{
    let mut heartbeat_budget = match HeartbeatBudget::new(config.heartbeat_miss_budget) {
        Ok(budget) => budget,
        Err(err) => return HostSessionDriveOutcome::Failed(err),
    };

    let shutdown = shutdown.fuse();
    futures_util::pin_mut!(shutdown);

    loop {
        let heartbeat_tick = heartbeat_tick().fuse();
        futures_util::pin_mut!(heartbeat_tick);

        futures_util::select_biased! {
            _ = shutdown => {
                task.stop();
                return HostSessionDriveOutcome::Shutdown;
            }
            finish = (&mut task).fuse() => {
                return map_drive_finish(finish.outcome);
            }
            _ = heartbeat_tick => {
                match task.heartbeat(&mut control).await {
                    Ok(status) => {
                        if let Some(missed_heartbeats) = heartbeat_budget.record_success() {
                            on_event(HostSessionDriveEvent::HeartbeatRecovered {
                                missed_heartbeats,
                            });
                        }
                        on_event(HostSessionDriveEvent::HeartbeatStatus { status });
                    }
                    Err(error) => {
                        let update = heartbeat_budget.record_miss();
                        on_event(HostSessionDriveEvent::HeartbeatMiss {
                            error,
                            missed_heartbeats: update.missed_heartbeats,
                            budget: update.budget,
                        });
                        if update.exhausted {
                            on_event(HostSessionDriveEvent::HeartbeatMissBudgetExhausted {
                                missed_heartbeats: update.missed_heartbeats,
                                budget: update.budget,
                            });
                            return HostSessionDriveOutcome::TransportLost;
                        }
                    }
                }
            }
        }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSessionError {
    kind: HostSessionErrorKind,
    message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeartbeatBudget {
    miss_budget: u32,
    missed_heartbeats: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeartbeatBudgetUpdate {
    missed_heartbeats: u32,
    budget: u32,
    exhausted: bool,
}

impl HeartbeatBudget {
    fn new(miss_budget: u32) -> Result<Self, HostSessionError> {
        if miss_budget == 0 {
            return Err(HostSessionError::with_message(
                HostSessionErrorKind::InvalidConfiguration,
                "heartbeat_miss_budget must be greater than zero",
            ));
        }
        Ok(Self {
            miss_budget,
            missed_heartbeats: 0,
        })
    }

    fn record_success(&mut self) -> Option<u32> {
        if self.missed_heartbeats == 0 {
            return None;
        }
        let recovered = self.missed_heartbeats;
        self.missed_heartbeats = 0;
        Some(recovered)
    }

    fn record_miss(&mut self) -> HeartbeatBudgetUpdate {
        self.missed_heartbeats = self.missed_heartbeats.saturating_add(1);
        HeartbeatBudgetUpdate {
            missed_heartbeats: self.missed_heartbeats,
            budget: self.miss_budget,
            exhausted: self.missed_heartbeats >= self.miss_budget,
        }
    }
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

async fn run_session<T>(
    session: HostSession,
    mut host: SmooHost<T, BlockSourceHandle>,
    state: Arc<SessionState>,
) -> HostSessionFinish
where
    T: Transport + Clone + Send + Sync + 'static,
{
    let outcome = loop {
        if state.stop_requested.load(Ordering::Relaxed) {
            break Ok(HostSessionOutcome::Stopped);
        }

        if state.session_changed.load(Ordering::Relaxed) {
            let previous = state.expected_session_id.load(Ordering::Relaxed);
            let current = state.observed_session_id.load(Ordering::Relaxed);
            break Ok(HostSessionOutcome::SessionChanged { previous, current });
        }

        match host.run_until_event().await {
            Ok(()) => {}
            Err(err) => match err.kind() {
                HostErrorKind::Transport => break Ok(HostSessionOutcome::TransportLost),
                HostErrorKind::Unsupported | HostErrorKind::InvalidRequest => {}
                _ => break Err(map_host_error(err)),
            },
        }

        if state.stop_requested.load(Ordering::Relaxed) {
            break Ok(HostSessionOutcome::Stopped);
        }
        if state.session_changed.load(Ordering::Relaxed) {
            let previous = state.expected_session_id.load(Ordering::Relaxed);
            let current = state.observed_session_id.load(Ordering::Relaxed);
            break Ok(HostSessionOutcome::SessionChanged { previous, current });
        }
    };

    HostSessionFinish { session, outcome }
}

async fn setup_session<T, C>(
    host: &mut SmooHost<T, BlockSourceHandle>,
    control: &mut C,
    sources: &BTreeMap<u32, BlockSourceHandle>,
    config: &HostSessionConfig,
) -> Result<u64, HostSessionError>
where
    T: Transport + Send + Sync,
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

fn map_drive_finish(
    outcome: Result<HostSessionOutcome, HostSessionError>,
) -> HostSessionDriveOutcome {
    match outcome {
        Ok(HostSessionOutcome::Stopped) => HostSessionDriveOutcome::Shutdown,
        Ok(HostSessionOutcome::TransportLost) => HostSessionDriveOutcome::TransportLost,
        Ok(HostSessionOutcome::SessionChanged { previous, current }) => {
            HostSessionDriveOutcome::SessionChanged { previous, current }
        }
        Err(err) => HostSessionDriveOutcome::Failed(err),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_budget_rejects_zero_budget() {
        let err = HeartbeatBudget::new(0).expect_err("zero budget must fail");
        assert_eq!(err.kind(), HostSessionErrorKind::InvalidConfiguration);
    }

    #[test]
    fn heartbeat_budget_counts_and_resets() {
        let mut budget = HeartbeatBudget::new(3).expect("budget");

        let miss1 = budget.record_miss();
        assert_eq!(
            miss1,
            HeartbeatBudgetUpdate {
                missed_heartbeats: 1,
                budget: 3,
                exhausted: false,
            }
        );

        let miss2 = budget.record_miss();
        assert_eq!(
            miss2,
            HeartbeatBudgetUpdate {
                missed_heartbeats: 2,
                budget: 3,
                exhausted: false,
            }
        );

        assert_eq!(budget.record_success(), Some(2));
        assert_eq!(budget.record_success(), None);

        let miss3 = budget.record_miss();
        assert_eq!(
            miss3,
            HeartbeatBudgetUpdate {
                missed_heartbeats: 1,
                budget: 3,
                exhausted: false,
            }
        );
    }

    #[test]
    fn heartbeat_budget_detects_exhaustion() {
        let mut budget = HeartbeatBudget::new(2).expect("budget");
        assert!(!budget.record_miss().exhausted);
        assert!(budget.record_miss().exhausted);
    }
}
