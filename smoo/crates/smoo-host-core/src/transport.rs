use alloc::{boxed::Box, string::String, sync::Arc};
use async_trait::async_trait;
use core::fmt;
#[cfg(target_has_atomic = "64")]
use core::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

#[cfg(target_has_atomic = "64")]
type CounterAtomic = AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type CounterAtomic = AtomicUsize;

pub type TransportResult<T> = core::result::Result<T, TransportError>;

/// High-level transport failure categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportErrorKind {
    NotReady,
    Disconnected,
    Timeout,
    Protocol,
    Unsupported,
    Other,
}

/// Error surfaced by [`Transport`] implementations.
#[derive(Clone, Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: Option<String>,
}

impl TransportError {
    pub const fn new(kind: TransportErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransportError {}

/// Provides access to vendor control transfers used by the smoo protocol.
#[async_trait]
pub trait ControlTransport: Send + Sync {
    /// Issue a vendor control IN transfer (device → host).
    ///
    /// Implementations handle the correct interface/index internally.
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize>;

    /// Issue a vendor control OUT transfer (host → device).
    ///
    /// Implementations handle the correct interface/index internally.
    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize>;
}

/// Abstracts the USB transport that carries protocol messages between the
/// host and gadget. This trait is intentionally low-level; smoo-specific
/// encoding/decoding is handled in `host-core`.
#[async_trait]
pub trait Transport: ControlTransport + Send + Sync {
    /// Receive bytes from the Request interrupt endpoint (device → host).
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize>;

    /// Send bytes to the Response interrupt endpoint (host → device).
    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize>;

    /// Read a payload from the gadget over the bulk IN endpoint.
    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize>;

    /// Write a payload to the gadget over the bulk OUT endpoint.
    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize>;
}

/// Snapshot of bytes transferred by direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCounterSnapshot {
    /// Bytes sent from host → gadget.
    pub bytes_up: u64,
    /// Bytes received gadget → host.
    pub bytes_down: u64,
}

/// Shared counters for a transport instance.
#[derive(Clone, Debug)]
pub struct TransportCounters {
    bytes_up: Arc<CounterAtomic>,
    bytes_down: Arc<CounterAtomic>,
}

impl TransportCounters {
    fn new() -> Self {
        Self {
            bytes_up: Arc::new(CounterAtomic::new(0)),
            bytes_down: Arc::new(CounterAtomic::new(0)),
        }
    }

    /// Bytes sent from host → gadget so far.
    pub fn bytes_up(&self) -> u64 {
        self.bytes_up.load(Ordering::Relaxed)
    }

    /// Bytes received from gadget → host so far.
    pub fn bytes_down(&self) -> u64 {
        self.bytes_down.load(Ordering::Relaxed)
    }

    /// Reset both counters back to zero.
    pub fn reset(&self) {
        self.bytes_up.store(0, Ordering::Relaxed);
        self.bytes_down.store(0, Ordering::Relaxed);
    }

    /// Obtain a point-in-time view of both counters.
    pub fn snapshot(&self) -> TransportCounterSnapshot {
        TransportCounterSnapshot {
            bytes_up: self.bytes_up(),
            bytes_down: self.bytes_down(),
        }
    }

    fn add_up(&self, bytes: usize) {
        self.add_to_counter(&self.bytes_up, bytes);
    }

    fn add_down(&self, bytes: usize) {
        self.add_to_counter(&self.bytes_down, bytes);
    }

    fn add_to_counter(&self, counter: &CounterAtomic, bytes: usize) {
        #[cfg(target_has_atomic = "64")]
        {
            counter.fetch_add(bytes as u64, Ordering::Relaxed);
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            counter.fetch_add(bytes as usize, Ordering::Relaxed);
        }
    }
}

/// Decorator that counts bytes flowing through an inner [`Transport`].
#[derive(Clone)]
pub struct CountingTransport<T> {
    inner: T,
    counters: TransportCounters,
}

impl<T> CountingTransport<T> {
    /// Wrap a transport with counters initialised to zero.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            counters: TransportCounters::new(),
        }
    }

    /// Access shared counters for this transport.
    pub fn counters(&self) -> TransportCounters {
        self.counters.clone()
    }

    /// Consume the decorator and return the inner transport.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait]
impl<T> ControlTransport for CountingTransport<T>
where
    T: ControlTransport + Send + Sync,
{
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        let res = self.inner.control_in(request_type, request, buf).await;
        if let Ok(len) = res {
            self.counters.add_down(len);
        }
        res
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        let res = self.inner.control_out(request_type, request, data).await;
        if res.is_ok() {
            self.counters.add_up(data.len());
        }
        res
    }
}

#[async_trait]
impl<T> Transport for CountingTransport<T>
where
    T: Transport + Clone + Send + Sync,
{
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize> {
        let res = self.inner.read_interrupt(buf).await;
        if let Ok(len) = res {
            self.counters.add_down(len);
        }
        res
    }

    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize> {
        let res = self.inner.write_interrupt(buf).await;
        if res.is_ok() {
            self.counters.add_up(buf.len());
        }
        res
    }

    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize> {
        let res = self.inner.read_bulk(buf).await;
        if let Ok(len) = res {
            self.counters.add_down(len);
        }
        res
    }

    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize> {
        let res = self.inner.write_bulk(buf).await;
        if res.is_ok() {
            self.counters.add_up(buf.len());
        }
        res
    }
}
