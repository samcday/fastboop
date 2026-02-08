#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block;
pub mod control;
pub mod export_id;
pub mod exports;
pub mod heartbeat;
#[cfg(feature = "std")]
pub mod host;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "std")]
pub mod pump;
pub mod transport;

pub use block::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceHandle, BlockSourceResult,
};
pub use export_id::{
    ExportHasher32, ExportIdentity, derive_export_id, derive_export_id_from_source,
    derive_export_id_with,
};
pub use exports::{ExportConfigError, ExportConfigErrorKind, register_export};
pub use heartbeat::heartbeat_once;
#[cfg(feature = "std")]
pub use host::{HostError, HostErrorKind, HostResult, SmooHost};
#[cfg(feature = "metrics")]
pub use metrics::{MetricsSnapshot, QueueSnapshot, StatSnapshot};
#[cfg(feature = "std")]
pub use pump::{
    BulkReadHandle, HostIoPumpHandle, HostIoPumpRequestRx, HostIoPumpTask, start_host_io_pump,
};
pub use transport::{
    ControlTransport, CountingTransport, Transport, TransportCounterSnapshot, TransportCounters,
    TransportError, TransportErrorKind, TransportResult,
};
