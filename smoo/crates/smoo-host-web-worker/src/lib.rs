#[cfg(target_arch = "wasm32")]
mod api;
#[cfg(target_arch = "wasm32")]
mod rpc;
#[cfg(target_arch = "wasm32")]
mod runner;

#[cfg(target_arch = "wasm32")]
pub use api::{HostWorkerConfig, HostWorkerEvent, HostWorkerState};
#[cfg(target_arch = "wasm32")]
pub use rpc::{HostWorker, run_if_worker};
