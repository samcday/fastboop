use crate::{ExportSpec, PersistedExportRecord, StateStore};
use anyhow::{Result, anyhow, ensure};
use smoo_gadget_ublk::{SmooUblk, SmooUblkDevice, UblkCtrlHandle, UblkQueueRuntime};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Clone, Copy, Debug)]
pub struct RuntimeTunables {
    pub queue_count: u16,
    pub queue_depth: u16,
    pub max_io_bytes: Option<usize>,
    pub dma_heap: Option<crate::DmaHeap>,
}

pub enum ExportState {
    New,
    RecoveringPending { dev_id: u32 },
    Device(DeviceHandle),
    Deleted,
}

pub enum DeviceHandle {
    Starting {
        dev_id: u32,
        ctrl: UblkCtrlHandle,
        queues: Arc<UblkQueueRuntime>,
    },
    Online {
        dev_id: u32,
        ctrl: UblkCtrlHandle,
        queues: Arc<UblkQueueRuntime>,
    },
    ShuttingDown {
        dev_id: u32,
        ctrl: UblkCtrlHandle,
        queues: Arc<UblkQueueRuntime>,
    },
    Failed {
        dev_id: u32,
        ctrl: Option<UblkCtrlHandle>,
        queues: Option<Arc<UblkQueueRuntime>>,
        last_error: String,
    },
}

impl DeviceHandle {
    pub fn dev_id(&self) -> u32 {
        match self {
            DeviceHandle::Starting { dev_id, .. }
            | DeviceHandle::Online { dev_id, .. }
            | DeviceHandle::ShuttingDown { dev_id, .. }
            | DeviceHandle::Failed { dev_id, .. } => *dev_id,
        }
    }

    pub fn queues(&self) -> Option<Arc<UblkQueueRuntime>> {
        match self {
            DeviceHandle::Starting { queues, .. }
            | DeviceHandle::Online { queues, .. }
            | DeviceHandle::ShuttingDown { queues, .. } => Some(queues.clone()),
            DeviceHandle::Failed { queues, .. } => queues.clone(),
        }
    }

    pub fn ctrl_mut(&mut self) -> Option<&mut UblkCtrlHandle> {
        match self {
            DeviceHandle::Starting { ctrl, .. }
            | DeviceHandle::Online { ctrl, .. }
            | DeviceHandle::ShuttingDown { ctrl, .. } => Some(ctrl),
            DeviceHandle::Failed { ctrl, .. } => ctrl.as_mut(),
        }
    }

    pub fn ctrl(&self) -> Option<&UblkCtrlHandle> {
        match self {
            DeviceHandle::Starting { ctrl, .. }
            | DeviceHandle::Online { ctrl, .. }
            | DeviceHandle::ShuttingDown { ctrl, .. } => Some(ctrl),
            DeviceHandle::Failed { ctrl, .. } => ctrl.as_ref(),
        }
    }

    pub fn is_online(&self) -> bool {
        matches!(self, DeviceHandle::Online { .. })
    }

    pub fn recovery_pending(&self) -> bool {
        self.ctrl()
            .map(|ctrl| ctrl.recovery_pending())
            .unwrap_or(false)
    }

    pub fn into_device(self) -> Option<SmooUblkDevice> {
        match self {
            DeviceHandle::Starting { ctrl, queues, .. }
            | DeviceHandle::Online { ctrl, queues, .. }
            | DeviceHandle::ShuttingDown { ctrl, queues, .. } => {
                Some(SmooUblkDevice::from_parts(ctrl, queues))
            }
            DeviceHandle::Failed {
                ctrl: Some(ctrl),
                queues: Some(queues),
                ..
            } => Some(SmooUblkDevice::from_parts(ctrl, queues)),
            _ => None,
        }
    }
}

pub struct ExportReconcileContext<'a> {
    pub ublk: &'a mut SmooUblk,
    pub state_store: &'a mut StateStore,
    pub tunables: RuntimeTunables,
}

fn error_is_missing(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(|io_err| io_err.raw_os_error())
        .is_some_and(|code| code == libc::ENOENT || code == libc::EINVAL)
}

pub struct ExportController {
    pub export_id: u32,
    pub spec: ExportSpec,
    pub state: ExportState,
    pub retry_backoff: Duration,
    pub next_retry_at: Option<Instant>,
}

impl ExportController {
    pub fn new(export_id: u32, spec: ExportSpec, state: ExportState) -> Self {
        Self {
            export_id,
            spec,
            state,
            retry_backoff: Duration::from_secs(1),
            next_retry_at: None,
        }
    }

    pub fn dev_id(&self) -> Option<u32> {
        match &self.state {
            ExportState::RecoveringPending { dev_id } => Some(*dev_id),
            ExportState::Device(handle) => Some(handle.dev_id()),
            _ => None,
        }
    }

    pub fn device_handle(&self) -> Option<&DeviceHandle> {
        match &self.state {
            ExportState::Device(handle) => Some(handle),
            _ => None,
        }
    }

    pub fn device_handle_mut(&mut self) -> Option<&mut DeviceHandle> {
        match &mut self.state {
            ExportState::Device(handle) => Some(handle),
            _ => None,
        }
    }

    pub fn take_device_handles(&mut self) -> Option<(UblkCtrlHandle, Arc<UblkQueueRuntime>)> {
        let mut handles = None;
        self.state = match std::mem::replace(&mut self.state, ExportState::New) {
            ExportState::Device(handle) => {
                match handle {
                    DeviceHandle::Starting { ctrl, queues, .. }
                    | DeviceHandle::Online { ctrl, queues, .. }
                    | DeviceHandle::ShuttingDown { ctrl, queues, .. } => {
                        handles = Some((ctrl, queues));
                    }
                    DeviceHandle::Failed {
                        ctrl: Some(ctrl),
                        queues: Some(queues),
                        ..
                    } => handles = Some((ctrl, queues)),
                    _ => {}
                }
                ExportState::Deleted
            }
            other => other,
        };
        handles
    }

    pub fn fail_device(&mut self, message: String) {
        self.state = match std::mem::replace(&mut self.state, ExportState::New) {
            ExportState::Device(handle) => match handle {
                DeviceHandle::Starting {
                    dev_id,
                    ctrl,
                    queues,
                }
                | DeviceHandle::Online {
                    dev_id,
                    ctrl,
                    queues,
                }
                | DeviceHandle::ShuttingDown {
                    dev_id,
                    ctrl,
                    queues,
                } => ExportState::Device(DeviceHandle::Failed {
                    dev_id,
                    ctrl: Some(ctrl),
                    queues: Some(queues),
                    last_error: message,
                }),
                DeviceHandle::Failed {
                    dev_id,
                    ctrl,
                    queues,
                    ..
                } => ExportState::Device(DeviceHandle::Failed {
                    dev_id,
                    ctrl,
                    queues,
                    last_error: message,
                }),
            },
            ExportState::RecoveringPending { dev_id } => {
                ExportState::Device(DeviceHandle::Failed {
                    dev_id,
                    ctrl: None,
                    queues: None,
                    last_error: message,
                })
            }
            other => other,
        };
        self.next_retry_at = Some(Instant::now() + self.retry_backoff);
    }

    pub fn needs_reconcile(&self, now: Instant) -> bool {
        match &self.state {
            ExportState::New | ExportState::RecoveringPending { .. } => {
                self.next_retry_at.is_none_or(|retry_at| now >= retry_at)
            }
            ExportState::Device(handle) => match handle {
                DeviceHandle::Online { .. } => false,
                DeviceHandle::Failed { .. } => {
                    self.next_retry_at.is_none_or(|retry_at| now >= retry_at)
                }
                _ => true,
            },
            ExportState::Deleted => false,
        }
    }

    pub fn is_active_for_status(&self) -> bool {
        matches!(self.state, ExportState::Device(DeviceHandle::Online { .. }))
    }

    pub fn take_handle(&mut self) -> Option<DeviceHandle> {
        let mut handle = None;
        self.state = match std::mem::replace(&mut self.state, ExportState::New) {
            ExportState::Device(inner) => {
                handle = Some(inner);
                ExportState::Deleted
            }
            other => other,
        };
        handle
    }

    pub async fn reconcile(&mut self, cx: &mut ExportReconcileContext<'_>) -> Result<()> {
        let now = Instant::now();
        self.state = match std::mem::replace(&mut self.state, ExportState::New) {
            ExportState::New => {
                let block_size = self.spec.block_size as usize;
                let blocks = self
                    .spec
                    .size_bytes
                    .checked_div(block_size as u64)
                    .unwrap_or(0);
                ensure!(blocks > 0, "export size too small");
                let block_count =
                    usize::try_from(blocks).map_err(|_| anyhow!("block count overflow"))?;
                let device = cx
                    .ublk
                    .setup_device(
                        block_size,
                        block_count,
                        cx.tunables.queue_count,
                        cx.tunables.queue_depth,
                        cx.tunables.max_io_bytes,
                    )
                    .await?;
                let dev_id = device.dev_id();
                cx.state_store.upsert_record(PersistedExportRecord {
                    export_id: self.export_id,
                    spec: self.spec.clone(),
                    assigned_dev_id: Some(dev_id),
                });
                cx.state_store.persist()?;
                let (ctrl, queues) = device.into_parts();
                self.next_retry_at = None;
                ExportState::Device(DeviceHandle::Starting {
                    dev_id,
                    ctrl,
                    queues,
                })
            }
            ExportState::RecoveringPending { dev_id } => {
                match cx.ublk.recover_existing_device(dev_id).await {
                    Ok(device) => {
                        let (ctrl, queues) = device.into_parts();
                        self.next_retry_at = None;
                        ExportState::Device(DeviceHandle::Starting {
                            dev_id,
                            ctrl,
                            queues,
                        })
                    }
                    Err(err) => {
                        if error_is_missing(&err) {
                            cx.state_store
                                .update_record(self.export_id, |record| {
                                    record.assigned_dev_id = None
                                })
                                .ok();
                            cx.state_store.persist().ok();
                            self.next_retry_at = None;
                            ExportState::New
                        } else {
                            self.next_retry_at = Some(now + self.retry_backoff);
                            ExportState::Device(DeviceHandle::Failed {
                                dev_id,
                                ctrl: None,
                                queues: None,
                                last_error: format!("recover device {dev_id} failed: {err:#}"),
                            })
                        }
                    }
                }
            }
            ExportState::Device(handle) => match handle {
                DeviceHandle::Starting {
                    dev_id,
                    mut ctrl,
                    queues,
                } => {
                    let start_result = ctrl.poll_start_result();
                    match start_result {
                        Some(Ok(())) => {
                            let mut device = SmooUblkDevice::from_parts(ctrl, queues.clone());
                            if device.recovery_pending() {
                                cx.ublk.finalize_recovery(&mut device).await?;
                            }
                            info!(
                                export_id = self.export_id,
                                dev_id,
                                queue_count = queues.queue_count(),
                                queue_depth = queues.queue_depth(),
                                block_size = queues.block_size(),
                                block_count = queues.block_count(),
                                max_io_bytes = queues.max_io_bytes(),
                                ioctl_encode = queues.ioctl_encode(),
                                buffer_len = queues.buffer_len(),
                                "ublk target online"
                            );
                            let (ctrl, queues) = device.into_parts();
                            self.next_retry_at = None;
                            ExportState::Device(DeviceHandle::Online {
                                dev_id,
                                ctrl,
                                queues,
                            })
                        }
                        Some(Err(err)) => {
                            ctrl.shutdown();
                            self.next_retry_at = Some(now + self.retry_backoff);
                            ExportState::Device(DeviceHandle::Failed {
                                dev_id,
                                ctrl: Some(ctrl),
                                queues: Some(queues),
                                last_error: format!("start_dev failed: {err:#}"),
                            })
                        }
                        None => {
                            if ctrl.start_deadline_passed(now) {
                                ctrl.mark_start_timed_out();
                                self.next_retry_at = Some(now + self.retry_backoff);
                                ExportState::Device(DeviceHandle::Failed {
                                    dev_id,
                                    ctrl: Some(ctrl),
                                    queues: Some(queues),
                                    last_error: "start_dev timed out".to_string(),
                                })
                            } else {
                                ExportState::Device(DeviceHandle::Starting {
                                    dev_id,
                                    ctrl,
                                    queues,
                                })
                            }
                        }
                    }
                }
                DeviceHandle::Online {
                    dev_id,
                    ctrl,
                    queues,
                } => {
                    self.next_retry_at = None;
                    ExportState::Device(DeviceHandle::Online {
                        dev_id,
                        ctrl,
                        queues,
                    })
                }
                DeviceHandle::ShuttingDown {
                    dev_id: _,
                    ctrl,
                    queues,
                } => {
                    cx.ublk
                        .stop_dev(SmooUblkDevice::from_parts(ctrl, queues), true)
                        .await?;
                    cx.state_store
                        .update_record(self.export_id, |record| record.assigned_dev_id = None)
                        .ok();
                    cx.state_store.persist().ok();
                    self.next_retry_at = None;
                    ExportState::Deleted
                }
                DeviceHandle::Failed {
                    dev_id,
                    mut ctrl,
                    mut queues,
                    last_error,
                } => {
                    if let Some(retry_at) = self.next_retry_at {
                        if now < retry_at {
                            self.next_retry_at = Some(retry_at);
                            ExportState::Device(DeviceHandle::Failed {
                                dev_id,
                                ctrl,
                                queues,
                                last_error,
                            })
                        } else {
                            if let (Some(ctrl_val), Some(queues_val)) = (ctrl.take(), queues.take())
                            {
                                let _ = cx
                                    .ublk
                                    .stop_dev(
                                        SmooUblkDevice::from_parts(ctrl_val, queues_val),
                                        true,
                                    )
                                    .await;
                            } else if let Some(mut ctrl_val) = ctrl.take() {
                                ctrl_val.shutdown();
                            }
                            cx.state_store
                                .update_record(self.export_id, |record| {
                                    record.assigned_dev_id = None
                                })
                                .ok();
                            cx.state_store.persist().ok();
                            self.next_retry_at = None;
                            ExportState::New
                        }
                    } else {
                        self.next_retry_at = None;
                        ExportState::New
                    }
                }
            },
            ExportState::Deleted => ExportState::Deleted,
        };
        Ok(())
    }
}

pub struct GadgetRuntime {
    pub exports: HashMap<u32, ExportController>,
    pub state_store: StateStore,
    pub tunables: RuntimeTunables,
}

impl GadgetRuntime {
    pub fn new(state_store: StateStore, tunables: RuntimeTunables) -> Self {
        Self {
            exports: HashMap::new(),
            state_store,
            tunables,
        }
    }

    pub fn rebuild_exports(&mut self, records: Vec<PersistedExportRecord>) {
        self.exports = records
            .into_iter()
            .map(|record| {
                let state = match record.assigned_dev_id {
                    Some(dev_id) => ExportState::RecoveringPending { dev_id },
                    None => ExportState::New,
                };
                let controller = ExportController::new(record.export_id, record.spec, state);
                (record.export_id, controller)
            })
            .collect();
    }
}
