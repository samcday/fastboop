mod buffers;
mod sys;

use crate::buffers::{BufferGuard, QueueBuffers};
use crate::sys::{
    UBLK_CMD_ADD_DEV, UBLK_CMD_DEL_DEV, UBLK_CMD_END_USER_RECOVERY, UBLK_CMD_GET_DEV_INFO,
    UBLK_CMD_GET_DEV_INFO2, UBLK_CMD_GET_PARAMS, UBLK_CMD_SET_PARAMS, UBLK_CMD_START_DEV,
    UBLK_CMD_START_USER_RECOVERY, UBLK_CMD_STOP_DEV, UBLK_F_USER_RECOVERY,
    UBLK_F_USER_RECOVERY_REISSUE, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ,
    UBLK_IO_OP_WRITE, UBLK_PARAM_TYPE_BASIC, UBLK_U_IO_COMMIT_AND_FETCH_REQ, UBLK_U_IO_FETCH_REQ,
    ublk_param_basic, ublk_params, ublksrv_ctrl_cmd, ublksrv_ctrl_dev_info, ublksrv_io_cmd,
    ublksrv_io_desc,
};
use anyhow::{Context, anyhow, ensure};
use async_channel::{Receiver, RecvError, Sender};
use io_uring::{IoUring, cqueue, squeue, types};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::mem::{ManuallyDrop, size_of, transmute};
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{Level, debug, error, info, trace, warn};
/// Top level interface to ublk. Creates SmooUblkDevices
pub struct SmooUblk {
    handle: Option<JoinHandle<()>>,
    sender: Sender<CtrlCommand>,
    managed_devs: HashSet<u32>,
    preserve_on_drop: bool,
}

const CTRL_RING_DEPTH: u32 = 8;
const START_DEV_TIMEOUT: Duration = Duration::from_secs(5);
type CtrlCommand = (
    u32,
    ublksrv_ctrl_cmd,
    Sender<Result<(), io::Error>>,
    Option<Duration>,
);

struct PendingCtrl {
    reply: Sender<Result<(), io::Error>>,
    _opcode: u32,
    _cmd_user_data: u64,
    _timeout_user_data: Option<u64>,
    cancel_user_data: Option<u64>,
}

impl PendingCtrl {
    fn resolve(self, res: i32) {
        let result = match res {
            0 => Ok(()),
            r if r < 0 => Err(io::Error::from_raw_os_error(-r)),
            r => Err(io::Error::from_raw_os_error(-r)),
        };
        send_ctrl_reply(self.reply, result);
    }

    fn cancel_user_data(&self) -> Option<u64> {
        self.cancel_user_data
    }
}

pub struct SmooUblkDevice {
    ctrl: UblkCtrlHandle,
    queues: Arc<UblkQueueRuntime>,
}

pub struct UblkCtrlHandle {
    dev_id: u32,
    queue_count: u16,
    queue_depth: u16,
    ioctl_encode: bool,
    recovery_pending: bool,
    completion_txs: Vec<Sender<QueueCompletion>>,
    workers: Vec<QueueWorkerHandle>,
    start_handle: Option<JoinHandle<anyhow::Result<()>>>,
    start_deadline: Option<Instant>,
    start_result: Option<anyhow::Result<()>>,
    shutdown: bool,
}

pub struct UblkQueueRuntime {
    dev_id: u32,
    queue_count: u16,
    queue_depth: u16,
    block_size: usize,
    block_count: usize,
    max_io_bytes: usize,
    ioctl_encode: bool,
    buffers: QueueBuffers,
    request_rxs: Vec<Receiver<UblkIoRequest>>,
    completion_txs: Vec<Sender<QueueCompletion>>,
}

#[derive(Debug, Clone, Copy)]
pub enum UblkOp {
    Read,
    Write,
    Flush,
    Discard,
    Unknown(u32),
}

#[derive(Debug, Clone, Copy)]
pub struct UblkIoRequest {
    pub dev_id: u32,
    pub queue_id: u16,
    pub tag: u16,
    pub op: UblkOp,
    pub sector: u64,
    pub num_sectors: u32,
}

impl UblkIoRequest {
    pub fn byte_len(&self) -> u64 {
        (self.num_sectors as u64) << 9
    }
}

struct QueueWorkerHandle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

struct QueueCompletion {
    tag: u16,
    result: i32,
}

struct RecoverDeviceParams {
    block_size: usize,
    block_count: usize,
    queue_count: u16,
    queue_depth: u16,
    max_io_bytes: u32,
    ioctl_encode: bool,
}

pub type UblkBuffer<'a> = BufferGuard<'a>;

impl SmooUblk {
    pub fn max_io_bytes_hint(block_size: usize, queue_depth: u16) -> anyhow::Result<usize> {
        compute_max_io_bytes(block_size, queue_depth, None)
    }

    /// Request that Drop skips issuing STOP/DEL so user-recovery can proceed.
    pub fn preserve_devices_on_drop(&mut self) {
        self.preserve_on_drop = true;
    }

    pub async fn owner_pid(&self, dev_id: u32) -> anyhow::Result<i32> {
        let info = self.get_device_info(dev_id).await?;
        Ok(info.ublksrv_pid)
    }

    pub fn new() -> anyhow::Result<Self> {
        let ublk_ctrl = File::options().write(true).open("/dev/ublk-control")?;
        let (sender, receiver) = async_channel::unbounded::<CtrlCommand>();
        // Control loop pumps multiple outstanding ops to /dev/ublk-control
        let mut ring: IoUring<io_uring::squeue::Entry128, _> =
            IoUring::<io_uring::squeue::Entry128>::builder().build(CTRL_RING_DEPTH)?;

        let span = tracing::span!(Level::INFO, "ublk-ctrl");
        let handle = std::thread::spawn(move || {
            let _enter = span.enter();
            info!("starting loop");
            let mut next_cmd_id: u64 = 1;
            let mut pending: HashMap<u64, PendingCtrl> = HashMap::new();
            let mut timeout_lookup: HashMap<u64, u64> = HashMap::new();
            let mut cancel_lookup: HashMap<u64, u64> = HashMap::new();
            let mut needs_submit = false;
            loop {
                // Drain new commands quickly
                while let Ok((opcode, cmd, reply, timeout)) = receiver.try_recv() {
                    let cmd_id = next_cmd_id;
                    next_cmd_id = next_cmd_id.wrapping_add(1);
                    match queue_ctrl_cmd(
                        &mut ring,
                        &mut pending,
                        &mut timeout_lookup,
                        cmd_id,
                        opcode,
                        cmd,
                        reply,
                        timeout,
                        ublk_ctrl.as_raw_fd(),
                    ) {
                        Ok(()) => {
                            needs_submit = true;
                        }
                        Err(err) => {
                            error!(opcode, error = ?err, "queue ctrl cmd failed");
                        }
                    }
                }

                if needs_submit {
                    if let Err(e) = ring.submitter().submit() {
                        error!("submit ctrl SQEs failed: {}", e);
                    }
                    needs_submit = false;
                }

                // Process completions
                let mut saw_completion = false;
                let mut pending_cancels: Vec<(u64, u64)> = Vec::new();
                while let Some(cqe) = ring.completion().next() {
                    saw_completion = true;
                    let user_data = cqe.user_data();
                    let res = cqe.result();
                    if let Some(pending_cmd) = pending.remove(&user_data) {
                        clear_lookup(user_data, &mut timeout_lookup, &mut cancel_lookup);
                        pending_cmd.resolve(res);
                        continue;
                    }
                    if let Some(cmd_user_data) = timeout_lookup.remove(&user_data) {
                        trace!(cmd_user_data, res, "ctrl timeout completion");
                        if let Some(pending_cmd) = pending.remove(&cmd_user_data) {
                            let cancel_ud = pending_cmd.cancel_user_data();
                            if let Some(cancel_ud) = cancel_ud {
                                pending_cancels.push((cmd_user_data, cancel_ud));
                                cancel_lookup.insert(cancel_ud, cmd_user_data);
                            }
                            pending_cmd.resolve(-libc::ETIME);
                        }
                        continue;
                    }
                    if let Some(cmd_user_data) = cancel_lookup.remove(&user_data) {
                        trace!(cmd_user_data, res, "ctrl cancel completion");
                        continue;
                    }
                    trace!(user_data, res, "ctrl extra completion");
                }
                for (target_ud, cancel_ud) in pending_cancels.drain(..) {
                    if let Err(err) = submit_ctrl_cancel(&mut ring, target_ud, cancel_ud) {
                        warn!(target_ud, error = ?err, "ctrl cancel submit failed");
                    }
                }

                if receiver.is_closed() && pending.is_empty() {
                    info!("smoo-gadget-ublk ctrl loop shutting down");
                    break;
                }

                // Avoid tight spinning when pending but no completions
                if pending.is_empty() {
                    match receiver.recv_blocking() {
                        Ok((opcode, cmd, reply, timeout)) => {
                            let cmd_id = next_cmd_id;
                            next_cmd_id = next_cmd_id.wrapping_add(1);
                            if let Err(err) = queue_ctrl_cmd(
                                &mut ring,
                                &mut pending,
                                &mut timeout_lookup,
                                cmd_id,
                                opcode,
                                cmd,
                                reply,
                                timeout,
                                ublk_ctrl.as_raw_fd(),
                            ) {
                                error!(opcode, error = ?err, "queue ctrl cmd failed");
                            } else {
                                needs_submit = true;
                            }
                        }
                        Err(RecvError) => {
                            info!("smoo-gadget-ublk ctrl loop shutting down");
                            break;
                        }
                    }
                } else if !saw_completion {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        });

        Ok(Self {
            handle: Some(handle),
            sender,
            managed_devs: HashSet::new(),
            preserve_on_drop: false,
        })
    }

    async fn get_device_info(&self, dev_id: u32) -> anyhow::Result<ublksrv_ctrl_dev_info> {
        let mut info = ublksrv_ctrl_dev_info {
            dev_id,
            ..Default::default()
        };
        let mut cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        cmd.len = ctrl_cmd_len::<ublksrv_ctrl_dev_info>();
        cmd.addr = &mut info as *mut _ as u64;
        if let Err(err) = submit_ctrl_command(
            &self.sender,
            UBLK_CMD_GET_DEV_INFO2,
            cmd,
            "get device info",
            None,
        )
        .await
        {
            if is_errno(&err, libc::EINVAL) {
                submit_ctrl_command(
                    &self.sender,
                    UBLK_CMD_GET_DEV_INFO,
                    cmd,
                    "get device info (fallback)",
                    None,
                )
                .await?;
            } else {
                return Err(err);
            }
        }
        Ok(info)
    }

    async fn get_params(&self, dev_id: u32) -> anyhow::Result<ublk_params> {
        let mut params = ublk_params {
            len: size_of::<ublk_params>() as u32,
            ..Default::default()
        };
        let mut cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        cmd.len = params.len as u16;
        cmd.addr = &mut params as *mut _ as u64;
        submit_ctrl_command(
            &self.sender,
            UBLK_CMD_GET_PARAMS,
            cmd,
            "get params",
            Some(Duration::from_secs(1)),
        )
        .await?;
        Ok(params)
    }

    pub async fn setup_device(
        &mut self,
        block_size: usize,
        block_count: usize,
        queue_count: u16,
        queue_depth: u16,
        max_io_bytes: Option<usize>,
    ) -> anyhow::Result<SmooUblkDevice> {
        debug!(
            block_size = block_size,
            block_count = block_count,
            queue_count = queue_count,
            queue_depth = queue_depth,
            "setup_device requested"
        );
        ensure!(block_size != 0, "block size must be non-zero");
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        let logical_shift = block_size.trailing_zeros() as u8;
        ensure!(
            logical_shift >= 9,
            "logical block size must be at least 512 bytes"
        );

        let total_bytes = block_count
            .checked_mul(block_size)
            .context("device capacity overflow")?;
        ensure!(
            total_bytes % 512 == 0,
            "device capacity must be divisible by 512"
        );
        let dev_sectors = (total_bytes / 512) as u64;
        let max_io_bytes = compute_max_io_bytes(block_size, queue_depth, max_io_bytes)?;
        let max_io_buf_bytes = max_io_bytes as u32;
        let buffers = QueueBuffers::new(queue_count, queue_depth, max_io_bytes)
            .context("allocate ublk buffers")?;
        let queue_buf_ptrs = buffers.raw_ptrs();

        // For now we use -1 as the dev_id, so that a fresh dev is created for us.
        // Once we support resuming this needs to change.
        let dev_id = u32::MAX;

        // ublksrv_ctrl_dev_info is passed in ublksrv_ctrl_dev_info during UBLK_CMD_ADD_DEV
        let mut info = ublksrv_ctrl_dev_info {
            dev_id,
            nr_hw_queues: queue_count,
            queue_depth,
            max_io_buf_bytes,
            ublksrv_pid: unsafe { libc::getpid() } as i32,
            ..Default::default()
        };
        info.flags |= (UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_REISSUE) as u64;

        // ublk_params is passed in ublksrv_ctrl_dev_info during UBLK_CMD_SET_PARAMS
        let mut params = ublk_params {
            len: size_of::<ublk_params>() as u32,
            types: UBLK_PARAM_TYPE_BASIC,
            basic: ublk_param_basic {
                logical_bs_shift: logical_shift,
                physical_bs_shift: logical_shift,
                io_opt_shift: logical_shift,
                io_min_shift: logical_shift,
                max_sectors: cmp::max(info.max_io_buf_bytes >> 9, 1),
                dev_sectors,
                ..Default::default()
            },
            ..Default::default()
        };

        // the ublksrv_ctrl_cmd descriptor is passed in for all UBLK_CMD_* requests.
        let mut cmd = ublksrv_ctrl_cmd {
            dev_id,
            // queue is -1 for all UBLK_CMD_* requests
            queue_id: u16::MAX,
            ..Default::default()
        };

        // We begin the process by sending ublksrv_ctrl_dev_info along in a UBLK_CMD_ADD_DEV op
        cmd.len = ctrl_cmd_len::<sys::ublksrv_ctrl_dev_info>();
        cmd.addr = &raw mut info as _;
        submit_ctrl_command(&self.sender, UBLK_CMD_ADD_DEV, cmd, "add device", None).await?;
        debug!(dev_id = info.dev_id, "add_dev completed");

        // Whilst completing our UBLK_CMD_ADD_DEV op, the kernel wrote our true dev_id into the
        // ublksrv_ctrl_dev_info struct.
        let dev_id = info.dev_id as u32;
        cmd.dev_id = dev_id;
        self.managed_devs.insert(dev_id);

        // Now we pass the ublk_params in a UBLK_CMD_SET_PARAMS to inform ublk of geometry/capacity.
        cmd.len = params.len as _;
        cmd.addr = &raw mut params as _;
        submit_ctrl_command(&self.sender, UBLK_CMD_SET_PARAMS, cmd, "set params", None).await?;

        let ioctl_encode = (info.flags & (sys::UBLK_F_CMD_IOCTL_ENCODE as u64)) != 0;
        let max_io_bytes =
            usize::try_from(info.max_io_buf_bytes).context("max_io_buf_bytes overflow")?;
        let cdev_path = format!("/dev/ublkc{dev_id}");
        let base_cdev = File::options()
            .read(true)
            .write(true)
            .open(&cdev_path)
            .with_context(|| format!("open {cdev_path}"))?;
        let mut request_rxs = Vec::with_capacity(queue_count as usize);
        let mut completion_txs = Vec::with_capacity(queue_count as usize);
        let mut workers = Vec::with_capacity(queue_count as usize);
        let mut ready_rxs = Vec::with_capacity(queue_count as usize);

        for queue_id in 0..queue_count {
            let (request_tx, request_rx) = async_channel::unbounded::<UblkIoRequest>();
            request_rxs.push(request_rx);
            let (complete_tx, complete_rx) = async_channel::unbounded::<QueueCompletion>();
            let stop = Arc::new(AtomicBool::new(false));
            let (ready_tx, ready_rx) = mpsc::channel();
            let cdev = base_cdev
                .try_clone()
                .with_context(|| format!("clone {cdev_path}"))?;
            let start = queue_id as usize * queue_depth as usize;
            let end = start + queue_depth as usize;
            let buf_ptrs = queue_buf_ptrs[start..end].to_vec();
            let worker_cfg = QueueWorkerConfig {
                dev_id,
                queue_id,
                queue_depth,
                ioctl_encode,
                buf_ptrs,
                request_tx,
                completion_rx: complete_rx,
                stop: stop.clone(),
                cdev,
                ready_tx,
            };
            debug!(queue_id = queue_id, "spawning queue worker");
            let thread = spawn_queue_worker(worker_cfg)?;
            completion_txs.push(complete_tx);
            workers.push(QueueWorkerHandle { stop, thread });
            ready_rxs.push(ready_rx);
        }

        for (queue_idx, ready_rx) in ready_rxs.into_iter().enumerate() {
            ready_rx.recv().context("queue worker init failed")?;
            debug!(
                queue_ready = true,
                queue_id = queue_idx,
                "queue worker ready"
            );
        }

        let queues = Arc::new(UblkQueueRuntime {
            dev_id,
            queue_count,
            queue_depth,
            block_size,
            block_count,
            max_io_bytes,
            ioctl_encode,
            buffers,
            request_rxs,
            completion_txs: completion_txs.clone(),
        });

        let mut ctrl = UblkCtrlHandle {
            dev_id,
            queue_count,
            queue_depth,
            ioctl_encode,
            recovery_pending: false,
            completion_txs,
            workers,
            start_handle: None,
            start_deadline: None,
            start_result: None,
            shutdown: false,
        };

        cmd.len = 0;
        cmd.addr = 0;
        cmd.data[0] = unsafe { libc::getpid() } as u64;
        let ctrl_sender = self.sender.clone();
        let start_cmd = cmd;
        let start_thread = std::thread::Builder::new()
            .name(format!("smoo-gadget-ublk-start-{dev_id}"))
            .spawn(move || {
                info!(dev_id = dev_id, "start_dev thread begin");
                let res = submit_ctrl_command_blocking(
                    &ctrl_sender,
                    UBLK_CMD_START_DEV,
                    start_cmd,
                    "start device",
                );
                match &res {
                    Ok(()) => info!(dev_id = dev_id, "start_dev completed"),
                    Err(err) => error!(dev_id = dev_id, "start_dev failed: {:?}", err),
                }
                res
            })
            .context("spawn start_dev thread")?;

        ctrl.start_deadline = Some(Instant::now() + START_DEV_TIMEOUT);
        ctrl.start_handle = Some(start_thread);
        Ok(SmooUblkDevice { ctrl, queues })
    }

    /// Attempt to recover a previously configured ublk device using kernel-queryable metadata.
    pub async fn recover_existing_device(&mut self, dev_id: u32) -> anyhow::Result<SmooUblkDevice> {
        let info = self
            .get_device_info(dev_id)
            .await
            .context("query ublk device info")?;
        let params = self
            .get_params(dev_id)
            .await
            .context("query ublk device params")?;
        let queue_count = info.nr_hw_queues;
        let queue_depth = info.queue_depth;
        let ioctl_encode = (info.flags & (sys::UBLK_F_CMD_IOCTL_ENCODE as u64)) != 0;
        let block_size_shift = params.basic.logical_bs_shift;
        ensure!(block_size_shift >= 9, "invalid logical block size shift");
        let block_size = 1usize << block_size_shift;
        let dev_sectors = params.basic.dev_sectors;
        ensure!(dev_sectors > 0, "device reports zero sectors");
        let total_bytes = dev_sectors
            .checked_mul(512)
            .context("device size overflow")?;
        ensure!(
            total_bytes % block_size as u64 == 0,
            "device size not aligned to block size"
        );
        let block_count =
            usize::try_from(total_bytes / block_size as u64).context("block_count overflow")?;
        let params = RecoverDeviceParams {
            block_size,
            block_count,
            queue_count,
            queue_depth,
            max_io_bytes: info.max_io_buf_bytes,
            ioctl_encode,
        };
        self.recover_device_with_params(dev_id, params).await
    }

    async fn recover_device_with_params(
        &mut self,
        dev_id: u32,
        params: RecoverDeviceParams,
    ) -> anyhow::Result<SmooUblkDevice> {
        let RecoverDeviceParams {
            block_size,
            block_count,
            queue_count,
            queue_depth,
            max_io_bytes,
            ioctl_encode,
        } = params;
        ensure!(block_size != 0, "block size must be non-zero");
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        let logical_shift = block_size.trailing_zeros() as u8;
        ensure!(
            logical_shift >= 9,
            "logical block size must be at least 512 bytes"
        );

        let total_bytes = block_count
            .checked_mul(block_size)
            .context("device capacity overflow")?;
        ensure!(
            total_bytes % 512 == 0,
            "device capacity must be divisible by 512"
        );
        let max_io_bytes = if max_io_bytes == 0 {
            compute_max_io_bytes(block_size, queue_depth, None)?
        } else {
            normalize_max_io_bytes(block_size, max_io_bytes as usize)?
        };
        let buffers = QueueBuffers::new(queue_count, queue_depth, max_io_bytes)
            .context("allocate ublk buffers")?;
        let queue_buf_ptrs = buffers.raw_ptrs();
        self.start_user_recovery(dev_id).await?;
        let cdev_path = format!("/dev/ublkc{dev_id}");
        let base_cdev = File::options()
            .read(true)
            .write(true)
            .open(&cdev_path)
            .with_context(|| format!("open {cdev_path}"))?;
        let mut request_rxs = Vec::with_capacity(queue_count as usize);
        let mut completion_txs = Vec::with_capacity(queue_count as usize);
        let mut workers = Vec::with_capacity(queue_count as usize);
        let mut ready_rxs = Vec::with_capacity(queue_count as usize);

        for queue_id in 0..queue_count {
            let (request_tx, request_rx) = async_channel::unbounded::<UblkIoRequest>();
            request_rxs.push(request_rx);
            let (complete_tx, complete_rx) = async_channel::unbounded::<QueueCompletion>();
            let stop = Arc::new(AtomicBool::new(false));
            let (ready_tx, ready_rx) = mpsc::channel();
            let cdev = base_cdev
                .try_clone()
                .with_context(|| format!("clone {cdev_path}"))?;
            let start = queue_id as usize * queue_depth as usize;
            let end = start + queue_depth as usize;
            let buf_ptrs = queue_buf_ptrs[start..end].to_vec();
            let worker_cfg = QueueWorkerConfig {
                dev_id,
                queue_id,
                queue_depth,
                ioctl_encode,
                buf_ptrs,
                request_tx,
                completion_rx: complete_rx,
                stop: stop.clone(),
                cdev,
                ready_tx,
            };
            debug!(queue_id = queue_id, "spawning queue worker (recovery)");
            let thread = spawn_queue_worker(worker_cfg)?;
            completion_txs.push(complete_tx);
            workers.push(QueueWorkerHandle { stop, thread });
            ready_rxs.push(ready_rx);
        }

        for (queue_idx, ready_rx) in ready_rxs.into_iter().enumerate() {
            ready_rx
                .recv()
                .context("queue worker init failed (recovery)")?;
            debug!(
                queue_ready = true,
                queue_id = queue_idx,
                "queue worker ready (recovery)"
            );
        }

        let queues = Arc::new(UblkQueueRuntime {
            dev_id,
            queue_count,
            queue_depth,
            block_size,
            block_count,
            max_io_bytes,
            ioctl_encode,
            buffers,
            request_rxs,
            completion_txs: completion_txs.clone(),
        });

        let device = SmooUblkDevice {
            ctrl: UblkCtrlHandle {
                dev_id,
                queue_count,
                queue_depth,
                ioctl_encode,
                recovery_pending: true,
                completion_txs,
                workers,
                start_handle: None,
                start_deadline: None,
                start_result: Some(Ok(())),
                shutdown: false,
            },
            queues,
        };

        self.managed_devs.insert(dev_id);
        Ok(device)
    }

    pub async fn finalize_recovery(&self, device: &mut SmooUblkDevice) -> anyhow::Result<()> {
        if !device.recovery_pending() {
            return Ok(());
        }
        let dev_id = device.dev_id();
        info!(dev_id, "issuing UBLK_CMD_END_USER_RECOVERY");
        let mut cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        cmd.data[0] = unsafe { libc::getpid() } as u64;
        submit_ctrl_command(
            &self.sender,
            UBLK_CMD_END_USER_RECOVERY,
            cmd,
            "end user recovery",
            None,
        )
        .await?;
        device.mark_recovery_complete();
        Ok(())
    }

    pub async fn start_user_recovery(&self, dev_id: u32) -> anyhow::Result<()> {
        let mut cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        cmd.data[0] = unsafe { libc::getpid() } as u64;
        info!(dev_id, "issuing UBLK_CMD_START_USER_RECOVERY");
        submit_ctrl_command(
            &self.sender,
            UBLK_CMD_START_USER_RECOVERY,
            cmd,
            "start user recovery",
            None,
        )
        .await
    }

    /// Gracefully stop a running device and optionally delete the control node.
    ///
    /// All queue workers and io_uring resources are torn down before
    /// sending `UBLK_CMD_STOP_DEV`, matching the kernel contract documented in
    /// `Documentation/block/ublk.rst`. When `delete_ctrl` is true, a follow-up
    /// `UBLK_CMD_DEL_DEV` removes the control character device so `/dev/ublkc*`
    /// disappears as well.
    pub async fn stop_dev(
        &mut self,
        mut device: SmooUblkDevice,
        delete_ctrl: bool,
    ) -> anyhow::Result<()> {
        let dev_id = device.dev_id();
        device.shutdown();
        drop(device);

        let cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        submit_ctrl_command(&self.sender, UBLK_CMD_STOP_DEV, cmd, "stop device", None).await?;

        if delete_ctrl {
            let del_cmd = ublksrv_ctrl_cmd {
                dev_id,
                queue_id: u16::MAX,
                ..Default::default()
            };
            submit_ctrl_command(
                &self.sender,
                UBLK_CMD_DEL_DEV,
                del_cmd,
                "delete device",
                None,
            )
            .await?;
        }

        self.managed_devs.remove(&dev_id);
        Ok(())
    }

    pub async fn force_remove_device(&mut self, dev_id: u32) -> anyhow::Result<()> {
        let cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        if let Err(err) =
            submit_ctrl_command(&self.sender, UBLK_CMD_STOP_DEV, cmd, "stop device", None).await
        {
            warn!(dev_id, error = ?err, "force stop failed");
        }
        let cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        if let Err(err) =
            submit_ctrl_command(&self.sender, UBLK_CMD_DEL_DEV, cmd, "delete device", None).await
        {
            warn!(dev_id, error = ?err, "force delete failed");
        }
        self.managed_devs.remove(&dev_id);
        Ok(())
    }
}

impl Drop for SmooUblk {
    fn drop(&mut self) {
        if !self.preserve_on_drop {
            self.teardown_managed_devices();
        }
        self.sender.close();
        if let Some(handle) = self.handle.take()
            && let Err(err) = handle.join()
        {
            warn!("smoo-gadget-ublk ctrl loop panicked: {:?}", err);
        }
    }
}

impl SmooUblk {
    fn teardown_managed_devices(&mut self) {
        let dev_ids: Vec<u32> = self.managed_devs.drain().collect();
        for dev_id in dev_ids {
            if let Err(err) = self.stop_and_delete_blocking(dev_id) {
                warn!(dev_id, error = ?err, "drop cleanup failed; ublk device may persist");
            }
        }
    }

    fn stop_and_delete_blocking(&self, dev_id: u32) -> anyhow::Result<()> {
        let mut stop_err = None;
        let mut del_err = None;

        let stop_cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        if let Err(err) =
            submit_ctrl_command_blocking(&self.sender, UBLK_CMD_STOP_DEV, stop_cmd, "stop device")
        {
            warn!(dev_id, error = ?err, "drop STOP_DEV failed");
            stop_err = Some(err);
        }

        let del_cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        if let Err(err) =
            submit_ctrl_command_blocking(&self.sender, UBLK_CMD_DEL_DEV, del_cmd, "delete device")
        {
            warn!(dev_id, error = ?err, "drop DEL_DEV failed");
            del_err = Some(err);
        }

        stop_err.or(del_err).map_or(Ok(()), Err)
    }
}

impl SmooUblkDevice {
    pub fn dev_id(&self) -> u32 {
        self.ctrl.dev_id()
    }

    pub fn queue_count(&self) -> u16 {
        self.ctrl.queue_count()
    }

    pub fn queue_depth(&self) -> u16 {
        self.ctrl.queue_depth()
    }

    pub fn block_size(&self) -> usize {
        self.queues.block_size()
    }

    pub fn block_count(&self) -> usize {
        self.queues.block_count()
    }

    pub fn max_io_bytes(&self) -> usize {
        self.queues.max_io_bytes()
    }

    pub fn buffer_len(&self) -> usize {
        self.queues.buffer_len()
    }

    pub fn recovery_pending(&self) -> bool {
        self.ctrl.recovery_pending()
    }

    fn mark_recovery_complete(&mut self) {
        self.ctrl.mark_recovery_complete();
    }

    pub fn ioctl_encode(&self) -> bool {
        self.ctrl.ioctl_encode()
    }

    pub fn checkout_buffer(&self, queue_id: u16, tag: u16) -> anyhow::Result<UblkBuffer<'_>> {
        self.queues.checkout_buffer(queue_id, tag)
    }

    pub async fn next_io(&self, queue_id: u16) -> anyhow::Result<UblkIoRequest> {
        self.queues.next_io(queue_id).await
    }

    pub fn complete_io(&self, request: UblkIoRequest, result: i32) -> anyhow::Result<()> {
        self.queues.complete_io(request, result)
    }

    pub fn queues(&self) -> Arc<UblkQueueRuntime> {
        self.queues.clone()
    }

    pub fn into_parts(self) -> (UblkCtrlHandle, Arc<UblkQueueRuntime>) {
        let this = ManuallyDrop::new(self);
        // Safe because ManuallyDrop prevents Drop; we take ownership of the fields.
        let ctrl = unsafe { std::ptr::read(&this.ctrl) };
        let queues = unsafe { std::ptr::read(&this.queues) };
        (ctrl, queues)
    }

    pub fn from_parts(ctrl: UblkCtrlHandle, queues: Arc<UblkQueueRuntime>) -> Self {
        Self { ctrl, queues }
    }

    fn shutdown(&mut self) {
        self.ctrl.shutdown();
    }
}

impl Drop for SmooUblkDevice {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl UblkCtrlHandle {
    pub fn dev_id(&self) -> u32 {
        self.dev_id
    }

    pub fn queue_count(&self) -> u16 {
        self.queue_count
    }

    pub fn queue_depth(&self) -> u16 {
        self.queue_depth
    }

    pub fn recovery_pending(&self) -> bool {
        self.recovery_pending
    }

    pub fn ioctl_encode(&self) -> bool {
        self.ioctl_encode
    }

    pub fn mark_recovery_complete(&mut self) {
        self.recovery_pending = false;
    }

    pub fn poll_start_result(&mut self) -> Option<anyhow::Result<()>> {
        if self.start_result.is_some() {
            return self.start_result.take();
        }
        if let Some(handle) = &self.start_handle {
            if handle.is_finished() {
                let handle = self.start_handle.take();
                let join_result = handle
                    .expect("start_handle vanished after is_finished check")
                    .join();
                let result = match join_result {
                    Ok(res) => res,
                    Err(err) => Err(anyhow!("start_dev thread panicked: {err:?}")),
                };
                self.start_result = Some(result);
                self.start_deadline = None;
                return self.start_result.take();
            }
        }
        None
    }

    pub fn start_deadline_passed(&self, now: Instant) -> bool {
        self.start_deadline
            .map(|deadline| now >= deadline)
            .unwrap_or(false)
    }

    pub fn mark_start_timed_out(&mut self) {
        if self.start_result.is_none() {
            self.start_result = Some(Err(anyhow!(
                "UBLK_CMD_START_DEV timed out after {START_DEV_TIMEOUT:?}"
            )));
        }
        self.start_deadline = None;
        self.start_handle = None;
        self.stop_workers();
        self.shutdown = true;
    }

    pub fn shutdown(&mut self) {
        if self.shutdown {
            return;
        }
        self.shutdown = true;
        self.stop_workers();
        self.join_start_handle();
    }

    fn stop_workers(&mut self) {
        for worker in &self.workers {
            worker.stop.store(true, Ordering::SeqCst);
        }
        for sender in &self.completion_txs {
            sender.close();
        }
        for worker in self.workers.drain(..) {
            if let Err(e) = worker.thread.join() {
                error!("queue worker join failed: {:?}", e);
            }
        }
    }

    fn join_start_handle(&mut self) {
        if let Some(handle) = self.start_handle.take() {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!("start_dev thread failed: {:?}", err),
                Err(err) => error!("start_dev thread join failed: {:?}", err),
            }
        }
    }
}

impl Drop for UblkCtrlHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl UblkQueueRuntime {
    pub fn dev_id(&self) -> u32 {
        self.dev_id
    }

    pub fn queue_count(&self) -> u16 {
        self.queue_count
    }

    pub fn queue_depth(&self) -> u16 {
        self.queue_depth
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn block_count(&self) -> usize {
        self.block_count
    }

    pub fn max_io_bytes(&self) -> usize {
        self.max_io_bytes
    }

    pub fn buffer_len(&self) -> usize {
        self.buffers.buffer_len()
    }

    pub fn ioctl_encode(&self) -> bool {
        self.ioctl_encode
    }

    pub fn checkout_buffer(&self, queue_id: u16, tag: u16) -> anyhow::Result<UblkBuffer<'_>> {
        self.buffers
            .checkout(queue_id, tag)
            .context("checkout ublk buffer")
    }

    pub async fn next_io(&self, queue_id: u16) -> anyhow::Result<UblkIoRequest> {
        let receiver = self
            .request_rxs
            .get(queue_id as usize)
            .context("invalid queue id")?;
        let req = receiver
            .recv()
            .await
            .context("smoo-gadget-ublk device channel closed")?;
        trace!(
            dev_id = req.dev_id,
            queue_id = req.queue_id,
            tag = req.tag,
            op = ?req.op,
            sector = req.sector,
            num_sectors = req.num_sectors,
            "next_io"
        );
        Ok(req)
    }

    pub fn complete_io(&self, request: UblkIoRequest, result: i32) -> anyhow::Result<()> {
        let sender = self
            .completion_txs
            .get(request.queue_id as usize)
            .context("invalid queue id")?;

        trace!(
            dev_id = request.dev_id,
            queue_id = request.queue_id,
            tag = request.tag,
            result = result,
            "complete_io enqueue"
        );
        sender
            .send_blocking(QueueCompletion {
                tag: request.tag,
                result,
            })
            .context("complete queue command")
    }
}

struct QueueWorkerConfig {
    dev_id: u32,
    queue_id: u16,
    queue_depth: u16,
    ioctl_encode: bool,
    buf_ptrs: Vec<u64>,
    request_tx: Sender<UblkIoRequest>,
    completion_rx: Receiver<QueueCompletion>,
    stop: Arc<AtomicBool>,
    cdev: File,
    ready_tx: mpsc::Sender<()>,
}

struct CmdBuf {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Drop for CmdBuf {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

fn spawn_queue_worker(cfg: QueueWorkerConfig) -> anyhow::Result<JoinHandle<()>> {
    let name = format!("smoo-gadget-ublk-q{}", cfg.queue_id);
    let thread = std::thread::Builder::new().name(name).spawn(move || {
        if let Err(err) = queue_worker_main(cfg) {
            error!("queue worker exited: {:?}", err);
        }
    })?;
    Ok(thread)
}

fn queue_worker_main(cfg: QueueWorkerConfig) -> anyhow::Result<()> {
    let QueueWorkerConfig {
        dev_id,
        queue_id,
        queue_depth,
        ioctl_encode,
        buf_ptrs,
        request_tx,
        completion_rx,
        stop,
        cdev,
        ready_tx,
    } = cfg;

    debug!(
        dev_id = dev_id,
        queue_id = queue_id,
        queue_depth = queue_depth,
        "queue worker starting"
    );
    let mut ring = IoUring::<io_uring::squeue::Entry, io_uring::cqueue::Entry>::builder()
        .setup_cqsize(queue_depth as u32)
        .setup_coop_taskrun()
        .build(queue_depth as u32)?;

    let cmd_buf_sz = queue_cmd_buf_size(queue_depth as u32);
    let max_cmd_buf_sz = queue_cmd_buf_size(sys::UBLK_MAX_QUEUE_DEPTH);
    let offset = sys::UBLKSRV_CMD_BUF_OFFSET as libc::off_t
        + (queue_id as libc::off_t) * max_cmd_buf_sz as libc::off_t;
    let raw_cmd_buf = unsafe {
        libc::mmap(
            ptr::null_mut(),
            cmd_buf_sz,
            libc::PROT_READ,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            cdev.as_raw_fd(),
            offset,
        )
    };
    let raw_cmd_buf = if raw_cmd_buf == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(raw_cmd_buf)
    }
    .context("map command buffer")?;
    let cmd_buf = CmdBuf {
        ptr: raw_cmd_buf,
        len: cmd_buf_sz,
    };
    let iod_base = cmd_buf.ptr as *mut ublksrv_io_desc;
    let fd = cdev.as_raw_fd();

    for tag in 0..queue_depth {
        let cmd_addr = buf_ptrs[tag as usize];
        trace!(
            dev_id = dev_id,
            queue_id = queue_id,
            tag = tag,
            "posting initial UBLK_IO_FETCH_REQ"
        );
        queue_cmd(
            QueueCmdCtx {
                ring: &mut ring,
                fd,
                ioctl_encode,
            },
            queue_id,
            tag,
            cmd_addr,
            UBLK_U_IO_FETCH_REQ,
            -1,
        )?;
    }
    ring.submitter().submit()?;
    debug!(
        dev_id = dev_id,
        queue_id = queue_id,
        "queue worker initial fetch submitted"
    );
    let _ = ready_tx.send(());
    debug!(
        dev_id = dev_id,
        queue_id = queue_id,
        "queue worker ready signal sent"
    );

    let timeout = types::Timespec::from(Duration::from_millis(5));
    let submit_args = types::SubmitArgs::new().timespec(&timeout);

    while !stop.load(Ordering::SeqCst) {
        while let Ok(comp) = completion_rx.try_recv() {
            let cmd_addr = buf_ptrs[comp.tag as usize];
            trace!(
                dev_id = dev_id,
                queue_id = queue_id,
                tag = comp.tag,
                result = comp.result,
                "issuing COMMIT_AND_FETCH"
            );
            queue_cmd(
                QueueCmdCtx {
                    ring: &mut ring,
                    fd,
                    ioctl_encode,
                },
                queue_id,
                comp.tag,
                cmd_addr,
                UBLK_U_IO_COMMIT_AND_FETCH_REQ,
                comp.result,
            )?;
        }

        match ring.submitter().submit_with_args(1, &submit_args) {
            Ok(_) => {}
            Err(err) => {
                if matches!(err.raw_os_error(), Some(x) if x == libc::ETIME) {
                    continue;
                }
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
        }

        while let Some(cqe) = ring.completion().next() {
            let result = cqe.result();
            if result < 0 {
                warn!(
                    dev = dev_id,
                    queue = queue_id,
                    "queue cqe error: {}",
                    result
                );
                return Err(io::Error::from_raw_os_error(-result).into());
            }
            let tag = cqe.user_data() as u16;
            let desc = unsafe { ptr::read(iod_base.add(tag as usize)) };
            let request = UblkIoRequest {
                dev_id,
                queue_id,
                tag,
                op: decode_op(desc.op_flags),
                sector: desc.start_sector,
                num_sectors: desc.nr_sectors,
            };
            trace!(
                dev_id = dev_id,
                queue_id = queue_id,
                tag = tag,
                op = ?request.op,
                sector = request.sector,
                num_sectors = request.num_sectors,
                "queue received io"
            );
            if request_tx.send_blocking(request).is_err() {
                debug!(
                    dev_id = dev_id,
                    queue_id = queue_id,
                    "request channel closed, terminating queue worker"
                );
                return Ok(());
            }
        }
    }

    Ok(())
}

struct QueueCmdCtx<'ring> {
    ring: &'ring mut IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry>,
    fd: i32,
    ioctl_encode: bool,
}

fn queue_cmd(
    ctx: QueueCmdCtx<'_>,
    queue_id: u16,
    tag: u16,
    desc_addr: u64,
    opcode: u32,
    result: i32,
) -> io::Result<()> {
    let QueueCmdCtx {
        ring,
        fd,
        ioctl_encode,
    } = ctx;
    let io_cmd = ublksrv_io_cmd {
        q_id: queue_id,
        tag,
        result,
        addr: desc_addr,
    };
    trace!(
        queue_id = queue_id,
        tag = tag,
        opcode = opcode,
        result = result,
        desc_addr = desc_addr,
        "submitting uring cmd"
    );
    let cmd_bytes: [u8; 16] = unsafe { transmute(io_cmd) };
    let sqe = io_uring::opcode::UringCmd16::new(types::Fd(fd), encode_cmd_op(opcode, ioctl_encode))
        .cmd(cmd_bytes)
        .build()
        .user_data(tag as u64);

    loop {
        match unsafe { ring.submission().push(&sqe) } {
            Ok(_) => break,
            Err(_) => {
                ring.submitter().submit()?;
            }
        }
    }

    Ok(())
}

fn push_ctrl_entry(
    ring: &mut IoUring<io_uring::squeue::Entry128, cqueue::Entry>,
    entry: &io_uring::squeue::Entry128,
) -> io::Result<()> {
    loop {
        match unsafe { ring.submission().push(entry) } {
            Ok(_) => return Ok(()),
            Err(_) => {
                let _ = ring.submitter().submit()?;
            }
        }
    }
}

fn submit_ctrl_cancel(
    ring: &mut IoUring<io_uring::squeue::Entry128, cqueue::Entry>,
    target_user_data: u64,
    cancel_user_data: u64,
) -> io::Result<()> {
    let cancel_entry = squeue::Entry128::from(
        io_uring::opcode::AsyncCancel::new(target_user_data)
            .build()
            .user_data(cancel_user_data),
    );
    push_ctrl_entry(ring, &cancel_entry)?;
    ring.submitter().submit()?;
    Ok(())
}

fn ctrl_cmd_len<T>() -> u16 {
    u16::try_from(size_of::<T>()).expect("control struct larger than u16")
}

fn queue_cmd_buf_size(depth: u32) -> usize {
    let desc_bytes = depth as usize * size_of::<ublksrv_io_desc>();
    let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    if desc_bytes == 0 {
        return page_sz;
    }
    desc_bytes.div_ceil(page_sz) * page_sz
}

fn encode_cmd_op(cmd: u32, ioctl_encode: bool) -> u32 {
    if ioctl_encode { cmd } else { cmd & 0xff }
}

fn normalize_max_io_bytes(block_size: usize, max_io_bytes: usize) -> anyhow::Result<usize> {
    ensure!(max_io_bytes >= block_size, "max io bytes below block size");
    ensure!(
        max_io_bytes.is_multiple_of(block_size),
        "max io bytes must be block aligned"
    );
    ensure!(
        max_io_bytes <= u32::MAX as usize,
        "max io bytes exceeds u32::MAX"
    );
    Ok(max_io_bytes)
}

fn compute_max_io_bytes(
    block_size: usize,
    queue_depth: u16,
    max_io_bytes: Option<usize>,
) -> anyhow::Result<usize> {
    if let Some(max_io_bytes) = max_io_bytes {
        return normalize_max_io_bytes(block_size, max_io_bytes);
    }
    let queue_depth_bytes = block_size
        .checked_mul(queue_depth as usize)
        .context("queue buffer size overflow")?;
    let desired = cmp::max(block_size, queue_depth_bytes);
    Ok(cmp::min(desired, u32::MAX as usize))
}

fn decode_op(op_flags: u32) -> UblkOp {
    match op_flags & 0xff {
        UBLK_IO_OP_READ => UblkOp::Read,
        UBLK_IO_OP_WRITE => UblkOp::Write,
        UBLK_IO_OP_FLUSH => UblkOp::Flush,
        UBLK_IO_OP_DISCARD => UblkOp::Discard,
        other => UblkOp::Unknown(other),
    }
}

fn send_ctrl_reply(reply: Sender<Result<(), io::Error>>, result: Result<(), io::Error>) {
    if let Err(e) = reply.send_blocking(result) {
        trace!("ctrl reply receiver dropped: {}", e);
    }
}

fn clear_lookup(
    cmd_user_data: u64,
    timeout_lookup: &mut HashMap<u64, u64>,
    cancel_lookup: &mut HashMap<u64, u64>,
) {
    timeout_lookup.retain(|_, v| *v != cmd_user_data);
    cancel_lookup.retain(|_, v| *v != cmd_user_data);
}

#[allow(clippy::too_many_arguments)]
fn queue_ctrl_cmd(
    ring: &mut IoUring<io_uring::squeue::Entry128, cqueue::Entry>,
    pending: &mut HashMap<u64, PendingCtrl>,
    timeout_lookup: &mut HashMap<u64, u64>,
    cmd_id: u64,
    opcode: u32,
    cmd: ublksrv_ctrl_cmd,
    reply: Sender<Result<(), io::Error>>,
    timeout: Option<Duration>,
    fd: i32,
) -> anyhow::Result<()> {
    let cmd_bytes_len = size_of::<sys::ublksrv_ctrl_cmd>();
    assert!(cmd_bytes_len <= 80, "ublksrv_ctrl_cmd larger than 80 bytes");
    let mut cmd_buf = [0u8; 80];
    let raw_cmd = unsafe {
        std::slice::from_raw_parts(
            (&cmd as *const sys::ublksrv_ctrl_cmd).cast::<u8>(),
            cmd_bytes_len,
        )
    };
    cmd_buf[..cmd_bytes_len].copy_from_slice(raw_cmd);

    let cmd_user_data = cmd_id << 2;
    let timeout_user_data = cmd_user_data | 1;
    let cancel_user_data = cmd_user_data | 2;

    let mut cmd_entry = io_uring::opcode::UringCmd80::new(io_uring::types::Fd(fd), opcode)
        .cmd(cmd_buf)
        .build()
        .user_data(cmd_user_data);

    if timeout.is_some() {
        cmd_entry = cmd_entry.flags(squeue::Flags::IO_LINK);
    }

    if let Err(e) = push_ctrl_entry(ring, &cmd_entry) {
        let err = io::Error::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EIO));
        send_ctrl_reply(reply, Err(err));
        return Ok(());
    }

    if let Some(duration) = timeout {
        let ts = types::Timespec::from(duration);
        let timeout_entry = squeue::Entry128::from(
            io_uring::opcode::LinkTimeout::new(&ts)
                .build()
                .user_data(timeout_user_data),
        );
        if let Err(e) = push_ctrl_entry(ring, &timeout_entry) {
            let err = io::Error::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EIO));
            send_ctrl_reply(reply, Err(err));
            return Ok(());
        }
        timeout_lookup.insert(timeout_user_data, cmd_user_data);
    }

    let pending_ctrl = PendingCtrl {
        reply: reply.clone(),
        _opcode: opcode,
        _cmd_user_data: cmd_user_data,
        _timeout_user_data: timeout.map(|_| timeout_user_data),
        cancel_user_data: timeout.map(|_| cancel_user_data),
    };
    pending.insert(cmd_user_data, pending_ctrl);
    Ok(())
}

async fn submit_ctrl_command(
    sender: &Sender<CtrlCommand>,
    opcode: u32,
    cmd: ublksrv_ctrl_cmd,
    label: &'static str,
    timeout: Option<Duration>,
) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = async_channel::bounded::<Result<(), io::Error>>(1);
    debug!(
        opcode = opcode,
        dev_id = cmd.dev_id,
        queue_id = cmd.queue_id,
        len = cmd.len,
        addr = cmd.addr,
        timeout_ms = timeout.map(|t| t.as_millis() as u64),
        "{label} submitting"
    );
    sender
        .send((opcode, cmd, reply_tx, timeout))
        .await
        .context("send ctrl command")?;
    let res = reply_rx
        .recv()
        .await
        .context("ctrl loop closed")?
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{label} failed"));
    match &res {
        Ok(_) => debug!(opcode = opcode, "{label} succeeded"),
        Err(err) => debug!(opcode = opcode, error = ?err, "{label} failed"),
    }
    res?;
    Ok(())
}

fn submit_ctrl_command_blocking(
    sender: &Sender<CtrlCommand>,
    opcode: u32,
    cmd: ublksrv_ctrl_cmd,
    label: &'static str,
) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = async_channel::bounded::<Result<(), io::Error>>(1);
    debug!(
        opcode = opcode,
        dev_id = cmd.dev_id,
        queue_id = cmd.queue_id,
        len = cmd.len,
        addr = cmd.addr,
        "{label} submitting"
    );
    sender
        .send_blocking((opcode, cmd, reply_tx, None))
        .context("send ctrl command blocking")?;
    reply_rx
        .recv_blocking()
        .context("ctrl loop closed")?
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{label} failed"))?;
    Ok(())
}

fn is_errno(err: &anyhow::Error, code: i32) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .and_then(|io_err| io_err.raw_os_error())
        == Some(code)
}
