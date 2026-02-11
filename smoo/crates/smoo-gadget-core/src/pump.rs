//! Serialized gadget-side I/O pump.

use crate::{SmooGadget, UblkIoRequest, UblkQueueRuntime};
use anyhow::{Result, anyhow};
use smoo_proto::{OpCode, Request};
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{trace, warn};

/// Work item executed by the I/O pump.
pub struct IoWork {
    pub ublk_request: UblkIoRequest,
    pub request: Request,
    pub req_len: usize,
    pub block_size: usize,
    pub queue_id: u16,
    pub tag: u16,
    pub op: OpCode,
    pub queues: Arc<UblkQueueRuntime>,
}

struct IoCommand {
    work: IoWork,
    completion: oneshot::Sender<Result<()>>,
}

/// Single-owner handle to the background I/O pump.
pub struct IoPumpHandle {
    tx: mpsc::Sender<IoCommand>,
}

impl Clone for IoPumpHandle {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl IoPumpHandle {
    /// Spawn a pump bound to the provided gadget and channel capacity.
    pub fn spawn(gadget: Arc<SmooGadget>, capacity: usize) -> (Self, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(capacity);
        let join = tokio::spawn(run_pump(gadget, rx));
        (Self { tx }, join)
    }

    /// Submit a work item and await its completion.
    pub async fn submit(&self, work: IoWork) -> Result<()> {
        let (completion, rx) = oneshot::channel();
        self.tx
            .send(IoCommand { work, completion })
            .await
            .map_err(|_| anyhow!("io pump stopped"))?;
        rx.await.map_err(|_| anyhow!("io pump dropped result"))?
    }
}

async fn run_pump(gadget: Arc<SmooGadget>, mut rx: mpsc::Receiver<IoCommand>) {
    while let Some(cmd) = rx.recv().await {
        let result = process_one(&gadget, cmd.work).await;
        if cmd.completion.send(result).is_err() {
            trace!("io pump: completion receiver dropped");
        }
    }
    trace!("io pump: channel closed; exiting");
}

async fn process_one(gadget: &SmooGadget, work: IoWork) -> Result<()> {
    trace!(
        export_id = work.request.export_id,
        request_id = work.request.request_id,
        queue = work.queue_id,
        tag = work.tag,
        op = ?work.op,
        bytes = work.req_len,
        "io pump: begin"
    );

    gadget
        .send_request(work.request)
        .await
        .map_err(|err| anyhow!("send smoo request: {err:#}"))?;

    if work.op == OpCode::Write && work.req_len > 0 {
        let mut buffer = work
            .queues
            .checkout_buffer(work.queue_id, work.tag)
            .map_err(|err| anyhow!("checkout buffer for write: {err:#}"))?;
        gadget
            .write_bulk_buffer(&mut buffer.as_mut_slice()[..work.req_len])
            .await
            .map_err(|err| anyhow!("bulk IN write failed: {err:#}"))?;
    }

    let response = gadget
        .read_response()
        .await
        .map_err(|err| anyhow!("read response failed: {err:#}"))?;
    if response.export_id != work.request.export_id
        || response.request_id != work.request.request_id
    {
        return Err(anyhow!(
            "response mismatch: expected ({}, {}), got ({}, {})",
            work.request.export_id,
            work.request.request_id,
            response.export_id,
            response.request_id
        ));
    }
    if response.op != work.op {
        return Err(anyhow!(
            "response opcode mismatch: expected {:?}, got {:?}",
            work.op,
            response.op
        ));
    }

    let mut status = if response.status == 0 {
        if matches!(response.op, OpCode::Read | OpCode::Write) {
            let reported = (response.num_blocks as usize).saturating_mul(work.block_size);
            i32::try_from(reported.min(work.req_len)).unwrap_or(i32::MAX)
        } else {
            0
        }
    } else {
        -i32::from(response.status)
    };

    if response.op == OpCode::Read && status > 0 && work.req_len > 0 {
        let read_len = usize::try_from(status)
            .unwrap_or(work.req_len)
            .min(work.req_len);
        let mut buffer = work
            .queues
            .checkout_buffer(work.queue_id, work.tag)
            .map_err(|err| anyhow!("checkout buffer for read: {err:#}"))?;
        gadget
            .read_bulk_buffer(&mut buffer.as_mut_slice()[..read_len])
            .await
            .map_err(|err| anyhow!("bulk OUT read failed: {err:#}"))?;
        status = i32::try_from(read_len).unwrap_or(i32::MAX);
    }

    work.queues
        .complete_io(work.ublk_request, status)
        .map_err(|err| anyhow!("complete ublk io failed: {err:#}"))?;

    if status < 0 {
        warn!(
            export_id = work.request.export_id,
            request_id = work.request.request_id,
            status,
            "io pump: request completed with error"
        );
    } else {
        trace!(
            export_id = work.request.export_id,
            request_id = work.request.request_id,
            status,
            "io pump: request completed"
        );
    }

    Ok(())
}
