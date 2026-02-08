//! The IoPump

use crate::{SmooGadget, UblkQueueRuntime};
use anyhow::{Result, anyhow};
use smoo_proto::{OpCode, Request};
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::trace;

/// Work item executed by the I/O pump.
pub struct IoWork {
    pub request: Request,
    pub req_len: usize,
    pub queue_id: u16,
    pub tag: u16,
    pub op: OpCode,
    pub queues: Arc<UblkQueueRuntime>,
    pub on_request_sent: Option<tokio::sync::oneshot::Sender<()>>,
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
    let (bulk_tx, mut bulk_rx) =
        mpsc::channel::<(IoWork, oneshot::Sender<Result<()>>)>(rx.capacity());

    let bulk_gadget = gadget.clone();
    let bulk_task = tokio::spawn(async move {
        while let Some((work, completion)) = bulk_rx.recv().await {
            let result = process_bulk(&bulk_gadget, work).await;
            if completion.send(result).is_err() {
                trace!("io pump: completion receiver dropped");
            }
        }
    });

    while let Some(mut cmd) = rx.recv().await {
        let send_result = process_send(&gadget, &mut cmd.work).await;
        if let Err(err) = send_result {
            if cmd.completion.send(Err(err)).is_err() {
                trace!("io pump: completion receiver dropped");
            }
            continue;
        }
        if bulk_tx.send((cmd.work, cmd.completion)).await.is_err() {
            trace!("io pump: bulk worker closed; exiting");
            break;
        }
    }

    drop(bulk_tx);
    let _ = bulk_task.await;
    trace!("io pump: channel closed; exiting");
}

async fn process_send(gadget: &SmooGadget, work: &mut IoWork) -> Result<()> {
    trace!(
        export_id = work.request.export_id,
        request_id = work.request.request_id,
        queue = work.queue_id,
        tag = work.tag,
        op = ?work.op,
        bytes = work.req_len,
        "io pump: dispatch request"
    );
    gadget
        .send_request(work.request)
        .await
        .map_err(|err| anyhow!("send smoo request: {err:#}"))?;

    if let Some(sent) = work.on_request_sent.take() {
        let _ = sent.send(());
    }
    Ok(())
}

async fn process_bulk(gadget: &SmooGadget, work: IoWork) -> Result<()> {
    trace!(
        export_id = work.request.export_id,
        request_id = work.request.request_id,
        queue = work.queue_id,
        tag = work.tag,
        op = ?work.op,
        bytes = work.req_len,
        "io pump: process bulk"
    );

    if work.req_len == 0 {
        return Ok(());
    }

    if work.op == OpCode::Write {
        let mut buffer = work
            .queues
            .checkout_buffer(work.queue_id, work.tag)
            .map_err(|err| anyhow!("checkout buffer for write: {err:#}"))?;
        gadget
            .write_bulk_buffer(&mut buffer.as_mut_slice()[..work.req_len])
            .await
            .map_err(|err| anyhow!("bulk write payload: {err:#}"))?;
    }

    Ok(())
}
