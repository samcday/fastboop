use crate::{Transport, TransportError, TransportErrorKind, TransportResult};
use alloc::{collections::VecDeque, format, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use futures_channel::{mpsc, oneshot};
use futures_util::{
    future::{BoxFuture, Fuse, FusedFuture, FutureExt, OptionFuture, poll_fn},
    stream::{Fuse as StreamFuse, StreamExt},
};
use smoo_proto::{REQUEST_LEN, RESPONSE_LEN, Request, Response};

/// Stream of Requests produced by the pump.
pub type HostIoPumpRequestRx = mpsc::UnboundedReceiver<Request>;

/// Handle to an ordered bulk read queued on the pump.
pub struct BulkReadHandle {
    rx: oneshot::Receiver<TransportResult<Vec<u8>>>,
}

impl BulkReadHandle {
    pub async fn recv(self) -> TransportResult<Vec<u8>> {
        self.rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }
}

/// Handle used by workers to issue bulk + interrupt OUT operations through the pump.
#[derive(Clone)]
pub struct HostIoPumpHandle {
    cmd_tx: mpsc::UnboundedSender<PumpCmd>,
}

/// Future that drives the pump. Callers should spawn this on their executor of choice.
pub struct HostIoPumpTask {
    inner: BoxFuture<'static, TransportResult<()>>,
}

impl Future for HostIoPumpTask {
    type Output = TransportResult<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// Start the host I/O pump.
///
/// Returns a handle for issuing commands, a request receiver for incoming Requests, and a pump
/// future that must be spawned by the caller.
pub fn start_host_io_pump<T>(
    transport: T,
) -> (HostIoPumpHandle, HostIoPumpRequestRx, HostIoPumpTask)
where
    T: Transport + Clone + Send + Sync + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::unbounded();
    let (req_tx, req_rx) = mpsc::unbounded();
    let task = HostIoPumpTask {
        inner: run_pump(transport, cmd_rx, req_tx).boxed(),
    };
    (HostIoPumpHandle { cmd_tx }, req_rx, task)
}

impl HostIoPumpHandle {
    /// Send a Response over interrupt OUT.
    pub async fn send_response(&self, response: Response) -> TransportResult<()> {
        self.send_response_with_bulk(response, None).await
    }

    /// Send a Response and its optional bulk payload in-order.
    pub async fn send_response_with_bulk(
        &self,
        response: Response,
        bulk_out: Option<Vec<u8>>,
    ) -> TransportResult<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tracing::trace!(
            export_id = response.export_id,
            request_id = response.request_id,
            "pump: queue send_response"
        );
        self.send_cmd(PumpCmd::SendResponseWithBulk {
            response,
            bulk_out,
            reply: reply_tx,
            #[cfg(feature = "metrics")]
            start: std::time::Instant::now(),
        })
        .await?;
        reply_rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }

    /// Queue an ordered bulk read and return a handle to await the payload.
    pub async fn queue_read_bulk(&self, len: usize) -> TransportResult<BulkReadHandle> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tracing::trace!(bytes = len, "pump: queue read_bulk");
        self.send_cmd(PumpCmd::ReadBulk {
            buf: vec![0u8; len],
            reply: reply_tx,
            #[cfg(feature = "metrics")]
            start: std::time::Instant::now(),
        })
        .await?;
        Ok(BulkReadHandle { rx: reply_rx })
    }

    /// Read a bulk payload of `len` bytes from the gadget.
    pub async fn read_bulk(&self, len: usize) -> TransportResult<Vec<u8>> {
        self.queue_read_bulk(len).await?.recv().await
    }

    /// Write a bulk payload to the gadget.
    pub async fn write_bulk(&self, buf: Vec<u8>) -> TransportResult<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tracing::trace!(bytes = buf.len(), "pump: queue write_bulk");
        self.send_cmd(PumpCmd::WriteBulk {
            buf,
            reply: reply_tx,
            #[cfg(feature = "metrics")]
            start: std::time::Instant::now(),
        })
        .await?;
        reply_rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }

    /// Request a graceful pump shutdown.
    pub async fn shutdown(&self) -> TransportResult<()> {
        self.cmd_tx
            .unbounded_send(PumpCmd::Shutdown)
            .map_err(|_| disconnected_err())
    }

    async fn send_cmd(&self, cmd: PumpCmd) -> TransportResult<()> {
        self.cmd_tx
            .unbounded_send(cmd)
            .map_err(|_| disconnected_err())
    }
}

enum PumpCmd {
    SendResponseWithBulk {
        response: Response,
        bulk_out: Option<Vec<u8>>,
        reply: oneshot::Sender<TransportResult<()>>,
        #[cfg(feature = "metrics")]
        start: std::time::Instant,
    },
    ReadBulk {
        buf: Vec<u8>,
        reply: oneshot::Sender<TransportResult<Vec<u8>>>,
        #[cfg(feature = "metrics")]
        start: std::time::Instant,
    },
    WriteBulk {
        buf: Vec<u8>,
        reply: oneshot::Sender<TransportResult<()>>,
        #[cfg(feature = "metrics")]
        start: std::time::Instant,
    },
    Shutdown,
}

struct InterruptOutOp {
    response: Response,
    reply: oneshot::Sender<TransportResult<()>>,
    #[cfg(feature = "metrics")]
    start: std::time::Instant,
}

struct BulkInOp {
    buf: Vec<u8>,
    reply: oneshot::Sender<TransportResult<Vec<u8>>>,
    #[cfg(feature = "metrics")]
    start: std::time::Instant,
}

struct BulkOutOp {
    buf: Vec<u8>,
    reply: Option<oneshot::Sender<TransportResult<()>>>,
    #[cfg(feature = "metrics")]
    start: std::time::Instant,
}

type InterruptInFuture = Fuse<OptionFuture<BoxFuture<'static, TransportResult<Request>>>>;
type InterruptOutFuture = Fuse<OptionFuture<BoxFuture<'static, InterruptOutResult>>>;
type InterruptOutResult = (oneshot::Sender<TransportResult<()>>, TransportResult<()>);
type BulkInResult = (
    oneshot::Sender<TransportResult<Vec<u8>>>,
    TransportResult<Vec<u8>>,
);
type BulkOutResult = (
    Option<oneshot::Sender<TransportResult<()>>>,
    TransportResult<()>,
);

struct InFlightBulkIn {
    fut: Fuse<BoxFuture<'static, BulkInResult>>,
}

impl InFlightBulkIn {
    fn new(fut: BoxFuture<'static, BulkInResult>) -> Self {
        Self { fut: fut.fuse() }
    }
}

struct InFlightBulkOut {
    fut: Fuse<BoxFuture<'static, BulkOutResult>>,
}

impl InFlightBulkOut {
    fn new(fut: BoxFuture<'static, BulkOutResult>) -> Self {
        Self { fut: fut.fuse() }
    }
}

const BULK_IN_MAX_IN_FLIGHT: usize = 4;
const BULK_OUT_MAX_IN_FLIGHT: usize = 4;

enum PumpProgress {
    Continue,
    Finished(TransportResult<()>),
}

async fn run_pump<T>(
    transport: T,
    cmd_rx: mpsc::UnboundedReceiver<PumpCmd>,
    req_tx: mpsc::UnboundedSender<Request>,
) -> TransportResult<()>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    let mut cmd_rx: StreamFuse<mpsc::UnboundedReceiver<PumpCmd>> = cmd_rx.fuse();
    let mut interrupt_in: InterruptInFuture = arm_interrupt_in(transport.clone());
    let mut interrupt_out: InterruptOutFuture = OptionFuture::from(None).fuse();
    let mut bulk_in_inflight: VecDeque<InFlightBulkIn> = VecDeque::new();
    let mut bulk_out_inflight: VecDeque<InFlightBulkOut> = VecDeque::new();
    let mut interrupt_out_queue: VecDeque<InterruptOutOp> = VecDeque::new();
    let mut bulk_in_queue: VecDeque<BulkInOp> = VecDeque::new();
    let mut bulk_out_queue: VecDeque<BulkOutOp> = VecDeque::new();
    let mut cmd_closed = false;

    loop {
        match poll_fn(|cx| {
            poll_pump(
                cx,
                &transport,
                &mut cmd_rx,
                &mut interrupt_in,
                &mut interrupt_out,
                &mut bulk_in_inflight,
                &mut bulk_out_inflight,
                &mut interrupt_out_queue,
                &mut bulk_in_queue,
                &mut bulk_out_queue,
                &mut cmd_closed,
                &req_tx,
            )
        })
        .await?
        {
            PumpProgress::Continue => continue,
            PumpProgress::Finished(res) => break res,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn poll_pump<T>(
    cx: &mut Context<'_>,
    transport: &T,
    cmd_rx: &mut StreamFuse<mpsc::UnboundedReceiver<PumpCmd>>,
    interrupt_in: &mut InterruptInFuture,
    interrupt_out: &mut InterruptOutFuture,
    bulk_in_inflight: &mut VecDeque<InFlightBulkIn>,
    bulk_out_inflight: &mut VecDeque<InFlightBulkOut>,
    interrupt_out_queue: &mut VecDeque<InterruptOutOp>,
    bulk_in_queue: &mut VecDeque<BulkInOp>,
    bulk_out_queue: &mut VecDeque<BulkOutOp>,
    cmd_closed: &mut bool,
    req_tx: &mpsc::UnboundedSender<Request>,
) -> Poll<TransportResult<PumpProgress>>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    let mut made_progress = false;

    if interrupt_in.is_terminated() {
        *interrupt_in = arm_interrupt_in(transport.clone());
    }
    if interrupt_out.is_terminated() {
        if let Some(op) = interrupt_out_queue.pop_front() {
            *interrupt_out = arm_interrupt_out(transport.clone(), op);
        }
    }

    while bulk_in_inflight.len() < BULK_IN_MAX_IN_FLIGHT {
        if let Some(op) = bulk_in_queue.pop_front() {
            bulk_in_inflight.push_back(InFlightBulkIn::new(arm_bulk_in_future(
                transport.clone(),
                op,
            )));
        } else {
            break;
        }
    }

    while bulk_out_inflight.len() < BULK_OUT_MAX_IN_FLIGHT {
        if let Some(op) = bulk_out_queue.pop_front() {
            bulk_out_inflight.push_back(InFlightBulkOut::new(arm_bulk_out_future(
                transport.clone(),
                op,
            )));
            #[cfg(feature = "metrics")]
            crate::metrics::record_bulk_out_queue(bulk_out_queue.len() + bulk_out_inflight.len());
        } else {
            break;
        }
    }

    if let Poll::Ready(cmd) = cmd_rx.poll_next_unpin(cx) {
        match cmd {
            Some(PumpCmd::SendResponseWithBulk {
                response,
                bulk_out,
                reply,
                #[cfg(feature = "metrics")]
                start,
                ..
            }) => {
                tracing::trace!(
                    export_id = response.export_id,
                    request_id = response.request_id,
                    "pump: enqueue response"
                );
                interrupt_out_queue.push_back(InterruptOutOp {
                    response,
                    reply,
                    #[cfg(feature = "metrics")]
                    start,
                });
                if let Some(buf) = bulk_out {
                    #[cfg(feature = "metrics")]
                    crate::metrics::record_bulk_out_queue(bulk_out_queue.len() + 1);
                    bulk_out_queue.push_back(BulkOutOp {
                        buf,
                        reply: None,
                        #[cfg(feature = "metrics")]
                        start: std::time::Instant::now(),
                    });
                }
            }
            Some(PumpCmd::ReadBulk {
                buf,
                reply,
                #[cfg(feature = "metrics")]
                start,
                ..
            }) => {
                tracing::trace!(bytes = buf.len(), "pump: enqueue bulk-in");
                #[cfg(feature = "metrics")]
                crate::metrics::record_bulk_in_queue(bulk_in_queue.len() + 1);
                bulk_in_queue.push_back(BulkInOp {
                    buf,
                    reply,
                    #[cfg(feature = "metrics")]
                    start,
                });
            }
            Some(PumpCmd::WriteBulk {
                buf,
                reply,
                #[cfg(feature = "metrics")]
                start,
                ..
            }) => {
                tracing::trace!(bytes = buf.len(), "pump: enqueue bulk-out");
                #[cfg(feature = "metrics")]
                crate::metrics::record_bulk_out_queue(bulk_out_queue.len() + 1);
                bulk_out_queue.push_back(BulkOutOp {
                    buf,
                    reply: Some(reply),
                    #[cfg(feature = "metrics")]
                    start,
                });
            }
            Some(PumpCmd::Shutdown) => return Poll::Ready(Ok(PumpProgress::Finished(Ok(())))),
            None => *cmd_closed = true,
        }
        made_progress = true;
    }

    if let Poll::Ready(req) = interrupt_in.poll_unpin(cx) {
        match req {
            Some(Ok(request)) => {
                if req_tx.unbounded_send(request).is_err() {
                    return Poll::Ready(Err(disconnected_err()));
                }
            }
            Some(Err(err)) => {
                if err.kind() != TransportErrorKind::Timeout {
                    return Poll::Ready(Err(err));
                }
            }
            None => {}
        }
        made_progress = true;
    }

    if let Poll::Ready(res) = interrupt_out.poll_unpin(cx) {
        if let Some((reply, result)) = res {
            if let Err(ref err) = result {
                tracing::warn!(%err, "pump: interrupt-out failed");
            } else {
                tracing::trace!("pump: interrupt-out done");
            }
            let _ = reply.send(result);
        }
        made_progress = true;
    }

    if let Some(front) = bulk_in_inflight.front_mut() {
        if let Poll::Ready(res) = front.fut.poll_unpin(cx) {
            if let Some((reply, result)) = Some(res) {
                match &result {
                    Ok(buf) => tracing::trace!(bytes = buf.len(), "pump: bulk-in done"),
                    Err(err) => tracing::warn!(%err, "pump: bulk-in failed"),
                }
                let _ = reply.send(result);
            }
            bulk_in_inflight.pop_front();
            #[cfg(feature = "metrics")]
            crate::metrics::record_bulk_in_queue(bulk_in_queue.len() + bulk_in_inflight.len());
            made_progress = true;
        }
    }

    if let Some(front) = bulk_out_inflight.front_mut() {
        if let Poll::Ready(res) = front.fut.poll_unpin(cx) {
            if let Some((reply, result)) = Some(res) {
                if let Err(ref err) = result {
                    tracing::warn!(%err, "pump: bulk-out failed");
                } else {
                    tracing::trace!("pump: bulk-out done");
                }
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
            }
            bulk_out_inflight.pop_front();
            made_progress = true;
        }
    }

    if *cmd_closed
        && interrupt_out_queue.is_empty()
        && bulk_in_queue.is_empty()
        && bulk_out_queue.is_empty()
        && interrupt_out.is_terminated()
        && bulk_in_inflight.is_empty()
        && bulk_out_inflight.is_empty()
    {
        return Poll::Ready(Ok(PumpProgress::Finished(Ok(()))));
    }

    if made_progress {
        Poll::Ready(Ok(PumpProgress::Continue))
    } else {
        Poll::Pending
    }
}

fn arm_interrupt_in<T>(transport: T) -> InterruptInFuture
where
    T: Transport + Clone + Send + Sync + 'static,
{
    OptionFuture::from(Some(
        async move {
            #[cfg(feature = "metrics")]
            let start = std::time::Instant::now();
            let mut buf = [0u8; REQUEST_LEN];
            let len = transport.read_interrupt(&mut buf).await?;
            if len != REQUEST_LEN {
                return Err(protocol_error(format!(
                    "request transfer truncated (expected {REQUEST_LEN}, got {len})"
                )));
            }
            #[cfg(feature = "metrics")]
            crate::metrics::observe_interrupt_in(len, start.elapsed());
            Request::decode(buf).map_err(|err| protocol_error(format!("decode request: {err}")))
        }
        .boxed(),
    ))
    .fuse()
}

fn arm_interrupt_out<T>(transport: T, op: InterruptOutOp) -> InterruptOutFuture
where
    T: Transport + Clone + Send + Sync + 'static,
{
    OptionFuture::from(Some(
        async move {
            #[cfg(feature = "metrics")]
            let start = op.start;
            let data = op.response.encode();
            let reply = op.reply;
            let result = match transport.write_interrupt(&data).await {
                Ok(len) if len == RESPONSE_LEN => Ok(()),
                Ok(len) => Err(protocol_error(format!(
                    "response transfer truncated (expected {RESPONSE_LEN}, wrote {len})"
                ))),
                Err(err) => Err(err),
            };
            #[cfg(feature = "metrics")]
            if result.is_ok() {
                crate::metrics::observe_interrupt_out(data.len(), start.elapsed());
            }
            (reply, result)
        }
        .boxed(),
    ))
    .fuse()
}

fn arm_bulk_in_future<T>(transport: T, op: BulkInOp) -> BoxFuture<'static, BulkInResult>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    async move {
        #[cfg(feature = "metrics")]
        let start = op.start;
        let mut buf = op.buf;
        let reply = op.reply;
        let len = transport.read_bulk(&mut buf).await;
        let result = match len {
            Ok(read) if read == buf.len() => Ok(buf),
            Ok(read) => Err(protocol_error(format!(
                "bulk read truncated (expected {}, got {read})",
                buf.len()
            ))),
            Err(err) => Err(err),
        };
        #[cfg(feature = "metrics")]
        if let Ok(ref data) = result {
            crate::metrics::observe_bulk_in(data.len(), start.elapsed());
        }
        (reply, result)
    }
    .boxed()
}

fn arm_bulk_out_future<T>(transport: T, op: BulkOutOp) -> BoxFuture<'static, BulkOutResult>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    async move {
        #[cfg(feature = "metrics")]
        let start = op.start;
        let reply = op.reply;
        let len = op.buf.len();
        tracing::trace!(bytes = len, "pump: bulk-out transport write start");
        let result = match transport.write_bulk(&op.buf).await {
            Ok(written) if written == len => Ok(()),
            Ok(written) => Err(protocol_error(format!(
                "bulk write truncated (expected {len}, wrote {written})"
            ))),
            Err(err) => Err(err),
        };
        match &result {
            Ok(_) => tracing::trace!("pump: bulk-out transport write done"),
            Err(err) => tracing::warn!(%err, "pump: bulk-out transport write failed"),
        }
        #[cfg(feature = "metrics")]
        if result.is_ok() {
            crate::metrics::observe_bulk_out(len, start.elapsed());
        }
        (reply, result)
    }
    .boxed()
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}

fn disconnected_err() -> TransportError {
    TransportError::with_message(TransportErrorKind::Disconnected, "pump not running")
}
