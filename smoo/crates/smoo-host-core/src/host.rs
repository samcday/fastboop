use crate::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BulkReadHandle, ControlTransport,
    ExportIdentity, HostIoPumpHandle, HostIoPumpRequestRx, TransportError, TransportErrorKind,
    control::{ConfigExportsV0, fetch_ident, send_config_exports_v0},
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use futures_util::{future::FutureExt, stream::FuturesUnordered, stream::StreamExt};
use smoo_proto::{Ident, OpCode, Request, Response};
use tracing::trace;

/// Host error categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostErrorKind {
    Transport,
    BlockSource,
    InvalidRequest,
    Unsupported,
    NotReady,
}

/// Errors surfaced by [`SmooHost`].
#[derive(Clone, Debug)]
pub struct HostError {
    kind: HostErrorKind,
    message: Option<String>,
}

impl HostError {
    pub fn new(kind: HostErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: HostErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> HostErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

impl core::error::Error for HostError {}

impl From<TransportError> for HostError {
    fn from(err: TransportError) -> Self {
        HostError::with_message(HostErrorKind::Transport, err.to_string())
    }
}

impl From<BlockSourceError> for HostError {
    fn from(err: BlockSourceError) -> Self {
        HostError::with_message(HostErrorKind::BlockSource, err.to_string())
    }
}

pub type HostResult<T> = core::result::Result<T, HostError>;

/// Core host driver tying a [`HostIoPumpHandle`] to one or more [`BlockSource`]s.
pub struct SmooHost<S> {
    pump: HostIoPumpHandle,
    requests: HostIoPumpRequestRx,
    sources: BTreeMap<u32, S>,
    ident: Option<Ident>,
    in_flight: FuturesUnordered<InFlightFuture>,
}

type InFlightFuture = Pin<Box<dyn Future<Output = HostResult<ResponseWithBulk>> + Send>>;

struct RequestWork {
    request: Request,
    bulk_in: Option<BulkReadHandle>,
}

struct ResponseWithBulk {
    response: Response,
    bulk_out: Option<Vec<u8>>,
}

impl<S> SmooHost<S>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    pub fn new(
        pump: HostIoPumpHandle,
        requests: HostIoPumpRequestRx,
        sources: BTreeMap<u32, S>,
    ) -> Self {
        Self {
            pump,
            requests,
            sources,
            ident: None,
            in_flight: FuturesUnordered::new(),
        }
    }

    pub fn ident(&self) -> Option<Ident> {
        self.ident
    }

    /// Record a previously obtained Ident to avoid reissuing the control transfer.
    pub fn record_ident(&mut self, ident: Ident) {
        self.ident = Some(ident);
    }

    pub async fn setup<C>(&mut self, control: &C) -> HostResult<Ident>
    where
        C: ControlTransport + Sync,
    {
        if let Some(ident) = self.ident {
            return Ok(ident);
        }
        let ident = fetch_ident(control).await?;
        self.ident = Some(ident);
        Ok(ident)
    }

    /// Send an explicit v0 CONFIG_EXPORTS payload.
    pub async fn configure_exports_v0<C>(
        &mut self,
        control: &C,
        payload: &ConfigExportsV0,
    ) -> HostResult<()>
    where
        C: ControlTransport + Sync,
    {
        send_config_exports_v0(control, payload).await?;
        Ok(())
    }

    pub async fn run_once(&mut self) -> HostResult<()> {
        while let Some(resp) = self.in_flight.next().now_or_never().flatten() {
            let response = resp?;
            self.send_response_with_bulk(response).await?;
        }

        let request = match self.requests.recv().now_or_never() {
            Some(Some(req)) => req,
            Some(None) => return Err(TransportError::new(TransportErrorKind::Disconnected).into()),
            None => return Ok(()),
        };
        self.enqueue_request(request).await
    }

    /// Wait until either one in-flight response completes or one request arrives.
    pub async fn run_until_event(&mut self) -> HostResult<()> {
        while let Some(resp) = self.in_flight.next().now_or_never().flatten() {
            let response = resp?;
            self.send_response_with_bulk(response).await?;
        }

        if self.in_flight.is_empty() {
            let request = self
                .requests
                .recv()
                .await
                .ok_or_else(|| TransportError::new(TransportErrorKind::Disconnected))?;
            return self.enqueue_request(request).await;
        }

        let mut next_response = self.in_flight.next().fuse();
        let mut next_request = self.requests.recv().fuse();
        futures_util::select_biased! {
            response = next_response => {
                if let Some(response) = response {
                    let response = response?;
                    self.send_response_with_bulk(response).await?;
                    Ok(())
                } else {
                    Err(TransportError::new(TransportErrorKind::Disconnected).into())
                }
            }
            request = next_request => {
                let request = request
                    .ok_or_else(|| TransportError::new(TransportErrorKind::Disconnected))?;
                self.enqueue_request(request).await
            }
        }
    }

    async fn enqueue_request(&mut self, request: Request) -> HostResult<()> {
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            op = ?request.op,
            lba = request.lba,
            blocks = request.num_blocks,
            "host: received Request"
        );
        let source = match self.sources.get(&request.export_id).cloned() {
            Some(src) => src,
            None => {
                self.send_response_with_bulk(ResponseWithBulk {
                    response: invalid_request_response(request, ERRNO_EINVAL),
                    bulk_out: None,
                })
                .await?;
                return Ok(());
            }
        };
        let bulk_in = if request.op == OpCode::Write {
            let byte_len = match blocks_to_bytes(request.num_blocks, source.block_size()) {
                Ok(len) => len,
                Err(_) => {
                    self.send_response_with_bulk(ResponseWithBulk {
                        response: invalid_request_response(request, ERRNO_EINVAL),
                        bulk_out: None,
                    })
                    .await?;
                    return Ok(());
                }
            };
            if byte_len > 0 {
                Some(self.pump.queue_read_bulk(byte_len).await?)
            } else {
                None
            }
        } else {
            None
        };
        let pump = self.pump.clone();
        let work = RequestWork { request, bulk_in };
        self.in_flight
            .push(Box::pin(handle_request(pump, source, work)));
        Ok(())
    }

    async fn send_response_with_bulk(&self, response: ResponseWithBulk) -> HostResult<()> {
        self.pump
            .send_response_with_bulk(response.response, response.bulk_out)
            .await?;
        Ok(())
    }
}

const ERRNO_EINVAL: u32 = 22;
const ERRNO_EIO: u32 = 5;
const ERRNO_EOPNOTSUPP: u32 = 95;

async fn handle_request<S>(
    pump: HostIoPumpHandle,
    source: S,
    work: RequestWork,
) -> HostResult<ResponseWithBulk>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    match work.request.op {
        OpCode::Read => handle_read(pump, source, work.request).await,
        OpCode::Write => handle_write(pump, source, work.request, work.bulk_in).await,
        OpCode::Flush => match source.flush().await {
            Ok(()) => Ok(ResponseWithBulk {
                response: Response::new(
                    work.request.export_id,
                    work.request.request_id,
                    OpCode::Flush,
                    0,
                    work.request.lba,
                    work.request.num_blocks,
                    0,
                ),
                bulk_out: None,
            }),
            Err(err) => Ok(ResponseWithBulk {
                response: response_from_block_error(work.request, err),
                bulk_out: None,
            }),
        },
        OpCode::Discard => match source
            .discard(work.request.lba, work.request.num_blocks)
            .await
        {
            Ok(()) => Ok(ResponseWithBulk {
                response: Response::new(
                    work.request.export_id,
                    work.request.request_id,
                    OpCode::Discard,
                    0,
                    work.request.lba,
                    work.request.num_blocks,
                    0,
                ),
                bulk_out: None,
            }),
            Err(err) => Ok(ResponseWithBulk {
                response: response_from_block_error(work.request, err),
                bulk_out: None,
            }),
        },
    }
}

async fn handle_read<S>(
    _pump: HostIoPumpHandle,
    source: S,
    request: Request,
) -> HostResult<ResponseWithBulk>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    let block_size = source.block_size();
    let byte_len = match blocks_to_bytes(request.num_blocks, block_size) {
        Ok(len) => len,
        Err(_) => {
            return Ok(ResponseWithBulk {
                response: invalid_request_response(request, ERRNO_EINVAL),
                bulk_out: None,
            });
        }
    };
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        bytes = byte_len,
        "host: handling read"
    );
    let bulk_out = if byte_len > 0 {
        let mut buf: Vec<u8> = vec![0u8; byte_len];
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            lba = request.lba,
            num_blocks = request.num_blocks,
            bytes = byte_len,
            "host: blocksource read_blocks start"
        );
        let read = match source.read_blocks(request.lba, &mut buf).await {
            Ok(len) => len,
            Err(err) => {
                return Ok(ResponseWithBulk {
                    response: response_from_block_error(request, err),
                    bulk_out: None,
                });
            }
        };
        if read != byte_len {
            return Ok(ResponseWithBulk {
                response: short_io_response(request),
                bulk_out: None,
            });
        }
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            lba = request.lba,
            num_blocks = request.num_blocks,
            bytes = read,
            "host: blocksource read_blocks done"
        );
        Some(buf)
    } else {
        None
    };
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        "host: read complete"
    );
    Ok(ResponseWithBulk {
        response: Response::new(
            request.export_id,
            request.request_id,
            OpCode::Read,
            0,
            request.lba,
            request.num_blocks,
            0,
        ),
        bulk_out,
    })
}

async fn handle_write<S>(
    _pump: HostIoPumpHandle,
    source: S,
    request: Request,
    bulk_in: Option<BulkReadHandle>,
) -> HostResult<ResponseWithBulk>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    let block_size = source.block_size();
    let byte_len = match blocks_to_bytes(request.num_blocks, block_size) {
        Ok(len) => len,
        Err(_) => {
            return Ok(ResponseWithBulk {
                response: invalid_request_response(request, ERRNO_EINVAL),
                bulk_out: None,
            });
        }
    };
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        bytes = byte_len,
        "host: handling write"
    );
    if byte_len > 0 {
        let bulk_in = bulk_in.ok_or_else(|| {
            HostError::with_message(HostErrorKind::InvalidRequest, "missing bulk payload")
        })?;
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            lba = request.lba,
            num_blocks = request.num_blocks,
            bytes = byte_len,
            "host: pump read_bulk start"
        );
        let buf = bulk_in.recv().await?;
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            lba = request.lba,
            num_blocks = request.num_blocks,
            bytes = buf.len(),
            "host: pump read_bulk done"
        );
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            lba = request.lba,
            num_blocks = request.num_blocks,
            bytes = buf.len(),
            "host: blocksource write_blocks start"
        );
        let written = match source.write_blocks(request.lba, &buf).await {
            Ok(len) => len,
            Err(err) => {
                return Ok(ResponseWithBulk {
                    response: response_from_block_error(request, err),
                    bulk_out: None,
                });
            }
        };
        if written != byte_len {
            return Ok(ResponseWithBulk {
                response: short_io_response(request),
                bulk_out: None,
            });
        }
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            lba = request.lba,
            num_blocks = request.num_blocks,
            bytes = written,
            "host: blocksource write_blocks done"
        );
    }
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        result = %request.num_blocks,
        "host: write complete"
    );
    Ok(ResponseWithBulk {
        response: Response::new(
            request.export_id,
            request.request_id,
            OpCode::Write,
            0,
            request.lba,
            request.num_blocks,
            0,
        ),
        bulk_out: None,
    })
}

fn blocks_to_bytes(num_blocks: u32, block_size: u32) -> HostResult<usize> {
    if block_size == 0 {
        return Err(HostError::with_message(
            HostErrorKind::InvalidRequest,
            "block size is zero",
        ));
    }
    num_blocks
        .checked_mul(block_size)
        .map(|len| len as usize)
        .ok_or_else(|| {
            HostError::with_message(HostErrorKind::InvalidRequest, "request size overflow")
        })
}

fn invalid_request_response(request: Request, errno: u32) -> Response {
    Response::new(
        request.export_id,
        request.request_id,
        request.op,
        errno as u8,
        request.lba,
        request.num_blocks,
        0,
    )
}

fn short_io_response(request: Request) -> Response {
    Response::new(
        request.export_id,
        request.request_id,
        request.op,
        ERRNO_EIO as u8,
        request.lba,
        request.num_blocks,
        0,
    )
}

fn response_from_block_error(request: Request, err: BlockSourceError) -> Response {
    let errno = match err.kind() {
        BlockSourceErrorKind::InvalidInput | BlockSourceErrorKind::OutOfRange => ERRNO_EINVAL,
        BlockSourceErrorKind::Unsupported => ERRNO_EOPNOTSUPP,
        BlockSourceErrorKind::Io | BlockSourceErrorKind::Other => ERRNO_EIO,
    };
    Response::new(
        request.export_id,
        request.request_id,
        request.op,
        errno as u8,
        request.lba,
        request.num_blocks,
        0,
    )
}
