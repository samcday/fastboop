use crate::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, ControlTransport, Transport,
    TransportError, TransportErrorKind,
    control::{ConfigExportsV0, fetch_ident, send_config_exports_v0},
};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt;
use smoo_proto::{OpCode, REQUEST_LEN, RESPONSE_LEN, Request, Response};
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

/// Core host driver tying a [`Transport`] to one or more [`BlockSource`]s.
///
/// This implementation is intentionally serialized for correctness: one Request
/// is processed end-to-end at a time (interrupt in -> optional bulk in ->
/// block source -> interrupt out -> optional bulk out).
pub struct SmooHost<T, S> {
    transport: T,
    sources: BTreeMap<u32, S>,
    ident: Option<smoo_proto::Ident>,
}

struct ResponseWithBulk {
    response: Response,
    bulk_out: Option<Vec<u8>>,
}

impl<T, S> SmooHost<T, S>
where
    T: Transport + Send + Sync,
    S: BlockSource + Send + Sync,
{
    pub fn new(transport: T, sources: BTreeMap<u32, S>) -> Self {
        Self {
            transport,
            sources,
            ident: None,
        }
    }

    pub fn ident(&self) -> Option<smoo_proto::Ident> {
        self.ident
    }

    /// Record a previously obtained Ident to avoid reissuing the control transfer.
    pub fn record_ident(&mut self, ident: smoo_proto::Ident) {
        self.ident = Some(ident);
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub async fn setup<C>(&mut self, control: &C) -> HostResult<smoo_proto::Ident>
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
        self.run_until_event().await
    }

    /// Wait until one request arrives (or timeout) and process it completely.
    pub async fn run_until_event(&mut self) -> HostResult<()> {
        let request = match self.read_request().await {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(err) => return Err(err),
        };
        self.process_request(request).await
    }

    async fn read_request(&self) -> HostResult<Option<Request>> {
        let mut req_buf = [0u8; REQUEST_LEN];
        match self.transport.read_interrupt(&mut req_buf).await {
            Ok(len) => {
                if len != REQUEST_LEN {
                    return Err(HostError::with_message(
                        HostErrorKind::InvalidRequest,
                        format!("request transfer truncated (expected {REQUEST_LEN}, got {len})"),
                    ));
                }
                let request = Request::decode(req_buf).map_err(|err| {
                    HostError::with_message(
                        HostErrorKind::InvalidRequest,
                        format!("decode request: {err}"),
                    )
                })?;
                Ok(Some(request))
            }
            Err(err) if err.kind() == TransportErrorKind::Timeout => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn process_request(&self, request: Request) -> HostResult<()> {
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            op = ?request.op,
            lba = request.lba,
            blocks = request.num_blocks,
            "host: received Request"
        );

        let Some(source) = self.sources.get(&request.export_id) else {
            let response = invalid_request_response(request, ERRNO_EINVAL);
            self.send_response_with_bulk(ResponseWithBulk {
                response,
                bulk_out: None,
            })
            .await?;
            return Ok(());
        };

        let response = handle_request(&self.transport, source, request).await?;
        self.send_response_with_bulk(response).await
    }

    async fn send_response_with_bulk(&self, response: ResponseWithBulk) -> HostResult<()> {
        let encoded = response.response.encode();
        let wrote = self.transport.write_interrupt(&encoded).await?;
        if wrote != RESPONSE_LEN {
            return Err(HostError::with_message(
                HostErrorKind::Transport,
                format!("response transfer truncated (expected {RESPONSE_LEN}, wrote {wrote})"),
            ));
        }
        if let Some(payload) = response.bulk_out {
            let len = payload.len();
            let wrote = self.transport.write_bulk(&payload).await?;
            if wrote != len {
                return Err(HostError::with_message(
                    HostErrorKind::Transport,
                    format!("bulk write truncated (expected {len}, wrote {wrote})"),
                ));
            }
        }
        Ok(())
    }
}

const ERRNO_EINVAL: u32 = 22;
const ERRNO_EIO: u32 = 5;
const ERRNO_EOPNOTSUPP: u32 = 95;

async fn handle_request<T, S>(
    transport: &T,
    source: &S,
    request: Request,
) -> HostResult<ResponseWithBulk>
where
    T: Transport + Send + Sync,
    S: BlockSource + Send + Sync,
{
    match request.op {
        OpCode::Read => handle_read(source, request).await,
        OpCode::Write => handle_write(transport, source, request).await,
        OpCode::Flush => match source.flush().await {
            Ok(()) => Ok(ResponseWithBulk {
                response: Response::new(
                    request.export_id,
                    request.request_id,
                    OpCode::Flush,
                    0,
                    request.lba,
                    request.num_blocks,
                    0,
                ),
                bulk_out: None,
            }),
            Err(err) => Ok(ResponseWithBulk {
                response: response_from_block_error(request, err),
                bulk_out: None,
            }),
        },
        OpCode::Discard => match source.discard(request.lba, request.num_blocks).await {
            Ok(()) => Ok(ResponseWithBulk {
                response: Response::new(
                    request.export_id,
                    request.request_id,
                    OpCode::Discard,
                    0,
                    request.lba,
                    request.num_blocks,
                    0,
                ),
                bulk_out: None,
            }),
            Err(err) => Ok(ResponseWithBulk {
                response: response_from_block_error(request, err),
                bulk_out: None,
            }),
        },
    }
}

async fn handle_read<S>(source: &S, request: Request) -> HostResult<ResponseWithBulk>
where
    S: BlockSource + Send + Sync,
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

async fn handle_write<T, S>(
    transport: &T,
    source: &S,
    request: Request,
) -> HostResult<ResponseWithBulk>
where
    T: Transport + Send + Sync,
    S: BlockSource + Send + Sync,
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
        let mut buf = vec![0u8; byte_len];
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            lba = request.lba,
            num_blocks = request.num_blocks,
            bytes = byte_len,
            "host: transport read_bulk start"
        );
        let read = transport.read_bulk(&mut buf).await?;
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
            "host: transport read_bulk done"
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
