use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

use gibblox_core::{BlockReader, GibbloxErrorKind, ReadContext};
use gibblox_http::HttpBlockReader;

#[derive(Clone, Copy)]
enum RangeBehavior {
    Honor,
    Ignore,
    IgnoreFirstThenHonor,
    WrongContentRange,
}

struct TestServerState {
    data: Vec<u8>,
    range_behavior: RangeBehavior,
    ranged_get_requests: AtomicUsize,
}

async fn start_server(data: Vec<u8>) -> (Url, oneshot::Sender<()>) {
    start_server_with_behavior(data, RangeBehavior::Honor).await
}

async fn start_server_with_behavior(
    data: Vec<u8>,
    range_behavior: RangeBehavior,
) -> (Url, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let state = Arc::new(TestServerState {
        data,
        range_behavior,
        ranged_get_requests: AtomicUsize::new(0),
    });
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accept = listener.accept() => {
                    let (stream, _) = match accept {
                        Ok(res) => res,
                        Err(_) => break,
                    };
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |req| handle_request(req, Arc::clone(&state)));
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    });
                }
            }
        }
    });
    let url = Url::parse(&format!("http://{addr}")).expect("url parse");
    (url, shutdown_tx)
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<TestServerState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    let total_len = state.data.len() as u64;
    let range = req
        .headers()
        .get(RANGE)
        .and_then(|val| val.to_str().ok())
        .and_then(parse_range);

    let mut ignore_range = false;
    let mut wrong_content_range = false;
    if method == Method::GET && range.is_some() {
        match state.range_behavior {
            RangeBehavior::Honor => {}
            RangeBehavior::Ignore => {
                ignore_range = true;
            }
            RangeBehavior::IgnoreFirstThenHonor => {
                let seen = state.ranged_get_requests.fetch_add(1, Ordering::SeqCst);
                ignore_range = seen == 0;
            }
            RangeBehavior::WrongContentRange => {
                wrong_content_range = true;
            }
        }
    }

    let (status, body, content_range) = match (range, ignore_range) {
        (Some((start, end)), false) if start < total_len => {
            let end = end.min(total_len - 1);
            let slice = &state.data[start as usize..=end as usize];
            let content_range = if wrong_content_range {
                let bad_start = start.saturating_add(1).min(end);
                format!("bytes {bad_start}-{end}/{total_len}")
            } else {
                format!("bytes {start}-{end}/{total_len}")
            };
            (
                StatusCode::PARTIAL_CONTENT,
                Bytes::copy_from_slice(slice),
                Some(content_range),
            )
        }
        _ => (StatusCode::OK, Bytes::copy_from_slice(&state.data), None),
    };

    let body_len = body.len();
    let response_body = if method == Method::HEAD {
        Bytes::new()
    } else {
        body
    };
    let mut resp = Response::new(Full::new(response_body));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_LENGTH, body_len.to_string().parse().unwrap());
    if let Some(range) = content_range {
        resp.headers_mut()
            .insert(CONTENT_RANGE, range.parse().unwrap());
    }
    Ok(resp)
}

fn parse_range(header: &str) -> Option<(u64, u64)> {
    let header = header.strip_prefix("bytes=")?;
    let mut parts = header.split('-');
    let start = parts.next()?.parse::<u64>().ok()?;
    let end = parts.next()?.parse::<u64>().ok()?;
    Some((start, end))
}

fn data_blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn http_read_blocks_roundtrip() {
    let data = data_blob(8192);
    let (url, shutdown) = start_server(data.clone()).await;
    let source = HttpBlockReader::new(url, 512).await.expect("http source");
    assert_eq!(source.size_bytes(), data.len() as u64);

    let mut buf = vec![0u8; 1024];
    let read = source
        .read_blocks(2, &mut buf, ReadContext::FOREGROUND)
        .await
        .expect("read blocks");
    assert_eq!(read, buf.len());
    assert_eq!(&buf[..], &data[1024..2048]);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_probe_size_uses_range() {
    let data = data_blob(4096);
    let (url, shutdown) = start_server(data.clone()).await;
    let source = HttpBlockReader::new(url, 512).await.expect("http source");
    assert_eq!(source.size_bytes(), 4096);
    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_reader_zero_pads_tail_block_for_unaligned_size() {
    let data = data_blob(4097);
    let (url, shutdown) = start_server(data.clone()).await;
    let source = HttpBlockReader::new(url, 512).await.expect("http source");

    assert_eq!(source.size_bytes(), 4097);
    assert_eq!(source.total_blocks().await.expect("total blocks"), 9);

    let mut tail = vec![0u8; 512];
    let read = source
        .read_blocks(8, &mut tail, ReadContext::FOREGROUND)
        .await
        .expect("read tail");
    assert_eq!(read, 512);
    assert_eq!(tail[0], data[4096]);
    assert!(tail[1..].iter().all(|b| *b == 0));

    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_reader_reports_out_of_range_after_last_block() {
    let data = data_blob(4097);
    let (url, shutdown) = start_server(data).await;
    let source = HttpBlockReader::new(url, 512).await.expect("http source");

    let mut buf = vec![0u8; 512];
    let err = source
        .read_blocks(9, &mut buf, ReadContext::FOREGROUND)
        .await
        .expect_err("read past end should fail");
    assert_eq!(err.kind(), GibbloxErrorKind::OutOfRange);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_reader_rejects_200_for_range_reads() {
    let data = data_blob(4096);
    let (url, shutdown) = start_server_with_behavior(data.clone(), RangeBehavior::Ignore).await;
    let source = HttpBlockReader::new_with_size(url, 512, data.len() as u64)
        .await
        .expect("http source");

    let mut buf = vec![0u8; 512];
    let err = source
        .read_blocks(2, &mut buf, ReadContext::FOREGROUND)
        .await
        .expect_err("range read should reject non-partial response");
    assert_eq!(err.kind(), GibbloxErrorKind::Io);
    assert!(err.to_string().contains("expected 206 Partial Content"));

    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_reader_retries_transient_non_partial_response() {
    let data = data_blob(4096);
    let (url, shutdown) =
        start_server_with_behavior(data.clone(), RangeBehavior::IgnoreFirstThenHonor).await;
    let source = HttpBlockReader::new_with_size(url, 512, data.len() as u64)
        .await
        .expect("http source");

    let mut buf = vec![0u8; 1024];
    let read = source
        .read_blocks(2, &mut buf, ReadContext::FOREGROUND)
        .await
        .expect("range read should succeed after retry");
    assert_eq!(read, 1024);
    assert_eq!(&buf[..], &data[1024..2048]);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_reader_rejects_mismatched_content_range_header() {
    let data = data_blob(4096);
    let (url, shutdown) =
        start_server_with_behavior(data.clone(), RangeBehavior::WrongContentRange).await;
    let source = HttpBlockReader::new_with_size(url, 512, data.len() as u64)
        .await
        .expect("http source");

    let mut buf = vec![0u8; 512];
    let err = source
        .read_blocks(2, &mut buf, ReadContext::FOREGROUND)
        .await
        .expect_err("range read should reject mismatched Content-Range");
    assert_eq!(err.kind(), GibbloxErrorKind::Io);
    assert!(err.to_string().contains("content-range mismatch"));

    let _ = shutdown.send(());
}
