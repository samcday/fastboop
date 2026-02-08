use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

use gibblox_core::{BlockReader, ReadContext};
use gibblox_http::HttpBlockReader;

async fn start_server(data: Vec<u8>) -> (Url, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
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
                    let data = data.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |req| handle_request(req, data.clone()));
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
    data: Vec<u8>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    let total_len = data.len() as u64;
    let range = req
        .headers()
        .get(RANGE)
        .and_then(|val| val.to_str().ok())
        .and_then(parse_range);

    let (status, body, content_range) = match range {
        Some((start, end)) if start < total_len => {
            let end = end.min(total_len - 1);
            let slice = &data[start as usize..=end as usize];
            (
                StatusCode::PARTIAL_CONTENT,
                Bytes::copy_from_slice(slice),
                Some(format!("bytes {start}-{end}/{total_len}")),
            )
        }
        _ => (StatusCode::OK, Bytes::copy_from_slice(&data), None),
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
