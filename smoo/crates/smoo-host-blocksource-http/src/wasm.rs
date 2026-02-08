use crate::HttpError;
use futures_util::FutureExt;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use js_sys::{Promise, Uint8Array};
use std::{
    future::Future,
    ops::RangeInclusive,
    pin::Pin,
    task::{Context, Poll},
};
use url::Url;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

/// Wrapper to mark `JsFuture` as `Send` on wasm targets.
struct SendJsFuture(JsFuture);

unsafe impl Send for SendJsFuture {}

impl From<Promise> for SendJsFuture {
    fn from(promise: Promise) -> Self {
        Self(JsFuture::from(promise))
    }
}

impl Future for SendJsFuture {
    type Output = Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        FutureExt::poll_unpin(&mut self.0, cx)
    }
}

/// Send wrapper around `web_sys::Response` for wasm single-threaded use.
#[derive(Clone)]
struct SendResponse(Response);

unsafe impl Send for SendResponse {}

impl SendResponse {
    fn status(&self) -> u16 {
        self.0.status()
    }

    fn ok(&self) -> bool {
        self.0.ok()
    }

    fn headers(&self) -> Headers {
        self.0.headers()
    }

    fn array_buffer(&self) -> Result<Promise, wasm_bindgen::JsValue> {
        self.0.array_buffer()
    }
}

#[derive(Clone)]
pub struct Client;

impl Client {
    pub fn new() -> Result<Self, crate::BlockSourceError> {
        Ok(Self)
    }

    pub async fn probe_size(&self, url: &Url) -> Result<u64, HttpError> {
        // Prefer a ranged GET to coax Content-Range, fall back to HEAD/Content-Length.
        let resp = self
            .send_request(url, Some("bytes=0-0"), "GET")
            .await
            .map_err(|err| HttpError::Msg(format!("probe request: {err}")))?;
        tracing::debug!(%url, status = resp.status(), "http probe response");
        let headers = resp.headers();
        if let Ok(Some(val)) = headers.get(CONTENT_RANGE.as_str()) {
            if let Some(len) = parse_content_range_total(&val) {
                return Ok(len);
            }
        }
        if resp.ok() {
            if let Ok(Some(val)) = headers.get(CONTENT_LENGTH.as_str()) {
                if let Ok(len) = val.parse::<u64>() {
                    return Ok(len);
                }
            }
        }
        // Final fallback: HEAD (best effort)
        let resp = self
            .send_request(url, None, "HEAD")
            .await
            .map_err(|err| HttpError::Msg(format!("probe HEAD: {err}")))?;
        if resp.ok() {
            if let Ok(Some(val)) = resp.headers().get(CONTENT_LENGTH.as_str()) {
                if let Ok(len) = val.parse::<u64>() {
                    return Ok(len);
                }
            }
        }
        Err(HttpError::Msg("unable to determine content length".into()))
    }

    pub async fn read_range(
        &self,
        url: &Url,
        range: RangeInclusive<u64>,
        buf: &mut [u8],
    ) -> Result<usize, HttpError> {
        let header = format!("bytes={}-{}", range.start(), range.end());
        let resp = self
            .send_request(url, Some(&header), "GET")
            .await
            .map_err(|err| HttpError::Msg(format!("GET: {err}")))?;
        tracing::trace!(
            status = resp.status(),
            start = *range.start(),
            end = *range.end(),
            "http read response"
        );
        if !(resp.ok() || resp.status() == 206) {
            return Err(HttpError::Msg(format!("GET status {}", resp.status())));
        }
        let promise = resp
            .array_buffer()
            .map_err(|err| HttpError::Msg(format!("array_buffer: {err:?}")))?;
        let buffer = SendJsFuture::from(promise)
            .await
            .map_err(|err| HttpError::Msg(format!("array_buffer await: {err:?}")))?;
        let array = Uint8Array::new(&buffer);
        let read = array.length() as usize;
        let copy_len = buf.len().min(read);
        array.slice(0, copy_len as u32).copy_to(buf);
        tracing::trace!(read = copy_len, expected = buf.len(), "http read done");
        Ok(copy_len)
    }

    async fn send_request(
        &self,
        url: &Url,
        range: Option<&str>,
        method: &str,
    ) -> Result<SendResponse, HttpError> {
        let promise = build_request_promise(url, range, method)?;
        let resp = SendJsFuture::from(promise)
            .await
            .map_err(|err| HttpError::Msg(format!("fetch await: {err:?}")))?;
        let resp: Response = resp
            .dyn_into()
            .map_err(|err| HttpError::Msg(format!("fetch dyn_into Response: {err:?}")))?;
        Ok(SendResponse(resp))
    }
}

fn build_request_promise(
    url: &Url,
    range: Option<&str>,
    method: &str,
) -> Result<Promise, HttpError> {
    let window = web_sys::window().ok_or_else(|| HttpError::Msg("window unavailable".into()))?;
    let init = RequestInit::new();
    init.set_method(method);
    init.set_mode(RequestMode::Cors);
    let headers = Headers::new().map_err(|err| HttpError::Msg(format!("{err:?}")))?;
    if let Some(range) = range {
        headers
            .append(RANGE.as_str(), range)
            .map_err(|err| HttpError::Msg(format!("set range: {err:?}")))?;
    }
    init.set_headers(&headers);
    let request = Request::new_with_str_and_init(url.as_str(), &init)
        .map_err(|err| HttpError::Msg(format!("build request: {err:?}")))?;
    Ok(window.fetch_with_request(&request))
}

fn parse_content_range_total(hdr: &str) -> Option<u64> {
    // e.g. "bytes 0-0/12345"
    let parts: Vec<&str> = hdr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    parts[1].parse::<u64>().ok()
}
