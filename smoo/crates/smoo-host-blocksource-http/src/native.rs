use crate::HttpError;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use reqwest::Client as ReqwestClient;
use std::ops::RangeInclusive;
use url::Url;

#[derive(Clone)]
pub struct Client {
    inner: ReqwestClient,
}

impl Client {
    pub fn new() -> Result<Self, crate::BlockSourceError> {
        let client = ReqwestClient::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(6))
            .build()
            .map_err(|err| {
                crate::BlockSourceError::with_message(
                    crate::BlockSourceErrorKind::Io,
                    format!("build HTTP client: {err}"),
                )
            })?;
        Ok(Self { inner: client })
    }

    pub async fn probe_size(&self, url: &Url) -> Result<u64, HttpError> {
        tracing::debug!(%url, "http probe range");
        let resp = self
            .inner
            .get(url.as_str())
            .header(RANGE, "bytes=0-0")
            .send()
            .await
            .map_err(|err| HttpError::Msg(format!("probe GET: {err}")))?;
        tracing::debug!(status = %resp.status(), "http probe response");
        if let Some(len) = resp
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|h| h.to_str().ok())
            .and_then(parse_content_range_total)
        {
            return Ok(len);
        }
        if resp.status().is_success() {
            if let Some(len) = resp
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                return Ok(len);
            }
        }
        // Final fallback: HEAD
        let head = self.inner.head(url.as_str()).send().await;
        if let Ok(resp) = head {
            if resp.status().is_success() {
                if let Some(len) = resp
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                {
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
            .inner
            .get(url.as_str())
            .header(RANGE, header)
            .send()
            .await
            .map_err(|err| HttpError::Msg(format!("GET: {err}")))?;
        tracing::trace!(status = %resp.status(), start = *range.start(), end = *range.end(), "http read response");
        if !(resp.status().is_success() || resp.status().as_u16() == 206) {
            return Err(HttpError::Msg(format!("GET status {}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|err| HttpError::Msg(format!("read body: {err}")))?;
        let read = bytes.len().min(buf.len());
        buf[..read].copy_from_slice(&bytes[..read]);
        tracing::trace!(read, expected = buf.len(), "http read done");
        Ok(read)
    }
}

fn parse_content_range_total(hdr: &str) -> Option<u64> {
    // e.g. "bytes 0-0/12345"
    let parts: Vec<&str> = hdr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    parts[1].parse::<u64>().ok()
}
