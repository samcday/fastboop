use crate::HttpError;
use gibblox_core::{GibbloxError, GibbloxErrorKind};
use gibblox_core::{ReadContext, ReadPriority};
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use reqwest::Client as ReqwestClient;
use reqwest::StatusCode;
use std::ops::RangeInclusive;
use url::Url;

const READ_RANGE_MAX_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub struct Client {
    inner: ReqwestClient,
}

impl Client {
    pub fn new() -> Result<Self, GibbloxError> {
        let client = ReqwestClient::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(6))
            .build()
            .map_err(|err| {
                GibbloxError::with_message(
                    GibbloxErrorKind::Io,
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
        ctx: ReadContext,
    ) -> Result<usize, HttpError> {
        let start = *range.start();
        let end = *range.end();
        let expected_len = range_len(start, end)?;
        let header = format!("bytes={}-{}", range.start(), range.end());
        let priority = priority_header_value(ctx);
        let mut last_err = HttpError::Msg("range read did not run".into());

        for attempt in 1..=READ_RANGE_MAX_ATTEMPTS {
            let response = self
                .inner
                .get(url.as_str())
                .header(RANGE, &header)
                .header("Priority", priority)
                .send()
                .await;

            let resp = match response {
                Ok(resp) => resp,
                Err(err) => {
                    last_err = HttpError::Msg(format!("GET: {err}"));
                    tracing::warn!(
                        attempt,
                        max_attempts = READ_RANGE_MAX_ATTEMPTS,
                        start,
                        end,
                        error = %last_err,
                        "http read attempt failed before response"
                    );
                    continue;
                }
            };

            let status = resp.status();
            let content_range = resp
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let content_length = resp
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            tracing::trace!(
                attempt,
                status = %status,
                start,
                end,
                content_range = ?content_range,
                content_length = ?content_length,
                "http read response"
            );

            if let Err(message) = validate_range_response(
                status,
                content_range.as_deref(),
                content_length.as_deref(),
                start,
                end,
                expected_len,
            ) {
                last_err = HttpError::Msg(message);
                tracing::warn!(
                    attempt,
                    max_attempts = READ_RANGE_MAX_ATTEMPTS,
                    start,
                    end,
                    error = %last_err,
                    "http read attempt received invalid range response"
                );
                continue;
            }

            let bytes = match resp.bytes().await {
                Ok(bytes) => bytes,
                Err(err) => {
                    last_err = HttpError::Msg(format!("read body: {err}"));
                    tracing::warn!(
                        attempt,
                        max_attempts = READ_RANGE_MAX_ATTEMPTS,
                        start,
                        end,
                        error = %last_err,
                        "http read attempt failed while reading body"
                    );
                    continue;
                }
            };

            if bytes.len() != expected_len {
                last_err = HttpError::Msg(format!(
                    "range body length mismatch: got {}, expected {}",
                    bytes.len(),
                    expected_len
                ));
                tracing::warn!(
                    attempt,
                    max_attempts = READ_RANGE_MAX_ATTEMPTS,
                    start,
                    end,
                    error = %last_err,
                    "http read attempt returned unexpected body length"
                );
                continue;
            }

            buf[..expected_len].copy_from_slice(&bytes);
            tracing::trace!(
                attempt,
                read = expected_len,
                expected = buf.len(),
                "http read done"
            );
            return Ok(expected_len);
        }

        Err(last_err)
    }
}

fn priority_header_value(ctx: ReadContext) -> &'static str {
    match ctx.priority {
        ReadPriority::High => "u=0, i",
        ReadPriority::Medium => "u=3",
        ReadPriority::Low => "u=7",
    }
}

fn range_len(start: u64, end: u64) -> Result<usize, HttpError> {
    end.checked_sub(start)
        .and_then(|delta| delta.checked_add(1))
        .and_then(|len| usize::try_from(len).ok())
        .ok_or_else(|| HttpError::Msg("range length overflow".into()))
}

fn validate_range_response(
    status: StatusCode,
    content_range: Option<&str>,
    content_length: Option<&str>,
    expected_start: u64,
    expected_end: u64,
    expected_len: usize,
) -> Result<(), String> {
    if status != StatusCode::PARTIAL_CONTENT {
        return Err(format!(
            "GET status {status} (expected 206 Partial Content)"
        ));
    }

    let content_range =
        content_range.ok_or_else(|| "missing Content-Range on partial response".to_string())?;
    let (start, end, _) = parse_content_range(content_range)
        .ok_or_else(|| format!("invalid Content-Range header '{content_range}'"))?;
    if start != expected_start || end != expected_end {
        return Err(format!(
            "content-range mismatch: got bytes {start}-{end}, expected bytes {expected_start}-{expected_end}"
        ));
    }

    if let Some(content_length) = content_length {
        let parsed_len = content_length
            .parse::<usize>()
            .map_err(|_| format!("invalid Content-Length header '{content_length}'"))?;
        if parsed_len != expected_len {
            return Err(format!(
                "content-length mismatch: got {parsed_len}, expected {expected_len}"
            ));
        }
    }

    Ok(())
}

fn parse_content_range_total(hdr: &str) -> Option<u64> {
    parse_content_range(hdr).and_then(|(_, _, total)| total)
}

fn parse_content_range(hdr: &str) -> Option<(u64, u64, Option<u64>)> {
    // e.g. "bytes 0-0/12345"
    let hdr = hdr.trim().strip_prefix("bytes ")?;
    let (span, total) = hdr.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    let total = if total == "*" {
        None
    } else {
        Some(total.parse::<u64>().ok()?)
    };
    Some((start, end, total))
}
