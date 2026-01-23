#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::fmt;
use core::future::Future;

use crate::{DeviceProfile, ProbeStep};
use tracing::debug;

/// Minimal fastboot wire operations required by v0 DevPro probing and boot.
///
/// Implementations should be cancellation-safe and async-first; adapters may
/// block internally if the underlying transport is synchronous.
pub trait FastbootWire {
    type Error;

    type SendCommandFuture<'a>: Future<Output = Result<Response, Self::Error>> + 'a
    where
        Self: 'a;

    fn send_command<'a>(&'a mut self, cmd: &'a str) -> Self::SendCommandFuture<'a>;

    type SendDataFuture<'a>: Future<Output = Result<(), Self::Error>> + 'a
    where
        Self: 'a;

    fn send_data<'a>(&'a mut self, data: &'a [u8]) -> Self::SendDataFuture<'a>;

    type ReadResponseFuture<'a>: Future<Output = Result<Response, Self::Error>> + 'a
    where
        Self: 'a;

    fn read_response<'a>(&'a mut self) -> Self::ReadResponseFuture<'a>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError<E> {
    Transport(E),
    MissingVar(String),
    Mismatch {
        name: String,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: String,
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastbootProtocolError<E> {
    Transport(E),
    Fail(String),
    UnexpectedStatus(String),
    DownloadTooLarge(usize),
}

impl<E: fmt::Display> fmt::Display for FastbootProtocolError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(err) => write!(f, "transport error: {err}"),
            Self::Fail(msg) => write!(f, "fastboot failure: {msg}"),
            Self::UnexpectedStatus(status) => write!(f, "unexpected status: {status}"),
            Self::DownloadTooLarge(size) => write!(f, "download too large: {size} bytes"),
        }
    }
}

pub async fn getvar<F: FastbootWire>(
    fastboot: &mut F,
    name: &str,
) -> Result<String, FastbootProtocolError<F::Error>> {
    let response = fastboot
        .send_command(&format!("getvar:{name}"))
        .await
        .map_err(FastbootProtocolError::Transport)?;
    expect_okay(response)
}

pub async fn boot<F: FastbootWire>(
    fastboot: &mut F,
) -> Result<(), FastbootProtocolError<F::Error>> {
    let response = fastboot
        .send_command("boot")
        .await
        .map_err(FastbootProtocolError::Transport)?;
    let _ = expect_okay(response)?;
    Ok(())
}

pub async fn download<F: FastbootWire>(
    fastboot: &mut F,
    data: &[u8],
) -> Result<(), FastbootProtocolError<F::Error>> {
    if data.len() > u32::MAX as usize {
        return Err(FastbootProtocolError::DownloadTooLarge(data.len()));
    }
    debug!(bytes = data.len(), "fastboot download send");
    let response = fastboot
        .send_command(&format!("download:{:08x}", data.len()))
        .await
        .map_err(FastbootProtocolError::Transport)?;
    if response.status != "DATA" {
        return Err(FastbootProtocolError::UnexpectedStatus(response.status));
    }
    fastboot
        .send_data(data)
        .await
        .map_err(FastbootProtocolError::Transport)?;
    let response = fastboot
        .read_response()
        .await
        .map_err(FastbootProtocolError::Transport)?;
    let _ = expect_okay(response)?;
    Ok(())
}

fn expect_okay<E>(response: Response) -> Result<String, FastbootProtocolError<E>> {
    match response.status.as_str() {
        "OKAY" => Ok(response.payload),
        "FAIL" => Err(FastbootProtocolError::Fail(response.payload)),
        other => Err(FastbootProtocolError::UnexpectedStatus(other.to_string())),
    }
}

pub fn profile_matches_vid_pid(profile: &DeviceProfile, vid: u16, pid: u16) -> bool {
    profile
        .r#match
        .iter()
        .any(|rule| rule.fastboot.vid == vid && rule.fastboot.pid == pid)
}

pub async fn probe_profile<F: FastbootWire>(
    fastboot: &mut F,
    profile: &DeviceProfile,
) -> Result<(), ProbeError<FastbootProtocolError<F::Error>>> {
    let mut cache: BTreeMap<String, String> = BTreeMap::new();
    probe_profile_with_cache(fastboot, profile, &mut cache).await
}

pub async fn probe_profile_with_cache<F: FastbootWire>(
    fastboot: &mut F,
    profile: &DeviceProfile,
    cache: &mut BTreeMap<String, String>,
) -> Result<(), ProbeError<FastbootProtocolError<F::Error>>> {
    debug!(profile_id = %profile.id, "fastboot probe start");
    for step in &profile.probe {
        match step {
            ProbeStep::FastbootGetvarEq(check) => {
                let mut cached = true;
                let value = if let Some(value) = cache.get(&check.name) {
                    value.clone()
                } else {
                    cached = false;
                    let value = getvar(fastboot, &check.name)
                        .await
                        .map_err(ProbeError::Transport)?;
                    cache.insert(check.name.clone(), value.clone());
                    value
                };
                debug!(
                    profile_id = %profile.id,
                    name = %check.name,
                    cached = cached,
                    value = %value,
                    "fastboot getvar"
                );
                if value != check.equals {
                    return Err(ProbeError::Mismatch {
                        name: check.name.clone(),
                        expected: check.equals.clone(),
                        actual: value,
                    });
                }
            }
            ProbeStep::FastbootGetvarExists(check) => {
                let mut cached = true;
                let value = if let Some(value) = cache.get(&check.name) {
                    value.clone()
                } else {
                    cached = false;
                    let value = getvar(fastboot, &check.name)
                        .await
                        .map_err(ProbeError::Transport)?;
                    cache.insert(check.name.clone(), value.clone());
                    value
                };
                debug!(
                    profile_id = %profile.id,
                    name = %check.name,
                    cached = cached,
                    value = %value,
                    "fastboot getvar"
                );
                if is_missing_getvar(&value) {
                    return Err(ProbeError::MissingVar(check.name.clone()));
                }
            }
        }
    }
    debug!(profile_id = %profile.id, "fastboot probe success");
    Ok(())
}

fn is_missing_getvar(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown")
}
