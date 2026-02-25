use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use dioxus::prelude::ReadableExt;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::Personalization;
use fastboop_core::{
    bootimg::build_android_bootimg, resolve_effective_boot_profile_stage0, BootProfile,
    BootProfileArtifactSource,
};
use fastboop_stage0_generator::{build_stage0, Stage0Options, Stage0SwitchrootFs};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_core::{
    block_identity_string, BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext,
};
use gibblox_http::HttpBlockReader;
use gibblox_zip::ZipEntryBlockReader;
use gobblytes_erofs::ErofsRootfs;
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::{
    register_export, BlockSource, BlockSourceHandle, CountingTransport, TransportCounterSnapshot,
};
use smoo_host_session::{
    drive_host_session, HostSession, HostSessionConfig, HostSessionDriveConfig,
    HostSessionDriveEvent, HostSessionDriveOutcome,
};
use smoo_host_transport_rusb::RusbTransport;
use tokio::sync::oneshot;
use tracing::{error, info, warn};
use ui::{
    apply_transport_counters, oneplus_fajita_dtbo_overlays, SmooStatsHandle, SmooTransportCounters,
};
use url::Url;

use super::session::{
    update_session_phase, BootConfig, BootRuntime, DeviceSession, SessionChannelIntake,
    SessionPhase, SessionStore,
};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const FASTBOOT_INTERFACE_SUBCLASS: u8 = 0x42;
const FASTBOOT_INTERFACE_PROTOCOL: u8 = 0x03;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_RETRY_ATTEMPTS: usize = 5;

pub async fn boot_selected_device(
    sessions: &mut SessionStore,
    session_id: &str,
) -> Result<BootRuntime> {
    let session = sessions
        .read()
        .iter()
        .find(|s| s.id == session_id)
        .cloned()
        .ok_or_else(|| anyhow!("session not found"))?;
    let mut boot_config = session.boot_config.clone();

    validate_session_dev_profiles(
        &session.device.profile.id,
        &session.channel_intake.accepted_dev_profiles,
    )
    .with_context(|| {
        format!(
            "device '{}' is not accepted by channel stream dev profiles",
            session.device.profile.id
        )
    })?;

    let selected_boot_profile = select_boot_profile_for_session(&session)?;
    let profile_stage0 = selected_boot_profile
        .as_ref()
        .map(|boot_profile| {
            resolve_effective_boot_profile_stage0(boot_profile, session.device.profile.id.as_str())
        })
        .unwrap_or_default();

    let channel = boot_config.channel.trim();
    if channel.is_empty() {
        return Err(anyhow!("channel is empty"));
    }

    if session.channel_intake.warning_count > 0 {
        info!(
            warning_count = session.channel_intake.warning_count,
            consumed_bytes = session.channel_intake.consumed_bytes,
            channel,
            "channel stream contained trailing bytes that were not valid profile records"
        );
    }

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: format!(
                "Opening channel {} for {} ({:04x}:{:04x})",
                channel, session.device.name, session.device.vid, session.device.pid
            ),
        },
    );
    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Building stage0".to_string(),
        },
    );
    let dtbo_overlays = if session.device.profile.id == "oneplus-fajita" {
        oneplus_fajita_dtbo_overlays()
    } else {
        Vec::new()
    };
    let mut dtbo_overlays = dtbo_overlays;
    dtbo_overlays.extend(profile_stage0.dt_overlays);

    let mut extra_modules = vec!["erofs".to_string()];
    extra_modules.extend(profile_stage0.extra_modules);

    boot_config.extra_kargs = join_cmdline(
        profile_stage0.extra_cmdline.as_deref(),
        nonempty(boot_config.extra_kargs.as_str()),
    );

    let stage0_opts = Stage0Options {
        switchroot_fs: Stage0SwitchrootFs::Erofs,
        extra_modules,
        kernel_override: None,
        dtb_override: None,
        dtbo_overlays,
        enable_serial: boot_config.enable_serial,
        mimic_fastboot: true,
        smoo_vendor: Some(session.device.vid),
        smoo_product: Some(session.device.pid),
        smoo_serial: session.device.serial.clone(),
        personalization: Some(personalization_from_host()),
    };
    let (build, runtime) = build_stage0_artifacts(
        session.device.profile.clone(),
        stage0_opts,
        boot_config,
        session.channel_intake.clone(),
        selected_boot_profile,
    )
    .await
    .context("open channel and build stage0")?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Assembling android boot image".to_string(),
        },
    );
    let cmdline = join_cmdline(
        session
            .device
            .profile
            .boot
            .fastboot_boot
            .android_bootimg
            .cmdline_append
            .as_deref(),
        Some(build.kernel_cmdline_append.as_str()),
    );
    let mut kernel_image = build.kernel_image;
    let mut profile = session.device.profile.clone();
    if profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .append_dtb()
    {
        kernel_image.extend_from_slice(&build.dtb);
        let header_version = profile.boot.fastboot_boot.android_bootimg.header_version;
        if header_version >= 2 {
            profile.boot.fastboot_boot.android_bootimg.header_version = 0;
        }
    }
    let bootimg = build_android_bootimg(
        &profile,
        &kernel_image,
        &build.initrd,
        Some(&build.dtb),
        &cmdline,
    )
    .map_err(|err| anyhow!("bootimg build failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Opening fastboot transport".to_string(),
        },
    );
    let mut fastboot = session
        .device
        .handle
        .open_fastboot()
        .await
        .map_err(|err| anyhow!("open fastboot failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Downloading boot image".to_string(),
        },
    );
    download(&mut fastboot, &bootimg)
        .await
        .map_err(|err| anyhow!("fastboot download failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Issuing fastboot boot".to_string(),
        },
    );
    boot(&mut fastboot)
        .await
        .map_err(|err| anyhow!("fastboot boot failed: {err}"))?;

    Ok(BootRuntime {
        reader: runtime.reader,
        size_bytes: runtime.size_bytes,
        identity: runtime.identity,
        smoo_stats: runtime.smoo_stats,
    })
}

async fn build_stage0_artifacts(
    profile: fastboop_core::DeviceProfile,
    stage0_opts: Stage0Options,
    boot_config: BootConfig,
    channel_intake: SessionChannelIntake,
    selected_boot_profile: Option<BootProfile>,
) -> Result<(fastboop_stage0_generator::Stage0Build, BootRuntime)> {
    let channel = boot_config.channel.trim().to_string();
    if channel.is_empty() {
        return Err(anyhow!("channel is empty"));
    }
    let extra_kargs = boot_config.extra_kargs.trim().to_string();

    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("fastboop-stage0-build".to_string())
        .spawn(move || {
            let result: Result<_> = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("create tokio runtime for stage0 build")?;
                runtime.block_on(async move {
                    info!(profile = %profile.id, channel = %channel, "opening channel for desktop boot");
                    let (provider_reader, provider_size_bytes) = if channel_intake.has_artifact_payload
                    {
                        let url = Url::parse(&channel)
                            .map_err(|err| anyhow!("parse channel URL {channel}: {err}"))?;
                        let (reader, exact_size_bytes) = open_cached_http_reader(&url).await?;

                        if exact_size_bytes != channel_intake.exact_total_bytes {
                            warn!(
                                expected = channel_intake.exact_total_bytes,
                                observed = exact_size_bytes,
                                channel,
                                "channel size changed since startup intake"
                            );
                        }

                        if let Some(entry_name) = zip_entry_name_from_url(&url)? {
                            let source_reader: Arc<dyn BlockReader> =
                                if channel_intake.consumed_bytes == 0 {
                                    reader.clone()
                                } else {
                                    Arc::new(OffsetChannelBlockReader::new(
                                        reader.clone(),
                                        channel_intake.consumed_bytes,
                                        exact_size_bytes,
                                    )?)
                                };
                            let zip_reader = ZipEntryBlockReader::new(&entry_name, source_reader)
                                .await
                                .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                            let zip_reader = Arc::new(zip_reader);
                            let zip_size_bytes = reader_size_bytes(zip_reader.as_ref()).await?;
                            (zip_reader as Arc<dyn BlockReader>, zip_size_bytes)
                        } else {
                            offset_tail_reader(
                                reader.clone(),
                                channel_intake.consumed_bytes,
                                exact_size_bytes,
                            )
                            .map_err(|err| anyhow!("channel stream requires trailing artifact: {err}"))?
                        }
                    } else {
                        let boot_profile = selected_boot_profile.as_ref().ok_or_else(|| {
                            anyhow!(
                                "channel has no trailing artifact payload and no compatible boot profile selected"
                            )
                        })?;
                        let rootfs_channel = boot_profile_http_source_url(boot_profile)?;
                        let rootfs_url = Url::parse(&rootfs_channel).map_err(|err| {
                            anyhow!("parse boot profile rootfs URL {rootfs_channel}: {err}")
                        })?;
                        let (reader, _exact_size_bytes) = open_cached_http_reader(&rootfs_url).await?;
                        if let Some(entry_name) = zip_entry_name_from_url(&rootfs_url)? {
                            let zip_reader = ZipEntryBlockReader::new(&entry_name, reader.clone())
                                .await
                                .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                            let zip_reader = Arc::new(zip_reader);
                            let zip_size_bytes = reader_size_bytes(zip_reader.as_ref()).await?;
                            (zip_reader as Arc<dyn BlockReader>, zip_size_bytes)
                        } else {
                            let size_bytes = reader_size_bytes(reader.as_ref()).await?;
                            (reader as Arc<dyn BlockReader>, size_bytes)
                        }
                    };

                    let provider = ErofsRootfs::new(provider_reader.clone(), provider_size_bytes).await?;
                    info!(profile = %profile.id, "building stage0 payload");
                    let build =
                        build_stage0(&profile, &provider, &stage0_opts, nonempty(&extra_kargs), None)
                            .await
                            .map_err(|err| anyhow!("stage0 build failed: {err:?}"))?;
                    let provider_identity = block_identity_string(provider_reader.as_ref());
                    Ok((
                        build,
                        BootRuntime {
                            reader: provider_reader,
                            size_bytes: provider_size_bytes,
                            identity: provider_identity,
                            smoo_stats: SmooStatsHandle::new(),
                        },
                    ))
                })
            })();
            let _ = tx.send(result);
        })
        .context("spawn stage0 build worker thread")?;

    rx.await
        .map_err(|_| anyhow!("stage0 build worker thread exited unexpectedly"))?
}

fn validate_session_dev_profiles(
    session_device_profile_id: &str,
    accepted: &[fastboop_core::DeviceProfile],
) -> Result<()> {
    if accepted.is_empty() {
        return Ok(());
    }

    if accepted
        .iter()
        .any(|profile| profile.id == session_device_profile_id)
    {
        return Ok(());
    }

    let allowed: Vec<_> = accepted.iter().map(|profile| profile.id.as_str()).collect();
    Err(anyhow!(
        "device '{}' is not accepted by this channel stream; channel-dev-profiles: {}",
        session_device_profile_id,
        allowed.join(", "),
    ))
}

fn select_boot_profile_for_session(session: &DeviceSession) -> Result<Option<BootProfile>> {
    let compatible = &session.channel_intake.compatible_boot_profiles;
    if compatible.is_empty() {
        return Ok(None);
    }

    if let Some(selected_id) = session.boot_config.selected_boot_profile_id.as_deref() {
        let selected = compatible
            .iter()
            .find(|profile| profile.id == selected_id)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "selected boot profile '{}' is not compatible with device profile '{}'",
                    selected_id,
                    session.device.profile.id
                )
            })?;
        return Ok(Some(selected));
    }

    if compatible.len() == 1 {
        return Ok(Some(compatible[0].clone()));
    }

    let available: Vec<_> = compatible
        .iter()
        .map(|profile| profile.id.as_str())
        .collect();
    bail!(
        "multiple compatible boot profiles available for '{}'; choose one: {}",
        session.device.profile.id,
        available.join(", ")
    )
}

fn boot_profile_http_source_url(boot_profile: &BootProfile) -> Result<String> {
    match boot_profile.rootfs.source() {
        BootProfileArtifactSource::Http(source) => {
            let source = source.http.trim();
            if source.is_empty() {
                bail!("boot profile '{}' rootfs.http is empty", boot_profile.id);
            }
            Url::parse(source)
                .map(|url| url.to_string())
                .map_err(|err| {
                    anyhow!(
                        "parse boot profile '{}' rootfs HTTP source {}: {err}",
                        boot_profile.id,
                        source
                    )
                })
        }
        _ => bail!(
            "boot profile '{}' rootfs source is not supported in fastboop-desktop yet; expected HTTP source",
            boot_profile.id
        ),
    }
}

async fn open_cached_http_reader(url: &Url) -> Result<(Arc<dyn BlockReader>, u64)> {
    let http_reader = HttpBlockReader::new(url.clone(), gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
        .await
        .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
    let exact_size_bytes = http_reader.size_bytes();
    let cache = StdCacheOps::open_default_for_reader(&http_reader)
        .await
        .map_err(|err| anyhow!("open std cache for HTTP source: {err}"))?;
    let cached = CachedBlockReader::new(http_reader, cache)
        .await
        .map_err(|err| anyhow!("initialize std cache for HTTP source: {err}"))?;
    Ok((Arc::new(cached), exact_size_bytes))
}

fn offset_tail_reader(
    reader: Arc<dyn BlockReader>,
    consumed_bytes: u64,
    total_size_bytes: u64,
) -> Result<(Arc<dyn BlockReader>, u64)> {
    if consumed_bytes == 0 {
        return Ok((reader, total_size_bytes));
    }

    if consumed_bytes >= total_size_bytes {
        bail!(
            "channel stream has only profile records and no trailing artifact payload; desktop boot requires an artifact stream"
        );
    }

    Ok((
        Arc::new(OffsetChannelBlockReader::new(
            reader.clone(),
            consumed_bytes,
            total_size_bytes,
        )?),
        total_size_bytes
            .checked_sub(consumed_bytes)
            .ok_or_else(|| anyhow!("channel consumed byte offset overflow"))?,
    ))
}

struct OffsetChannelBlockReader {
    inner: Arc<dyn BlockReader>,
    offset_bytes: u64,
    size_bytes: u64,
    block_size: u32,
    inner_size_bytes: u64,
}

impl OffsetChannelBlockReader {
    fn new(inner: Arc<dyn BlockReader>, offset_bytes: u64, inner_size_bytes: u64) -> Result<Self> {
        if offset_bytes > inner_size_bytes {
            bail!(
                "offset {offset_bytes} exceeds source size {inner_size_bytes} while truncating channel stream"
            );
        }

        let block_size = inner.block_size();
        if block_size == 0 {
            bail!("block size must be non-zero");
        }

        Ok(Self {
            inner,
            offset_bytes,
            size_bytes: inner_size_bytes
                .checked_sub(offset_bytes)
                .ok_or_else(|| anyhow!("channel consumed byte offset underflow"))?,
            block_size,
            inner_size_bytes,
        })
    }
}

#[async_trait::async_trait]
impl gibblox_core::BlockReader for OffsetChannelBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        let block_size = u64::from(self.block_size);
        if block_size == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero",
            ));
        }
        Ok(self.size_bytes.div_ceil(block_size))
    }

    fn write_identity(&self, out: &mut dyn core::fmt::Write) -> std::fmt::Result {
        let mut identity = String::new();
        self.inner.write_identity(&mut identity)?;
        write!(out, "{}|offset:{}", identity, self.offset_bytes)
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let local_offset = lba.checked_mul(u64::from(self.block_size)).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset overflow")
        })?;
        if local_offset >= self.size_bytes {
            return Ok(0);
        }

        let remaining = self.size_bytes.checked_sub(local_offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read offset underflow")
        })?;
        let max_read = core::cmp::min(buf.len() as u64, remaining) as usize;
        let global_offset = self.offset_bytes.checked_add(local_offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "global read offset overflow")
        })?;

        let byte_reader = gibblox_core::ByteRangeReader::new(
            self.inner.clone(),
            self.block_size as usize,
            self.inner_size_bytes,
        );
        byte_reader
            .read_exact_at(global_offset, &mut buf[..max_read], ctx)
            .await
            .map_err(|err| err)?;
        Ok(max_read)
    }
}

fn zip_entry_name_from_url(url: &Url) -> Result<Option<String>> {
    let file_name = url
        .path_segments()
        .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back());
    zip_entry_name_from_file_name(file_name)
}

fn zip_entry_name_from_file_name(file_name: Option<&str>) -> Result<Option<String>> {
    let Some(file_name) = file_name else {
        return Ok(None);
    };
    if !file_name.to_ascii_lowercase().ends_with(".zip") {
        return Ok(None);
    }

    let stem = &file_name[..file_name.len() - 4];
    if stem.is_empty() {
        return Err(anyhow!("zip artifact name must include a filename stem"));
    }
    Ok(Some(format!("{stem}.ero")))
}

async fn reader_size_bytes(reader: &dyn BlockReader) -> Result<u64> {
    let total_blocks = reader
        .total_blocks()
        .await
        .map_err(|err| anyhow!("read total blocks for channel: {err}"))?;
    total_blocks
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow!("channel size overflow"))
}

pub fn run_rusb_host_daemon(
    reader: Arc<dyn gibblox_core::BlockReader>,
    size_bytes: u64,
    identity: String,
    smoo_stats: SmooStatsHandle,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create tokio runtime for smoo host")?;
    runtime.block_on(async move {
        loop {
            let (transport, control) = match open_matching_rusb_transport().await {
                Ok(pair) => pair,
                Err(err) => {
                    info!(%err, "desktop smoo gadget not ready yet");
                    tokio::time::sleep(DISCOVERY_RETRY).await;
                    continue;
                }
            };

            match run_rusb_session(
                transport,
                control,
                reader.clone(),
                size_bytes,
                identity.clone(),
                smoo_stats.clone(),
            )
            .await
            {
                Ok(SessionEnd::TransportLost) => {
                    info!("desktop smoo gadget disconnected; waiting to reconnect");
                }
                Err(err) => {
                    error!(%err, "desktop smoo session failed");
                }
            }
            tokio::time::sleep(DISCOVERY_RETRY).await;
        }
    })
}

async fn open_matching_rusb_transport() -> std::result::Result<
    (RusbTransport, smoo_host_transport_rusb::RusbControl),
    smoo_host_core::TransportError,
> {
    match RusbTransport::open_matching(
        None,
        None,
        SMOO_INTERFACE_CLASS,
        SMOO_INTERFACE_SUBCLASS,
        SMOO_INTERFACE_PROTOCOL,
        TRANSFER_TIMEOUT,
    )
    .await
    {
        Ok(pair) => Ok(pair),
        Err(_) => {
            RusbTransport::open_matching(
                None,
                None,
                SMOO_INTERFACE_CLASS,
                FASTBOOT_INTERFACE_SUBCLASS,
                FASTBOOT_INTERFACE_PROTOCOL,
                TRANSFER_TIMEOUT,
            )
            .await
        }
    }
}

enum SessionEnd {
    TransportLost,
}

async fn run_rusb_session(
    transport: RusbTransport,
    mut control: smoo_host_transport_rusb::RusbControl,
    reader: Arc<dyn gibblox_core::BlockReader>,
    size_bytes: u64,
    identity: String,
    smoo_stats: SmooStatsHandle,
) -> Result<SessionEnd> {
    let transport = CountingTransport::new(transport);
    let counters = transport.counters();
    let source = GibbloxBlockSource::new(reader, identity.clone());
    let block_size = source.block_size();
    ensure!(block_size > 0, "block size must be non-zero");
    ensure!(
        size_bytes.is_multiple_of(block_size as u64),
        "image size must align to export block size"
    );

    let source_handle = BlockSourceHandle::new(source, identity.clone());
    let mut sources = BTreeMap::new();
    let mut entries = Vec::new();
    register_export(
        &mut sources,
        &mut entries,
        source_handle,
        identity,
        block_size,
        size_bytes,
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    let session = HostSession::new(
        sources,
        HostSessionConfig {
            status_retry_attempts: STATUS_RETRY_ATTEMPTS,
        },
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    let task = session
        .start(transport, &mut control)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    smoo_stats.set_connected(true);
    let mut counter_snapshot = transport_counters_from_snapshot(counters.snapshot());

    let outcome = drive_host_session(
        task,
        control,
        std::future::pending::<()>(),
        || tokio::time::sleep(HEARTBEAT_INTERVAL),
        HostSessionDriveConfig::default(),
        |event| {
            update_smoo_stats_from_transport(
                &smoo_stats,
                &mut counter_snapshot,
                transport_counters_from_snapshot(counters.snapshot()),
            );
            match event {
                HostSessionDriveEvent::HeartbeatStatus { .. } => {}
                HostSessionDriveEvent::HeartbeatRecovered { missed_heartbeats } => {
                    info!(missed_heartbeats, "desktop smoo heartbeat recovered");
                }
                HostSessionDriveEvent::HeartbeatMiss {
                    error,
                    missed_heartbeats,
                    budget,
                } => {
                    warn!(
                        %error,
                        missed_heartbeats,
                        budget,
                        "desktop smoo heartbeat failed"
                    );
                }
                HostSessionDriveEvent::HeartbeatMissBudgetExhausted {
                    missed_heartbeats,
                    budget,
                } => {
                    error!(
                        missed_heartbeats,
                        budget, "desktop smoo heartbeat budget exhausted"
                    );
                }
            }
        },
    )
    .await;

    update_smoo_stats_from_transport(
        &smoo_stats,
        &mut counter_snapshot,
        transport_counters_from_snapshot(counters.snapshot()),
    );
    smoo_stats.set_connected(false);

    match outcome {
        HostSessionDriveOutcome::Shutdown | HostSessionDriveOutcome::TransportLost => {
            Ok(SessionEnd::TransportLost)
        }
        HostSessionDriveOutcome::SessionChanged { previous, current } => {
            info!(
                previous = format_args!("0x{previous:016x}"),
                current = format_args!("0x{current:016x}"),
                "desktop smoo session changed; reconnecting"
            );
            Ok(SessionEnd::TransportLost)
        }
        HostSessionDriveOutcome::Failed(err) => Err(anyhow!(err.to_string())),
    }
}

fn update_smoo_stats_from_transport(
    smoo_stats: &SmooStatsHandle,
    previous: &mut SmooTransportCounters,
    current: SmooTransportCounters,
) {
    apply_transport_counters(smoo_stats, previous, current);
}

fn transport_counters_from_snapshot(snapshot: TransportCounterSnapshot) -> SmooTransportCounters {
    SmooTransportCounters {
        ios_up: snapshot.ios_up,
        ios_down: snapshot.ios_down,
        bytes_up: snapshot.bytes_up,
        bytes_down: snapshot.bytes_down,
    }
}

fn join_cmdline(left: Option<&str>, right: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(left) = left {
        out.push_str(left.trim());
    }
    if let Some(right) = right {
        let right = right.trim();
        if !right.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(right);
        }
    }
    out
}

fn nonempty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn personalization_from_host() -> Personalization {
    let locale = detect_locale().unwrap_or_else(|| "en_US.UTF-8".to_string());
    let locale_messages = detect_locale_messages().unwrap_or_else(|| locale.clone());
    let keymap = detect_keymap().unwrap_or_else(|| "us".to_string());
    let timezone = detect_timezone().unwrap_or_else(|| "UTC".to_string());
    Personalization {
        locale: Some(locale),
        locale_messages: Some(locale_messages),
        keymap: Some(keymap),
        timezone: Some(timezone),
    }
}

fn detect_locale() -> Option<String> {
    locale_from_env_or_file("LC_ALL").or_else(|| locale_from_env_or_file("LANG"))
}

fn detect_locale_messages() -> Option<String> {
    locale_from_env_or_file("LC_MESSAGES")
        .or_else(|| locale_from_env_or_file("LC_ALL"))
        .or_else(|| locale_from_env_or_file("LANG"))
}

fn locale_from_env_or_file(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .and_then(nonempty_owned)
        .or_else(|| read_key_from_file(Path::new("/etc/locale.conf"), key))
}

fn detect_keymap() -> Option<String> {
    read_key_from_file(Path::new("/etc/vconsole.conf"), "KEYMAP")
        .or_else(|| read_key_from_file(Path::new("/etc/default/keyboard"), "XKBLAYOUT"))
        .map(|s| s.split(',').next().unwrap_or(&s).trim().to_string())
        .and_then(nonempty_owned)
}

fn detect_timezone() -> Option<String> {
    if let Some(tz) = read_timezone_from_localtime() {
        return Some(tz);
    }
    if let Ok(tz) = fs::read_to_string("/etc/timezone") {
        if let Some(tz) = nonempty_owned(tz) {
            return Some(tz);
        }
    }
    env::var("TZ").ok().and_then(nonempty_owned)
}

fn read_timezone_from_localtime() -> Option<String> {
    let target = fs::read_link("/etc/localtime").ok()?;
    let target = if target.is_absolute() {
        target
    } else {
        Path::new("/etc").join(target)
    };
    let target = target.to_string_lossy();
    let marker = "zoneinfo/";
    let idx = target.find(marker)? + marker.len();
    let tz = target[idx..].trim();
    if tz.is_empty() {
        None
    } else {
        Some(tz.to_string())
    }
}

fn read_key_from_file(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        if k.trim() != key {
            continue;
        }
        let v = v.trim().trim_matches('"').trim_matches('\'');
        if let Some(v) = nonempty_owned(v.to_string()) {
            return Some(v);
        }
    }
    None
}

fn nonempty_owned(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
