#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use fastboop_core::DeviceProfile;
#[cfg(target_arch = "wasm32")]
use fastboop_core::Personalization;
use fastboop_core::device::DeviceHandle as _;
use fastboop_fastboot_webusb::{FastbootWebUsb, WebUsbDeviceHandle};
use fastboop_session::{
    BootRequest, BootSessionEnvironment, FastboopSession, PreparedBoot, PreparedBootInfo,
    RuntimeExport, SessionCodecError, SessionEnvironment, SessionEvent, SessionEventPhase,
    SessionSnapshot, SessionStatus,
};
#[cfg(target_arch = "wasm32")]
use gibblox_core::BlockReader;

#[cfg(target_arch = "wasm32")]
use anyhow::Context as _;
#[cfg(target_arch = "wasm32")]
use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileRootfs, BootProfileRootfsFilesystemSource,
    resolve_effective_boot_profile_stage0, select_boot_profile_for_device,
};
#[cfg(target_arch = "wasm32")]
use fastboop_session::{
    OstreeArg, Stage0Assembly, auto_detect_ostree_deployment_path, build_android_boot_payload,
    join_cmdline, resolve_effective_ostree_arg,
};
#[cfg(target_arch = "wasm32")]
use fastboop_stage0_generator::{
    Stage0Error, Stage0KernelOverride, Stage0Options, Stage0SwitchrootFs,
};
#[cfg(target_arch = "wasm32")]
use gibblox_blockreader_messageport::{MessagePortBlockReaderClient, MessagePortBlockReaderServer};
#[cfg(target_arch = "wasm32")]
use gibblox_core::{WindowBlockReader, block_identity_string};
#[cfg(target_arch = "wasm32")]
use gibblox_ext4::{Ext4EntryType, Ext4Fs};
#[cfg(target_arch = "wasm32")]
use gibblox_pipeline::{
    PipelineCachePolicy, PipelineHints, PipelineSource, encode_pipeline, encode_pipeline_hints,
};
#[cfg(target_arch = "wasm32")]
use gibblox_web_worker::{GibbloxWebWorker, OpenPipelineRequestOptions};
#[cfg(target_arch = "wasm32")]
use gibblox_zip::ZipEntryBlockReader;
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::sleep;
#[cfg(target_arch = "wasm32")]
use gobblytes_core::{Filesystem, FilesystemEntryType, OstreeFs as OstreeRootfs};
#[cfg(target_arch = "wasm32")]
use gobblytes_erofs::{DEFAULT_IMAGE_BLOCK_SIZE, ErofsRootfs};
#[cfg(target_arch = "wasm32")]
use gobblytes_fat::FatFs;
#[cfg(target_arch = "wasm32")]
use js_sys::Reflect;
#[cfg(target_arch = "wasm32")]
use serde_json::json;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::MessageChannel;

#[cfg(target_arch = "wasm32")]
use crate::channel_source::{
    derive_casync_chunk_store_url, is_casync_archive_index_url, is_casync_blob_index_url,
    parse_optional_chunk_store_url, zip_entry_name_from_url,
};
#[cfg(target_arch = "wasm32")]
use crate::gibblox_worker::spawn_gibblox_worker;
#[cfg(target_arch = "wasm32")]
use crate::js::js_value_to_string;
#[cfg(target_arch = "wasm32")]
use crate::startup::{open_web_channel_source_reader, reader_size_bytes};

#[cfg(target_arch = "wasm32")]
const DEFAULT_SMOO_MAX_IO_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct WebBootStage0Config {
    pub channel: String,
    pub boot_profile: Option<String>,
    pub cmdline_append: Option<String>,
    pub serial: bool,
    pub stage0_asset_url: Option<String>,
    pub smoo_max_io: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct WebBootConfig {
    pub stage0: WebBootStage0Config,
}

impl WebBootConfig {
    pub fn boot_request(&self) -> Result<BootRequest> {
        let mut request = BootRequest::new(web_session_seed()?);
        request.source = Some(self.stage0.channel.clone());
        request.requested_boot_profile = self.stage0.boot_profile.clone();
        Ok(request)
    }
}

#[derive(Clone)]
pub struct WebSelectedFastbootDevice {
    pub handle: WebUsbDeviceHandle,
    pub profile: DeviceProfile,
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
}

impl WebSelectedFastbootDevice {
    pub fn new(handle: WebUsbDeviceHandle, profile: DeviceProfile) -> Self {
        let vid = handle.vid();
        let pid = handle.pid();
        let serial = webusb_serial_number(&handle);
        Self {
            handle,
            profile,
            vid,
            pid,
            serial,
        }
    }
}

#[derive(Clone)]
pub struct WebBootRuntime {
    pub size_bytes: u64,
    pub identity: String,
    pub channel: String,
    pub channel_offset_bytes: u64,
    #[cfg(target_arch = "wasm32")]
    pub local_reader_bridge: LocalReaderBridge,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct LocalReaderBridge {
    reader: Arc<dyn BlockReader>,
    servers: Rc<std::cell::RefCell<Vec<MessagePortBlockReaderServer>>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct LocalReaderBridge;

#[cfg(target_arch = "wasm32")]
impl LocalReaderBridge {
    pub fn new(reader: Arc<dyn BlockReader>) -> Self {
        Self {
            reader,
            servers: Rc::new(std::cell::RefCell::new(Vec::new())),
        }
    }

    pub async fn create_reader(&self) -> Result<MessagePortBlockReaderClient> {
        let channel = MessageChannel::new().map_err(|err| {
            anyhow!(
                "create local channel reader bridge message channel: {}",
                js_value_to_string(&err)
            )
        })?;
        let server = MessagePortBlockReaderServer::serve(channel.port2(), self.reader.clone())
            .map_err(|err| anyhow!("serve local channel reader bridge: {err}"))?;
        let client = MessagePortBlockReaderClient::connect(channel.port1())
            .await
            .map_err(|err| anyhow!("connect local channel reader bridge: {err}"))
            .with_context(|| "attach local channel reader bridge")?;
        self.servers.borrow_mut().push(server);
        Ok(client)
    }
}

#[derive(Clone, Debug)]
struct WebRuntimeInfo {
    channel: String,
    channel_offset_bytes: u64,
}

pub struct WebBootEnvironment {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    config: WebBootConfig,
    selected_device: Option<WebSelectedFastbootDevice>,
    runtime_info: Option<WebRuntimeInfo>,
    events: Vec<SessionEvent>,
}

impl WebBootEnvironment {
    pub fn new(config: WebBootConfig) -> Self {
        Self {
            config,
            selected_device: None,
            runtime_info: None,
            events: Vec::new(),
        }
    }

    pub fn with_selected_device(mut self, device: WebSelectedFastbootDevice) -> Self {
        self.selected_device = Some(device);
        self
    }

    pub fn drain_events(&mut self) -> Vec<SessionEvent> {
        core::mem::take(&mut self.events)
    }

    pub fn runtime_for_export(&self, export: &RuntimeExport) -> Result<WebBootRuntime> {
        let info = self
            .runtime_info
            .as_ref()
            .ok_or_else(|| anyhow!("web runtime metadata is unavailable before prepare"))?;
        Ok(WebBootRuntime {
            size_bytes: export.size_bytes,
            identity: export.identity.clone(),
            channel: info.channel.clone(),
            channel_offset_bytes: info.channel_offset_bytes,
            #[cfg(target_arch = "wasm32")]
            local_reader_bridge: LocalReaderBridge::new(export.reader.clone()),
        })
    }

    fn emit(&mut self, event: SessionEvent) {
        self.events.push(event);
    }
}

impl SessionEnvironment for WebBootEnvironment {
    type Error = anyhow::Error;

    fn session_codec_error(&mut self, err: SessionCodecError) -> Self::Error {
        anyhow!(err.to_string())
    }

    async fn persist_session(&mut self, snapshot: &SessionSnapshot, _encoded: &[u8]) -> Result<()> {
        emit_session_status(self, &snapshot.status);
        Ok(())
    }

    async fn prepare_boot(&mut self, session: &FastboopSession) -> Result<PreparedBoot> {
        prepare_boot_impl(self, session).await
    }
}

impl BootSessionEnvironment for WebBootEnvironment {
    type Fastboot = FastbootWebUsb;

    async fn connect_fastboot(
        &mut self,
        _session: &FastboopSession,
        _prepared: &PreparedBootInfo,
    ) -> Result<FastbootWebUsb> {
        let Some(device) = self.selected_device.as_ref() else {
            bail!("selected WebUSB fastboot device is unavailable")
        };
        device
            .handle
            .open_fastboot()
            .await
            .map_err(|err| anyhow!("open selected WebUSB fastboot device failed: {err}"))
    }

    async fn serve_runtime(
        &mut self,
        _session: &FastboopSession,
        export: RuntimeExport,
    ) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let Some(device) = self.selected_device.as_ref() else {
                bail!("selected WebUSB fastboot device is unavailable")
            };
            let runtime = self.runtime_for_export(&export)?;
            let (tx, _rx) = futures_channel::mpsc::unbounded();
            crate::smoo::run_web_smoo_host(
                device.handle.device(),
                runtime,
                crate::smoo::WebSmooHostOptions::default(),
                tx,
            )
            .await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = export;
            bail!("web smoo host is only available on wasm32 targets")
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn prepare_boot_impl(
    env: &mut WebBootEnvironment,
    session: &FastboopSession,
) -> Result<PreparedBoot> {
    env.emit(SessionEvent::Phase {
        phase: SessionEventPhase::Preparing,
        detail: "loading web channel".to_string(),
    });

    let channel = env.config.stage0.channel.trim().to_string();
    if channel.is_empty() {
        bail!("channel is empty");
    }

    let selected_device = env
        .selected_device
        .as_ref()
        .ok_or_else(|| anyhow!("selected WebUSB fastboot device is unavailable"))?
        .clone();
    let resume_status = session.status().await;
    if let Some(profile_id) = resume_status.profile_id()
        && profile_id != selected_device.profile.id
    {
        bail!(
            "selected WebUSB device profile '{}' does not match session profile '{}'",
            selected_device.profile.id,
            profile_id,
        );
    }

    let source = open_web_channel_source_reader(&channel)
        .await
        .with_context(|| format!("open channel {channel}"))?;
    let stream_head = fastboop_core::read_channel_stream_head_from_reader(
        source.reader.as_ref(),
        source.exact_total_bytes,
    )
    .await
    .map_err(|err| anyhow!("read channel stream head: {err}"))?;

    if stream_head.warning_count > 0 {
        env.emit(SessionEvent::Log(format!(
            "channel stream has {} warning(s) while reading profile head; using {} bytes of leading records",
            stream_head.warning_count, stream_head.consumed_bytes
        )));
    }

    let selected_boot_profile = select_web_boot_profile(
        &stream_head.boot_profiles,
        selected_device.profile.id.as_str(),
        env.config.stage0.boot_profile.as_deref(),
    )?;

    env.emit(SessionEvent::Phase {
        phase: SessionEventPhase::DeviceDetected,
        detail: format!(
            "{:04x}:{:04x} {} profile={}",
            selected_device.vid,
            selected_device.pid,
            selected_device
                .serial
                .as_deref()
                .map(|serial| format!("serial={serial}"))
                .unwrap_or_else(|| "serial=unknown".to_string()),
            selected_device.profile.id,
        ),
    });
    env.emit(SessionEvent::Phase {
        phase: SessionEventPhase::BuildingStage0,
        detail: "building stage0 payload".to_string(),
    });

    let prepared = build_stage0_artifacts(
        env,
        &channel,
        source.reader.as_ref(),
        source.exact_total_bytes,
        &stream_head,
        &selected_device,
        selected_boot_profile.as_ref(),
    )
    .await?;
    let build = prepared
        .build
        .map_err(|err| anyhow!("stage0 build failed: {err:?}"))?;
    let boot_image = build_android_boot_payload(&selected_device.profile, build)
        .map_err(|err| anyhow!("bootimg build failed: {err}"))?;

    Ok(PreparedBoot {
        profile_id: selected_device.profile.id,
        boot_image,
        export: RuntimeExport {
            reader: prepared.reader,
            size_bytes: prepared.size_bytes,
            identity: prepared.identity,
        },
    })
}

#[cfg(not(target_arch = "wasm32"))]
async fn prepare_boot_impl(
    _env: &mut WebBootEnvironment,
    _session: &FastboopSession,
) -> Result<PreparedBoot> {
    bail!("web boot preparation is only available on wasm32 targets")
}

#[cfg(target_arch = "wasm32")]
struct Stage0Artifacts {
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    build: core::result::Result<fastboop_stage0_generator::Stage0Build, Stage0Error>,
}

#[cfg(target_arch = "wasm32")]
async fn build_stage0_artifacts(
    env: &mut WebBootEnvironment,
    channel: &str,
    channel_reader: &dyn BlockReader,
    exact_total_bytes: u64,
    stream_head: &fastboop_core::ChannelStreamHead,
    selected_device: &WebSelectedFastbootDevice,
    selected_boot_profile: Option<&BootProfile>,
) -> Result<Stage0Artifacts> {
    let mut opts = stage0_options_for_web_boot(env, selected_device, selected_boot_profile);
    let gibblox_worker = spawn_gibblox_worker(channel.to_string(), 0, None)
        .await
        .map_err(|err| anyhow!("spawn gibblox worker failed: {err}"))?;
    let pipeline_hints = match selected_boot_profile {
        Some(boot_profile) => {
            read_channel_pipeline_hints_for_boot_profile(channel_reader, stream_head, boot_profile)
                .await?
        }
        None => PipelineHints::default(),
    };
    let profile_source_overrides = resolve_boot_profile_source_overrides_web(
        selected_boot_profile,
        &selected_device.profile,
        &pipeline_hints,
        &gibblox_worker,
    )
    .await?;
    opts.kernel_override = profile_source_overrides.kernel_override;
    opts.dtb_override = profile_source_overrides.dtb_override;

    let using_trailing_payload = stream_head.consumed_bytes < exact_total_bytes;
    let (reader, rootfs_kind, channel_offset_bytes) = if using_trailing_payload {
        let reader = open_channel_payload_reader_via_worker(
            &gibblox_worker,
            channel,
            stream_head.consumed_bytes,
            None,
        )
        .await?;
        (reader, Stage0RootfsKind::Erofs, stream_head.consumed_bytes)
    } else {
        let boot_profile = selected_boot_profile.ok_or_else(|| {
            anyhow!(
                "channel has no trailing artifact payload and no compatible boot profile selected"
            )
        })?;
        let reader =
            open_boot_profile_rootfs_reader(boot_profile, &pipeline_hints, &gibblox_worker).await?;
        (reader, rootfs_kind_for_web_boot(boot_profile)?, 0)
    };

    let size_bytes = reader_size_bytes(reader.as_ref()).await?;
    let identity = block_identity_string(reader.as_ref());
    env.runtime_info = Some(WebRuntimeInfo {
        channel: channel.to_string(),
        channel_offset_bytes,
    });

    tracing::info!(profile = %selected_device.profile.id, "building stage0 payload");
    sleep(std::time::Duration::from_millis(100)).await;

    let provider = Stage0RootfsProvider::open(rootfs_kind, reader.clone(), size_bytes).await?;
    opts.switchroot_fs = provider.switchroot_fs();
    let selected_ostree =
        match resolve_effective_ostree_arg(&OstreeArg::Disabled, selected_boot_profile) {
            OstreeArg::Disabled => None,
            OstreeArg::AutoDetect => {
                let detected = auto_detect_ostree_deployment_path(&provider)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                tracing::debug!(ostree = %detected, "auto-detected ostree deployment path");
                Some(detected)
            }
            OstreeArg::Explicit(path) => Some(path),
        };

    let extra_cmdline = build_extra_cmdline(
        env,
        selected_boot_profile,
        selected_device.profile.id.as_str(),
        selected_ostree.as_deref(),
    );
    let stage0_binary = load_stage0_binary_sidecar(env.config.stage0.stage0_asset_url.clone())
        .await
        .map_err(|err| anyhow!("stage0 binary sidecar: {err:?}"))?;
    let assembly = Stage0Assembly::new(opts, stage0_binary).with_extra_cmdline(extra_cmdline);
    let build = if let Some(ostree) = selected_ostree.as_deref() {
        let resolved_ostree = OstreeRootfs::resolve_deployment_path(&provider, ostree)
            .await
            .map_err(|err| anyhow!("resolve ostree deployment path {ostree}: {err}"))?;
        tracing::debug!(ostree = %ostree, resolved_ostree = %resolved_ostree, "resolved ostree deployment path");
        let provider = OstreeRootfs::new(provider, &resolved_ostree)
            .map_err(|err| anyhow!("initialize ostree filesystem view: {err}"))?;
        assembly.build(&selected_device.profile, &provider).await
    } else {
        assembly.build(&selected_device.profile, &provider).await
    };

    Ok(Stage0Artifacts {
        reader,
        size_bytes,
        identity,
        build,
    })
}

#[cfg(target_arch = "wasm32")]
fn stage0_options_for_web_boot(
    env: &WebBootEnvironment,
    selected_device: &WebSelectedFastbootDevice,
    selected_boot_profile: Option<&BootProfile>,
) -> Stage0Options {
    let profile_stage0 = selected_boot_profile
        .map(|boot_profile| {
            resolve_effective_boot_profile_stage0(boot_profile, selected_device.profile.id.as_str())
        })
        .unwrap_or_default();

    Stage0Options {
        switchroot_fs: Stage0SwitchrootFs::Erofs,
        kernel_modules: profile_stage0.kernel_modules,
        inject_mac: profile_stage0.inject_mac,
        kernel_override: None,
        dtb_override: None,
        dtbo_overlays: profile_stage0.dt_overlays,
        enable_serial: env.config.stage0.serial,
        mimic_fastboot: true,
        smoo_vendor: Some(selected_device.vid),
        smoo_product: Some(selected_device.pid),
        stage0_serial: selected_device.serial.clone(),
        personalization: Some(personalization_from_browser()),
    }
}

#[cfg(target_arch = "wasm32")]
fn build_extra_cmdline(
    env: &WebBootEnvironment,
    selected_boot_profile: Option<&BootProfile>,
    device_profile_id: &str,
    selected_ostree: Option<&str>,
) -> Option<String> {
    let profile_cmdline = selected_boot_profile
        .map(|boot_profile| {
            resolve_effective_boot_profile_stage0(boot_profile, device_profile_id).extra_cmdline
        })
        .unwrap_or_default();
    let merged_profile_cmdline = join_cmdline(
        profile_cmdline.as_deref(),
        env.config.stage0.cmdline_append.as_deref(),
    );

    let mut extra_parts = Vec::new();
    if let Some(ostree) = selected_ostree {
        extra_parts.push(format!("ostree=/{ostree}"));
    }
    if !merged_profile_cmdline.is_empty() {
        extra_parts.push(merged_profile_cmdline);
    }
    extra_parts.push(format!(
        "smoo.max_io_bytes={}",
        env.config
            .stage0
            .smoo_max_io
            .unwrap_or(DEFAULT_SMOO_MAX_IO_BYTES)
    ));

    if extra_parts.is_empty() {
        None
    } else {
        Some(extra_parts.join(" "))
    }
}

#[cfg(target_arch = "wasm32")]
fn select_web_boot_profile(
    boot_profiles: &[BootProfile],
    device_profile_id: &str,
    requested_boot_profile_id: Option<&str>,
) -> Result<Option<BootProfile>> {
    if boot_profiles.is_empty() {
        if let Some(requested) = requested_boot_profile_id {
            bail!(
                "boot profile '{requested}' was requested, but channel does not start with a boot profile stream"
            );
        }
        return Ok(None);
    }

    select_boot_profile_for_device(boot_profiles, device_profile_id, requested_boot_profile_id)
        .map(Some)
        .map_err(|err| anyhow!(err.to_string()))
}

#[cfg(target_arch = "wasm32")]
async fn read_channel_pipeline_hints_for_boot_profile(
    reader: &dyn BlockReader,
    stream_head: &fastboop_core::ChannelStreamHead,
    boot_profile: &BootProfile,
) -> Result<PipelineHints> {
    if stream_head.pipeline_hint_records.is_empty() {
        return Ok(PipelineHints::default());
    }

    fastboop_core::read_channel_pipeline_hints_for_boot_profile(reader, stream_head, boot_profile)
        .await
        .map_err(|err| anyhow!("read channel pipeline hints: {err}"))
}

#[cfg(target_arch = "wasm32")]
async fn open_channel_payload_reader_via_worker(
    worker: &GibbloxWebWorker,
    channel: &str,
    channel_offset_bytes: u64,
    channel_chunk_store_url: Option<&str>,
) -> Result<Arc<dyn BlockReader>> {
    let channel = channel.trim();
    if channel.is_empty() {
        bail!("channel URL is empty");
    }

    let url =
        url::Url::parse(channel).map_err(|err| anyhow!("parse channel URL {channel}: {err}"))?;
    if is_casync_archive_index_url(&url) {
        bail!(
            "casync archive indexes (.caidx) are not supported for channel block reads; provide a casync blob index (.caibx)"
        );
    }

    let chunk_store_url = parse_optional_chunk_store_url(channel_chunk_store_url)?;
    if !is_casync_blob_index_url(&url) && chunk_store_url.is_some() {
        bail!(
            "channel chunk store override is only supported with casync blob-index channels (.caibx)"
        );
    }

    let pipeline_source: PipelineSource = if is_casync_blob_index_url(&url) {
        serde_json::from_value(json!({
            "casync": {
                "index": url.to_string(),
                "chunk_store": chunk_store_url
                    .unwrap_or(derive_casync_chunk_store_url(&url)?)
                    .to_string(),
            }
        }))
        .map_err(|err| anyhow!("build casync pipeline source: {err}"))?
    } else {
        serde_json::from_value(json!({
            "http": url.to_string(),
        }))
        .map_err(|err| anyhow!("build HTTP pipeline source: {err}"))?
    };

    let pipeline_bytes = encode_pipeline(&pipeline_source)
        .map_err(|err| anyhow!("encode channel pipeline source: {err}"))?;
    let open_options = OpenPipelineRequestOptions {
        image_block_size: None,
        cache_policy: Some(PipelineCachePolicy::None),
        pipeline_hints_bin: None,
    };
    let opened = worker
        .open_pipeline_with_options(&pipeline_bytes, &open_options)
        .await
        .map_err(|err| anyhow!("open gibblox worker pipeline: {err}"))?;

    let reader: Arc<dyn BlockReader> = Arc::new(opened.reader);
    let reader = crate::channel_source::maybe_offset_reader(reader, channel_offset_bytes).await?;
    let reader: Arc<dyn BlockReader> = match zip_entry_name_from_url(&url)? {
        Some(entry_name) => {
            let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                .await
                .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
            Arc::new(zip_reader)
        }
        None => reader,
    };
    Ok(reader)
}

#[cfg(target_arch = "wasm32")]
async fn open_artifact_source_via_worker(
    worker: &GibbloxWebWorker,
    source: &PipelineSource,
    pipeline_hints: &PipelineHints,
) -> Result<Arc<dyn BlockReader>> {
    let pipeline_bytes =
        encode_pipeline(source).map_err(|err| anyhow!("encode artifact pipeline source: {err}"))?;
    let open_options = OpenPipelineRequestOptions {
        image_block_size: None,
        cache_policy: Some(PipelineCachePolicy::Head),
        pipeline_hints_bin: encode_pipeline_hints_for_worker(pipeline_hints)?,
    };
    let opened = worker
        .open_pipeline_with_options(&pipeline_bytes, &open_options)
        .await
        .map_err(|err| anyhow!("open gibblox worker artifact pipeline: {err}"))?;
    Ok(Arc::new(opened.reader))
}

#[cfg(target_arch = "wasm32")]
fn encode_pipeline_hints_for_worker(pipeline_hints: &PipelineHints) -> Result<Option<Vec<u8>>> {
    if pipeline_hints.entries.is_empty() {
        return Ok(None);
    }
    encode_pipeline_hints(pipeline_hints)
        .map(Some)
        .map_err(|err| anyhow!("encode pipeline hints for worker: {err}"))
}

#[cfg(target_arch = "wasm32")]
async fn open_boot_profile_rootfs_reader(
    boot_profile: &BootProfile,
    pipeline_hints: &PipelineHints,
    gibblox_worker: &GibbloxWebWorker,
) -> Result<Arc<dyn BlockReader>> {
    open_boot_profile_artifact_source(boot_profile.rootfs.source(), pipeline_hints, gibblox_worker)
        .await
}

#[cfg(target_arch = "wasm32")]
struct ProfileSourceOverrides {
    kernel_override: Option<Stage0KernelOverride>,
    dtb_override: Option<Vec<u8>>,
}

#[cfg(target_arch = "wasm32")]
async fn resolve_boot_profile_source_overrides_web(
    boot_profile: Option<&BootProfile>,
    device_profile: &DeviceProfile,
    pipeline_hints: &PipelineHints,
    gibblox_worker: &GibbloxWebWorker,
) -> Result<ProfileSourceOverrides> {
    let Some(boot_profile) = boot_profile else {
        return Ok(ProfileSourceOverrides {
            kernel_override: None,
            dtb_override: None,
        });
    };

    let kernel_override = if let Some(kernel_source) = boot_profile.kernel.as_ref() {
        let kernel_path = non_empty_profile_path(kernel_source.path.as_str(), "kernel.path")?;
        let source_reader = open_boot_profile_artifact_source(
            kernel_source.artifact_source(),
            pipeline_hints,
            gibblox_worker,
        )
        .await?;
        let source_rootfs = ProfileSourceRootfs::open(&kernel_source.source, source_reader).await?;
        let kernel_image = source_rootfs.read_all(kernel_path).await?;
        Some(Stage0KernelOverride {
            path: kernel_path.to_string(),
            image: kernel_image,
        })
    } else {
        None
    };

    let dtb_override = if let Some(dtbs_source) = boot_profile.dtbs.as_ref() {
        let dtbs_base = non_empty_profile_path(dtbs_source.path.as_str(), "dtbs.path")?;
        let source_reader = open_boot_profile_artifact_source(
            dtbs_source.artifact_source(),
            pipeline_hints,
            gibblox_worker,
        )
        .await?;
        let source_rootfs = ProfileSourceRootfs::open(&dtbs_source.source, source_reader).await?;
        let dtb_path = resolve_dtb_path_candidate_web(
            &source_rootfs,
            dtbs_base,
            device_profile.devicetree_name.as_str(),
        )
        .await?;
        Some(source_rootfs.read_all(dtb_path.as_str()).await?)
    } else {
        None
    };

    Ok(ProfileSourceOverrides {
        kernel_override,
        dtb_override,
    })
}

#[cfg(target_arch = "wasm32")]
enum ProfileSourceRootfs {
    Erofs(ErofsRootfs),
    Ext4(Ext4Rootfs),
    Fat(FatFs),
}

#[cfg(target_arch = "wasm32")]
impl ProfileSourceRootfs {
    async fn open(source: &BootProfileRootfs, reader: Arc<dyn BlockReader>) -> Result<Self> {
        match source {
            BootProfileRootfs::Ostree(source) => match &source.ostree {
                BootProfileRootfsFilesystemSource::Erofs(_) => {
                    let image_size_bytes = reader_size_bytes(reader.as_ref()).await?;
                    let rootfs = ErofsRootfs::new(reader, image_size_bytes)
                        .await
                        .map_err(|err| anyhow!("open boot profile erofs source: {err}"))?;
                    Ok(Self::Erofs(rootfs))
                }
                BootProfileRootfsFilesystemSource::Ext4(_) => {
                    let rootfs = Ext4Rootfs::open(reader).await?;
                    Ok(Self::Ext4(rootfs))
                }
                BootProfileRootfsFilesystemSource::Fat(_) => {
                    let rootfs = FatFs::open(reader)
                        .await
                        .map_err(|err| anyhow!("open boot profile fat source: {err}"))?;
                    Ok(Self::Fat(rootfs))
                }
            },
            BootProfileRootfs::Erofs(_) => {
                let image_size_bytes = reader_size_bytes(reader.as_ref()).await?;
                let rootfs = ErofsRootfs::new(reader, image_size_bytes)
                    .await
                    .map_err(|err| anyhow!("open boot profile erofs source: {err}"))?;
                Ok(Self::Erofs(rootfs))
            }
            BootProfileRootfs::Ext4(_) => {
                let rootfs = Ext4Rootfs::open(reader).await?;
                Ok(Self::Ext4(rootfs))
            }
            BootProfileRootfs::Fat(_) => {
                let rootfs = FatFs::open(reader)
                    .await
                    .map_err(|err| anyhow!("open boot profile fat source: {err}"))?;
                Ok(Self::Fat(rootfs))
            }
        }
    }

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read boot profile erofs path {path}: {err}")),
            Self::Ext4(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read boot profile ext4 path {path}: {err}")),
            Self::Fat(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read boot profile fat path {path}: {err}")),
        }
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self {
            Self::Erofs(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check boot profile erofs path {path}: {err}")),
            Self::Ext4(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check boot profile ext4 path {path}: {err}")),
            Self::Fat(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check boot profile fat path {path}: {err}")),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn non_empty_profile_path<'a>(path: &'a str, field: &str) -> Result<&'a str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        bail!("boot profile {field} must not be empty");
    }
    Ok(trimmed)
}

#[cfg(target_arch = "wasm32")]
async fn resolve_dtb_path_candidate_web(
    source_rootfs: &ProfileSourceRootfs,
    dtbs_base: &str,
    devicetree_name: &str,
) -> Result<String> {
    let devicetree_name = devicetree_name.trim().trim_start_matches('/');
    if devicetree_name.is_empty() {
        bail!("device profile devicetree_name is empty");
    }

    let mut candidates = Vec::new();
    if dtbs_base.ends_with(".dtb") {
        candidates.push(dtbs_base.to_string());
    } else {
        let dtb_file = format!("{devicetree_name}.dtb");
        candidates.push(join_profile_path(dtbs_base, dtb_file.as_str()));
        candidates.push(join_profile_path(dtbs_base, devicetree_name));
        candidates.push(dtbs_base.to_string());
    }

    for candidate in candidates {
        if source_rootfs.exists(candidate.as_str()).await? {
            return Ok(candidate);
        }
    }

    bail!("boot profile dtbs path {dtbs_base} does not contain dtb for {devicetree_name}")
}

#[cfg(target_arch = "wasm32")]
fn join_profile_path(base: &str, suffix: &str) -> String {
    let base = base.trim_end_matches('/');
    let suffix = suffix.trim_start_matches('/');
    if base.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base}/{suffix}")
    }
}

#[cfg(target_arch = "wasm32")]
async fn open_boot_profile_artifact_source(
    source: &BootProfileArtifactSource,
    pipeline_hints: &PipelineHints,
    gibblox_worker: &GibbloxWebWorker,
) -> Result<Arc<dyn BlockReader>> {
    if let BootProfileArtifactSource::File(source) = source {
        bail!(
            "boot profile file source '{}' is not supported in fastboop-web; use HTTP/casync sources",
            source.file
        );
    }

    let reader = open_artifact_source_via_worker(gibblox_worker, source, pipeline_hints).await?;
    normalize_partition_reader_block_size(source, reader).await
}

#[cfg(target_arch = "wasm32")]
async fn normalize_partition_reader_block_size(
    source: &BootProfileArtifactSource,
    reader: Arc<dyn BlockReader>,
) -> Result<Arc<dyn BlockReader>> {
    if !matches!(
        source,
        BootProfileArtifactSource::Mbr(_) | BootProfileArtifactSource::Gpt(_)
    ) || reader.block_size() == DEFAULT_IMAGE_BLOCK_SIZE
    {
        return Ok(reader);
    }

    let size_bytes = reader_size_bytes(reader.as_ref()).await?;
    let reader = WindowBlockReader::new(reader, 0, size_bytes, DEFAULT_IMAGE_BLOCK_SIZE)
        .await
        .map_err(|err| anyhow!("normalize partition reader block size: {err}"))?;
    Ok(Arc::new(reader))
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage0RootfsKind {
    Erofs,
    Ext4,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct Ext4Rootfs {
    fs: Ext4Fs,
}

#[cfg(target_arch = "wasm32")]
impl Ext4Rootfs {
    async fn open(reader: Arc<dyn BlockReader>) -> Result<Self> {
        let fs = Ext4Fs::open(reader)
            .await
            .map_err(|err| anyhow!("open ext4 rootfs: {err}"))?;
        Ok(Self { fs })
    }
}

#[cfg(target_arch = "wasm32")]
impl Filesystem for Ext4Rootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        self.fs
            .read_all(path)
            .await
            .map_err(|err| anyhow!("read ext4 path {path}: {err}"))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.fs
            .read_range(path, offset, len)
            .await
            .map_err(|err| anyhow!("read ext4 path range {path}@{offset}+{len}: {err}"))
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        self.fs
            .read_dir(path)
            .await
            .map_err(|err| anyhow!("read ext4 directory {path}: {err}"))
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        let ty = self
            .fs
            .entry_type(path)
            .await
            .map_err(|err| anyhow!("read ext4 entry type {path}: {err}"))?;
        Ok(ty.map(|entry| match entry {
            Ext4EntryType::File => FilesystemEntryType::File,
            Ext4EntryType::Directory => FilesystemEntryType::Directory,
            Ext4EntryType::Symlink => FilesystemEntryType::Symlink,
            Ext4EntryType::Other => FilesystemEntryType::Other,
        }))
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        self.fs
            .read_link(path)
            .await
            .map_err(|err| anyhow!("read ext4 symlink target {path}: {err}"))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        self.fs
            .exists(path)
            .await
            .map_err(|err| anyhow!("check ext4 path {path}: {err}"))
    }
}

#[cfg(target_arch = "wasm32")]
enum Stage0RootfsProvider {
    Erofs(ErofsRootfs),
    Ext4(Ext4Rootfs),
}

#[cfg(target_arch = "wasm32")]
impl Stage0RootfsProvider {
    async fn open(
        kind: Stage0RootfsKind,
        reader: Arc<dyn BlockReader>,
        size_bytes: u64,
    ) -> Result<Self> {
        match kind {
            Stage0RootfsKind::Erofs => {
                let rootfs = ErofsRootfs::new(reader, size_bytes)
                    .await
                    .map_err(|err| anyhow!("open erofs image: {err}"))?;
                Ok(Self::Erofs(rootfs))
            }
            Stage0RootfsKind::Ext4 => {
                let rootfs = Ext4Rootfs::open(reader).await?;
                Ok(Self::Ext4(rootfs))
            }
        }
    }

    fn switchroot_fs(&self) -> Stage0SwitchrootFs {
        match self {
            Self::Erofs(_) => Stage0SwitchrootFs::Erofs,
            Self::Ext4(_) => Stage0SwitchrootFs::Ext4,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl Filesystem for Stage0RootfsProvider {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_all(path).await,
            Self::Ext4(rootfs) => rootfs.read_all(path).await,
        }
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_range(path, offset, len).await,
            Self::Ext4(rootfs) => rootfs.read_range(path, offset, len).await,
        }
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_dir(path).await,
            Self::Ext4(rootfs) => rootfs.read_dir(path).await,
        }
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        match self {
            Self::Erofs(rootfs) => rootfs.entry_type(path).await,
            Self::Ext4(rootfs) => rootfs.entry_type(path).await,
        }
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_link(path).await,
            Self::Ext4(rootfs) => rootfs.read_link(path).await,
        }
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self {
            Self::Erofs(rootfs) => rootfs.exists(path).await,
            Self::Ext4(rootfs) => rootfs.exists(path).await,
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn rootfs_kind_for_web_boot(boot_profile: &BootProfile) -> Result<Stage0RootfsKind> {
    match &boot_profile.rootfs {
        BootProfileRootfs::Erofs(_) => Ok(Stage0RootfsKind::Erofs),
        BootProfileRootfs::Ext4(_) => Ok(Stage0RootfsKind::Ext4),
        BootProfileRootfs::Fat(_) => {
            bail!("web stage0 build does not support FAT rootfs providers")
        }
        BootProfileRootfs::Ostree(source) => match &source.ostree {
            BootProfileRootfsFilesystemSource::Erofs(_) => Ok(Stage0RootfsKind::Erofs),
            BootProfileRootfsFilesystemSource::Ext4(_) => Ok(Stage0RootfsKind::Ext4),
            BootProfileRootfsFilesystemSource::Fat(_) => {
                bail!("web stage0 build does not support OSTree on FAT rootfs")
            }
        },
    }
}

#[cfg(target_arch = "wasm32")]
async fn load_stage0_binary_sidecar(
    asset_url: Option<String>,
) -> core::result::Result<Option<Vec<u8>>, Stage0Error> {
    let url = asset_url.ok_or_else(|| {
        Stage0Error::Stage0Binary(
            "web build does not include the stage0 sidecar asset at assets/stage0/fastboop-stage0-aarch64-unknown-linux-musl"
                .to_string(),
        )
    })?;
    tracing::debug!(%url, "loading stage0 sidecar asset");
    let window = web_sys::window()
        .ok_or_else(|| Stage0Error::Stage0Binary("window unavailable".to_string()))?;
    let response = JsFuture::from(window.fetch_with_str(&url))
        .await
        .map_err(|err| {
            Stage0Error::Stage0Binary(format!(
                "fetch stage0 sidecar {url}: {}",
                js_value_to_string(&err)
            ))
        })?;
    let response = response.dyn_into::<web_sys::Response>().map_err(|err| {
        Stage0Error::Stage0Binary(format!(
            "fetch stage0 sidecar {url}: response object expected: {}",
            js_value_to_string(&err)
        ))
    })?;
    if !response.ok() {
        return Err(Stage0Error::Stage0Binary(format!(
            "fetch stage0 sidecar {url} failed: HTTP {}",
            response.status()
        )));
    }

    let buffer = response.array_buffer().map_err(|err| {
        Stage0Error::Stage0Binary(format!(
            "read stage0 sidecar {url} response body: {}",
            js_value_to_string(&err)
        ))
    })?;
    let buffer = JsFuture::from(buffer).await.map_err(|err| {
        Stage0Error::Stage0Binary(format!(
            "read stage0 sidecar {url}: {}",
            js_value_to_string(&err)
        ))
    })?;
    let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
    if bytes.is_empty() {
        return Err(Stage0Error::Stage0Binary(format!(
            "stage0 sidecar {url} is empty"
        )));
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Err(Stage0Error::Stage0Binary(format!(
            "stage0 sidecar {url} is not an ELF binary; rebuild fastboop-web with the real stage0 sidecar asset"
        )));
    }
    tracing::debug!(%url, size_bytes = bytes.len(), "loaded stage0 sidecar asset");
    Ok(Some(bytes))
}

fn emit_session_status(env: &mut WebBootEnvironment, status: &SessionStatus) {
    match status {
        SessionStatus::BootImageReady {
            boot_image_size, ..
        } => env.emit(SessionEvent::Phase {
            phase: SessionEventPhase::BuildingBootImage,
            detail: format!("boot image built ({boot_image_size} bytes)"),
        }),
        SessionStatus::Downloading {
            boot_image_size, ..
        } => env.emit(SessionEvent::Phase {
            phase: SessionEventPhase::Downloading,
            detail: format!("sending {boot_image_size} bytes"),
        }),
        SessionStatus::BootHandoffStarted { .. } => env.emit(SessionEvent::Phase {
            phase: SessionEventPhase::Booting,
            detail: "issuing fastboot boot".to_string(),
        }),
        SessionStatus::BootIssued { .. } => env.emit(SessionEvent::Log(
            "fastboot boot command accepted".to_string(),
        )),
        _ => {}
    }
}

#[cfg(target_arch = "wasm32")]
fn personalization_from_browser() -> Personalization {
    let locale = browser_locale().unwrap_or_else(|| "en_US.UTF-8".to_string());
    let timezone = browser_timezone().unwrap_or_else(|| "UTC".to_string());
    Personalization {
        locale: Some(locale.clone()),
        locale_messages: Some(locale),
        keymap: None,
        timezone: Some(timezone),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn webusb_serial_number(handle: &WebUsbDeviceHandle) -> Option<String> {
    let device = handle.device();
    let serial = Reflect::get(device.as_ref(), &JsValue::from_str("serialNumber"))
        .ok()?
        .as_string()?;
    let serial = serial.trim();
    if serial.is_empty() {
        None
    } else {
        Some(serial.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn webusb_serial_number(_handle: &WebUsbDeviceHandle) -> Option<String> {
    None
}

#[cfg(target_arch = "wasm32")]
fn browser_locale() -> Option<String> {
    let window = web_sys::window()?;
    let nav = window.navigator();
    let value = nav.language()?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value.replace('-', "_"))
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_timezone() -> Option<String> {
    let tz = js_sys::eval("Intl.DateTimeFormat().resolvedOptions().timeZone")
        .ok()?
        .as_string()?;
    if tz.trim().is_empty() { None } else { Some(tz) }
}

fn web_session_seed() -> Result<u64> {
    #[cfg(target_arch = "wasm32")]
    {
        let millis = js_sys::Date::now() as u64;
        let random = (js_sys::Math::random() * u64::MAX as f64) as u64;
        Ok(millis ^ random)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(0)
    }
}
