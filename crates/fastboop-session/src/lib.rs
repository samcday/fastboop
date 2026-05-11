#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;

use fastboop_core::bootimg::{BootImageError, build_android_bootimg};
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::fastboot::{FastbootProtocolError, FastbootWire, ProbeError, boot, download};
use fastboop_core::{BootProfile, DeviceProfile};
use fastboop_stage0_generator::{
    Stage0Build, Stage0Error, Stage0Options, build_stage0, stage0_binary_ready,
};
use gibblox_core::BlockReader;
use gobblytes_core::{Filesystem, FilesystemEntryType, normalize_ostree_deployment_path};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const SESSION_STATE_VERSION: u32 = 0;
pub const SESSION_STATE_MAGIC: &[u8; 8] = b"FBSESS0\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OstreeArg {
    Disabled,
    AutoDetect,
    Explicit(String),
}

#[derive(Debug)]
pub enum OstreeArgError {
    Normalize(gobblytes_core::OstreeError),
}

impl fmt::Display for OstreeArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normalize(err) => write!(f, "normalize ostree deployment path: {err}"),
        }
    }
}

pub fn parse_ostree_arg(raw: Option<&Option<String>>) -> Result<OstreeArg, OstreeArgError> {
    match raw {
        None => Ok(OstreeArg::Disabled),
        Some(None) => Ok(OstreeArg::AutoDetect),
        Some(Some(path)) => normalize_ostree_deployment_path(path)
            .map(OstreeArg::Explicit)
            .map_err(OstreeArgError::Normalize),
    }
}

pub fn resolve_effective_ostree_arg(
    requested: &OstreeArg,
    boot_profile: Option<&BootProfile>,
) -> OstreeArg {
    if matches!(requested, OstreeArg::Disabled)
        && boot_profile.is_some_and(|profile| profile.rootfs.is_ostree())
    {
        OstreeArg::AutoDetect
    } else {
        requested.clone()
    }
}

#[derive(Debug)]
pub enum OstreeDetectError {
    Filesystem {
        operation: &'static str,
        path: String,
        source: String,
    },
    NotDirectory {
        path: &'static str,
    },
    MissingDeploymentSymlink,
}

impl fmt::Display for OstreeDetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem {
                operation,
                path,
                source,
            } => write!(f, "{operation} {path}: {source}"),
            Self::NotDirectory { path } => {
                write!(
                    f,
                    "auto-detect ostree deployment failed: {path} is not a directory"
                )
            }
            Self::MissingDeploymentSymlink => write!(
                f,
                "auto-detect ostree deployment failed: no deployment symlink found under /ostree/boot.*"
            ),
        }
    }
}

pub async fn auto_detect_ostree_deployment_path<P>(rootfs: &P) -> Result<String, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    const OSTREE_ROOT: &str = "/ostree";

    if !is_directory(rootfs, OSTREE_ROOT).await? {
        return Err(OstreeDetectError::NotDirectory { path: OSTREE_ROOT });
    }

    for boot_dir in sorted_dir_entries(rootfs, OSTREE_ROOT).await? {
        if !boot_dir.starts_with("boot.") {
            continue;
        }
        let boot_path = format!("{OSTREE_ROOT}/{boot_dir}");
        if !is_directory(rootfs, &boot_path).await? {
            continue;
        }

        for stateroot in sorted_dir_entries(rootfs, &boot_path).await? {
            let stateroot_path = format!("{boot_path}/{stateroot}");
            if !is_directory(rootfs, &stateroot_path).await? {
                continue;
            }

            for checksum in sorted_dir_entries(rootfs, &stateroot_path).await? {
                let checksum_path = format!("{stateroot_path}/{checksum}");
                if !is_directory(rootfs, &checksum_path).await? {
                    continue;
                }

                for deploy_index in sorted_dir_entries(rootfs, &checksum_path).await? {
                    let candidate_path = format!("{checksum_path}/{deploy_index}");
                    if is_symlink(rootfs, &candidate_path).await? {
                        return Ok(candidate_path.trim_start_matches('/').to_string());
                    }
                }
            }
        }
    }

    Err(OstreeDetectError::MissingDeploymentSymlink)
}

async fn sorted_dir_entries<P>(rootfs: &P, path: &str) -> Result<Vec<String>, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    let mut entries = rootfs
        .read_dir(path)
        .await
        .map_err(|err| ostree_fs_error("read directory", path, err))?;
    entries.sort();
    Ok(entries)
}

async fn is_directory<P>(rootfs: &P, path: &str) -> Result<bool, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| ostree_fs_error("read entry type", path, err))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Directory)))
}

async fn is_symlink<P>(rootfs: &P, path: &str) -> Result<bool, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| ostree_fs_error("read entry type", path, err))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Symlink)))
}

fn ostree_fs_error<E>(operation: &'static str, path: &str, source: E) -> OstreeDetectError
where
    E: fmt::Display,
{
    OstreeDetectError::Filesystem {
        operation,
        path: path.to_string(),
        source: source.to_string(),
    }
}

#[derive(Debug)]
pub enum DeviceProfilePoolError {
    Builtin(postcard::Error),
    NotFound {
        requested: String,
        available: Vec<String>,
    },
}

impl fmt::Display for DeviceProfilePoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(err) => write!(f, "loading builtin device profiles: {err}"),
            Self::NotFound {
                requested,
                available,
            } => write!(
                f,
                "device profile '{requested}' not found; available ids: [{}]",
                available.join(", ")
            ),
        }
    }
}

/// Returns the device profile matching pool: the union of built-in,
/// channel-carried, and externally-loaded DevPros. Precedence on id collision
/// is `external > channel > built-in`.
pub fn build_device_profile_pool(
    channel_dev_profiles: &[DeviceProfile],
    external_profiles: impl IntoIterator<Item = DeviceProfile>,
) -> Result<Vec<DeviceProfile>, DeviceProfilePoolError> {
    let mut profiles = BTreeMap::<String, DeviceProfile>::new();
    for profile in builtin_profiles().map_err(DeviceProfilePoolError::Builtin)? {
        profiles.insert(profile.id.clone(), profile);
    }
    for profile in channel_dev_profiles {
        profiles.insert(profile.id.clone(), profile.clone());
    }
    for profile in external_profiles {
        profiles.insert(profile.id.clone(), profile);
    }
    Ok(profiles.into_values().collect())
}

pub fn resolve_profile_in_pool(
    pool: &[DeviceProfile],
    requested: &str,
) -> Result<DeviceProfile, DeviceProfilePoolError> {
    if let Some(profile) = pool.iter().find(|profile| profile.id == requested) {
        return Ok(profile.clone());
    }

    let mut available: Vec<_> = pool.iter().map(|profile| profile.id.clone()).collect();
    available.sort();
    Err(DeviceProfilePoolError::NotFound {
        requested: requested.to_string(),
        available,
    })
}

pub fn format_probe_error<E>(err: ProbeError<FastbootProtocolError<E>>) -> String
where
    E: fmt::Display,
{
    match err {
        ProbeError::Transport(err) => err.to_string(),
        ProbeError::MissingVar(name) => format!("missing getvar {name}"),
        ProbeError::Mismatch {
            name,
            expected,
            actual,
        } => format!("getvar {name} mismatch: expected '{expected}', got '{actual}'"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Phase {
        phase: SessionEventPhase,
        detail: String,
    },
    Log(String),
    SmooStatus {
        active: bool,
        export_count: u32,
        session_id: u64,
        ios_up: u64,
        ios_down: u64,
        bytes_up: u64,
        bytes_down: u64,
        inflight_requests: u64,
        max_inflight_requests: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEventPhase {
    Preparing,
    WaitingForDevice,
    DeviceDetected,
    BuildingStage0,
    BuildingBootImage,
    Downloading,
    Booting,
    WaitingForSmoo,
    Serving,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BootRequest {
    pub seed: u64,
    pub source: Option<String>,
    pub requested_device_profile: Option<String>,
    pub requested_boot_profile: Option<String>,
}

impl BootRequest {
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            source: None,
            requested_device_profile: None,
            requested_boot_profile: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionSnapshot {
    pub version: u32,
    pub request: BootRequest,
    pub status: SessionStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SessionStatus {
    New,
    Preparing,
    BootImageReady {
        profile_id: String,
        boot_image_size: u64,
        export_identity: String,
        export_size_bytes: u64,
    },
    Downloading {
        profile_id: String,
        boot_image_size: u64,
    },
    BootHandoffStarted {
        profile_id: String,
        boot_image_size: u64,
    },
    BootIssued {
        profile_id: String,
    },
    Serving {
        profile_id: String,
        export_identity: String,
        export_size_bytes: u64,
    },
    Completed,
    Failed {
        message: String,
    },
}

impl SessionStatus {
    pub const fn phase(&self) -> SessionPhase {
        match self {
            Self::New => SessionPhase::New,
            Self::Preparing => SessionPhase::Preparing,
            Self::BootImageReady { .. } => SessionPhase::Ready,
            Self::Downloading { .. }
            | Self::BootHandoffStarted { .. }
            | Self::BootIssued { .. } => SessionPhase::Booting,
            Self::Serving { .. } => SessionPhase::Serving,
            Self::Completed => SessionPhase::Completed,
            Self::Failed { .. } => SessionPhase::Failed,
        }
    }

    pub const fn is_post_handoff(&self) -> bool {
        matches!(
            self,
            Self::BootHandoffStarted { .. } | Self::BootIssued { .. } | Self::Serving { .. }
        )
    }

    pub fn profile_id(&self) -> Option<&str> {
        match self {
            Self::BootImageReady { profile_id, .. }
            | Self::Downloading { profile_id, .. }
            | Self::BootHandoffStarted { profile_id, .. }
            | Self::BootIssued { profile_id }
            | Self::Serving { profile_id, .. } => Some(profile_id),
            Self::New | Self::Preparing | Self::Completed | Self::Failed { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SessionPhase {
    New,
    Preparing,
    Ready,
    Booting,
    Serving,
    Completed,
    Failed,
}

#[derive(Clone)]
pub struct FastboopSession {
    inner: Rc<RefCell<SessionSnapshot>>,
}

impl FastboopSession {
    pub fn new(request: BootRequest) -> Self {
        Self::from_snapshot(SessionSnapshot {
            version: SESSION_STATE_VERSION,
            request,
            status: SessionStatus::New,
        })
    }

    pub fn from_snapshot(snapshot: SessionSnapshot) -> Self {
        Self {
            inner: Rc::new(RefCell::new(snapshot)),
        }
    }

    pub async fn request(&self) -> BootRequest {
        self.snapshot_sync().request
    }

    pub async fn status(&self) -> SessionStatus {
        self.snapshot_sync().status
    }

    pub async fn phase(&self) -> SessionPhase {
        self.snapshot_sync().status.phase()
    }

    pub async fn snapshot(&self) -> SessionSnapshot {
        self.snapshot_sync()
    }

    pub async fn prepare<E>(&self, env: &mut E) -> Result<PreparedBoot, E::Error>
    where
        E: SessionEnvironment,
        E::Error: fmt::Display,
    {
        let resume_status = self.status().await;
        let preserve_handoff_state = resume_status.is_post_handoff();
        if !preserve_handoff_state {
            self.transition(env, SessionStatus::Preparing).await?;
        }

        let prepared = match env.prepare_boot(self).await {
            Ok(prepared) => prepared,
            Err(err) => {
                let message = err.to_string();
                let _ = self.mark_failed(env, message).await;
                return Err(err);
            }
        };

        if !preserve_handoff_state {
            self.transition(env, prepared.ready_status()).await?;
        }
        Ok(prepared)
    }

    pub async fn run<E>(
        &self,
        env: &mut E,
    ) -> Result<(), SessionRunError<E::Error, <E::Fastboot as FastbootWire>::Error>>
    where
        E: BootSessionEnvironment,
        E::Error: fmt::Display,
        <E::Fastboot as FastbootWire>::Error: fmt::Display,
    {
        let resume_status = self.status().await;
        let post_handoff_resume = resume_status.is_post_handoff();
        let prepared = self
            .prepare(env)
            .await
            .map_err(SessionRunError::Environment)?;

        if !post_handoff_resume {
            let mut fastboot = match env.connect_fastboot(self, &prepared.info()).await {
                Ok(fastboot) => fastboot,
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.mark_failed(env, message).await;
                    return Err(SessionRunError::Environment(err));
                }
            };

            self.transition(env, prepared.downloading_status())
                .await
                .map_err(SessionRunError::Environment)?;
            if let Err(err) = download(&mut fastboot, &prepared.boot_image).await {
                let message = err.to_string();
                let _ = self.mark_failed(env, message).await;
                return Err(SessionRunError::Fastboot(err));
            }

            self.transition(env, prepared.handoff_started_status())
                .await
                .map_err(SessionRunError::Environment)?;
            if let Err(err) = boot(&mut fastboot).await {
                let message = err.to_string();
                let _ = self.mark_failed(env, message).await;
                return Err(SessionRunError::Fastboot(err));
            }

            self.transition(env, prepared.boot_issued_status())
                .await
                .map_err(SessionRunError::Environment)?;
        }

        self.transition(env, prepared.serving_status())
            .await
            .map_err(SessionRunError::Environment)?;
        let export = prepared.export;
        if let Err(err) = env.serve_runtime(self, export).await {
            let message = err.to_string();
            let _ = self.mark_failed(env, message).await;
            return Err(SessionRunError::Environment(err));
        }
        self.transition(env, SessionStatus::Completed)
            .await
            .map_err(SessionRunError::Environment)
    }

    async fn transition<E>(&self, env: &mut E, status: SessionStatus) -> Result<(), E::Error>
    where
        E: SessionEnvironment,
    {
        let snapshot = self.replace_status(status);
        let encoded =
            encode_session_snapshot(&snapshot).map_err(|err| env.session_codec_error(err))?;
        tracing::debug!(phase = ?snapshot.status.phase(), "fastboop session transition");
        env.persist_session(&snapshot, &encoded).await
    }

    async fn mark_failed<E>(&self, env: &mut E, message: String) -> Result<(), E::Error>
    where
        E: SessionEnvironment,
    {
        self.transition(env, SessionStatus::Failed { message })
            .await
    }

    fn replace_status(&self, status: SessionStatus) -> SessionSnapshot {
        let mut snapshot = self.inner.borrow_mut();
        snapshot.status = status;
        snapshot.clone()
    }

    pub fn snapshot_sync(&self) -> SessionSnapshot {
        self.inner.borrow().clone()
    }
}

impl Serialize for FastboopSession {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.snapshot_sync().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FastboopSession {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let snapshot = SessionSnapshot::deserialize(deserializer)?;
        Ok(Self::from_snapshot(snapshot))
    }
}

#[derive(Clone)]
pub struct RuntimeExport {
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
}

pub struct PreparedBoot {
    pub profile_id: String,
    pub boot_image: Vec<u8>,
    pub export: RuntimeExport,
}

impl PreparedBoot {
    pub fn info(&self) -> PreparedBootInfo {
        PreparedBootInfo {
            profile_id: self.profile_id.clone(),
            boot_image_size: self.boot_image.len() as u64,
            export_identity: self.export.identity.clone(),
            export_size_bytes: self.export.size_bytes,
        }
    }

    fn ready_status(&self) -> SessionStatus {
        let info = self.info();
        SessionStatus::BootImageReady {
            profile_id: info.profile_id,
            boot_image_size: info.boot_image_size,
            export_identity: info.export_identity,
            export_size_bytes: info.export_size_bytes,
        }
    }

    fn downloading_status(&self) -> SessionStatus {
        SessionStatus::Downloading {
            profile_id: self.profile_id.clone(),
            boot_image_size: self.boot_image.len() as u64,
        }
    }

    fn handoff_started_status(&self) -> SessionStatus {
        SessionStatus::BootHandoffStarted {
            profile_id: self.profile_id.clone(),
            boot_image_size: self.boot_image.len() as u64,
        }
    }

    fn boot_issued_status(&self) -> SessionStatus {
        SessionStatus::BootIssued {
            profile_id: self.profile_id.clone(),
        }
    }

    fn serving_status(&self) -> SessionStatus {
        SessionStatus::Serving {
            profile_id: self.profile_id.clone(),
            export_identity: self.export.identity.clone(),
            export_size_bytes: self.export.size_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedBootInfo {
    pub profile_id: String,
    pub boot_image_size: u64,
    pub export_identity: String,
    pub export_size_bytes: u64,
}

pub trait SessionEnvironment {
    type Error;

    fn session_codec_error(&mut self, err: SessionCodecError) -> Self::Error;

    async fn persist_session(
        &mut self,
        snapshot: &SessionSnapshot,
        encoded: &[u8],
    ) -> Result<(), Self::Error>;

    async fn prepare_boot(
        &mut self,
        session: &FastboopSession,
    ) -> Result<PreparedBoot, Self::Error>;
}

pub trait BootSessionEnvironment: SessionEnvironment {
    type Fastboot: FastbootWire;

    async fn connect_fastboot(
        &mut self,
        session: &FastboopSession,
        prepared: &PreparedBootInfo,
    ) -> Result<Self::Fastboot, Self::Error>;

    async fn serve_runtime(
        &mut self,
        session: &FastboopSession,
        export: RuntimeExport,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum SessionRunError<E, F> {
    Environment(E),
    Fastboot(FastbootProtocolError<F>),
}

impl<E, F> fmt::Display for SessionRunError<E, F>
where
    E: fmt::Display,
    F: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment(err) => write!(f, "session environment error: {err}"),
            Self::Fastboot(err) => write!(f, "fastboot handoff error: {err}"),
        }
    }
}

pub struct Stage0Assembly {
    pub options: Stage0Options,
    pub stage0_binary: Option<Vec<u8>>,
    pub extra_cmdline: Option<String>,
    pub existing_cpio: Option<Vec<u8>>,
}

impl Stage0Assembly {
    pub fn new(options: Stage0Options, stage0_binary: Option<Vec<u8>>) -> Self {
        Self {
            options,
            stage0_binary,
            extra_cmdline: None,
            existing_cpio: None,
        }
    }

    pub fn with_extra_cmdline(mut self, extra_cmdline: Option<String>) -> Self {
        self.extra_cmdline = extra_cmdline;
        self
    }

    pub fn with_existing_cpio(mut self, existing_cpio: Option<Vec<u8>>) -> Self {
        self.existing_cpio = existing_cpio;
        self
    }

    pub async fn build<P>(
        &self,
        profile: &DeviceProfile,
        rootfs: &P,
    ) -> Result<Stage0Build, Stage0Error>
    where
        P: Filesystem,
    {
        build_stage0(
            profile,
            rootfs,
            &self.options,
            stage0_binary_ready(self.stage0_binary.clone()),
            self.extra_cmdline.as_deref(),
            self.existing_cpio.as_deref(),
        )
        .await
    }
}

pub fn build_android_boot_payload(
    profile: &DeviceProfile,
    build: Stage0Build,
) -> Result<Vec<u8>, BootImageError> {
    let cmdline = join_cmdline(
        profile
            .boot
            .fastboot_boot
            .android_bootimg
            .cmdline_append
            .as_deref(),
        Some(build.kernel_cmdline_append.as_str()),
    );

    let mut kernel_image = build.kernel_image;
    if profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .append_dtb()
    {
        kernel_image.extend_from_slice(&build.dtb);
    }

    build_android_bootimg(
        profile,
        &kernel_image,
        &build.initrd,
        Some(&build.dtb),
        &cmdline,
    )
}

pub fn join_cmdline(left: Option<&str>, right: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(left) = left.map(str::trim).filter(|value| !value.is_empty()) {
        out.push_str(left);
    }
    if let Some(right) = right.map(str::trim).filter(|value| !value.is_empty()) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(right);
    }
    out
}

#[derive(Debug)]
pub enum SessionCodecError {
    BadMagic,
    Encode(postcard::Error),
    Decode(postcard::Error),
}

impl fmt::Display for SessionCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "session state has an invalid magic header"),
            Self::Encode(err) => write!(f, "encode session state: {err}"),
            Self::Decode(err) => write!(f, "decode session state: {err}"),
        }
    }
}

pub fn encode_session_snapshot(snapshot: &SessionSnapshot) -> Result<Vec<u8>, SessionCodecError> {
    let payload = postcard::to_allocvec(snapshot).map_err(SessionCodecError::Encode)?;
    let mut out = Vec::with_capacity(SESSION_STATE_MAGIC.len() + payload.len());
    out.extend_from_slice(SESSION_STATE_MAGIC);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_session_snapshot(bytes: &[u8]) -> Result<SessionSnapshot, SessionCodecError> {
    let payload = bytes
        .strip_prefix(SESSION_STATE_MAGIC)
        .ok_or(SessionCodecError::BadMagic)?;
    postcard::from_bytes(payload).map_err(SessionCodecError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_snapshot_round_trips_postcard_envelope() {
        let snapshot = SessionSnapshot {
            version: SESSION_STATE_VERSION,
            request: BootRequest {
                seed: 42,
                source: Some("rootfs.ero".to_string()),
                requested_device_profile: Some("oneplus-fajita".to_string()),
                requested_boot_profile: Some("pmos".to_string()),
            },
            status: SessionStatus::BootHandoffStarted {
                profile_id: "oneplus-fajita".to_string(),
                boot_image_size: 1024,
            },
        };

        let encoded = encode_session_snapshot(&snapshot).unwrap();
        assert!(encoded.starts_with(SESSION_STATE_MAGIC));
        let decoded = decode_session_snapshot(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn fastboop_session_serializes_as_snapshot() {
        let session = FastboopSession::from_snapshot(SessionSnapshot {
            version: SESSION_STATE_VERSION,
            request: BootRequest::new(7),
            status: SessionStatus::Serving {
                profile_id: "oneplus-fajita".to_string(),
                export_identity: "test-export".to_string(),
                export_size_bytes: 4096,
            },
        });

        let encoded = postcard::to_allocvec(&session).unwrap();
        let decoded: FastboopSession = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.snapshot_sync(), session.snapshot_sync());
    }

    #[test]
    fn ostree_arg_normalizes_explicit_paths() {
        let raw = Some(Some(" /ostree//boot.1/./fedora/abc/0/ ".to_string()));
        let parsed = parse_ostree_arg(raw.as_ref()).unwrap();
        assert_eq!(
            parsed,
            OstreeArg::Explicit("ostree/boot.1/fedora/abc/0".to_string())
        );
    }

    #[test]
    fn device_profile_pool_reports_available_ids() {
        let pool = build_device_profile_pool(&[], []).unwrap();
        let err = resolve_profile_in_pool(&pool, "does-not-exist").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("does-not-exist"));
        assert!(message.contains("available ids"));
    }
}
