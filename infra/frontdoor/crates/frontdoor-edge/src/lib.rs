use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use frontdoor_core::content_type::{cache_control_for_ext, content_type_for_ext};
use tar::EntryType;
use tracing::{debug, error, info, trace, warn};
use wstd::http::{Body, BodyExt, Client, Request, Response, StatusCode};

static TRACING_INIT: Once = Once::new();
static CONFIG: OnceLock<Config> = OnceLock::new();
static VERSION_LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();

#[derive(Clone, Debug)]
struct Config {
    live_version: String,
    cache_dir: String,
    github_owner: String,
    github_repo: String,
    asset_name_template: String,
    max_cache_bytes: u64,
    max_download_bytes: u64,
    matrix_server_name: String,
    matrix_client_base_url: String,
}

#[derive(Debug)]
struct EdgeError {
    status: StatusCode,
    message: String,
}

impl EdgeError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl Config {
    fn from_env() -> Self {
        let live_version = std::env::var("LIVE_VERSION").expect("LIVE_VERSION env var must be set").trim().to_string();
        if !frontdoor_core::version::is_valid_version(&live_version) {
            panic!("LIVE_VERSION must match vX.Y.Z or vX.Y.Z-rc.N");
        }

        Self {
            live_version,
            cache_dir: env_or("CACHE_DIR", "/cache"),
            github_owner: env_or("GITHUB_OWNER", "samcday"),
            github_repo: env_or("GITHUB_REPO", "fastboop"),
            asset_name_template: env_or("ASSET_NAME_TEMPLATE", "fastboop-web-{version}.tar.gz"),
            max_cache_bytes: env_u64("MAX_CACHE_BYTES", 0),
            max_download_bytes: env_u64("MAX_DOWNLOAD_BYTES", 100_000_000),
            matrix_server_name: env_or("MATRIX_SERVER_NAME", "matrix.fastboop.win:443"),
            matrix_client_base_url: env_or("MATRIX_CLIENT_BASE_URL", "https://matrix.fastboop.win"),
        }
    }

    fn web_cache_dir(&self) -> PathBuf {
        PathBuf::from(&self.cache_dir).join("web")
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_u64(name: &str, default: u64) -> u64 {
    let raw = env_or(name, "");
    if raw.is_empty() {
        return default;
    }
    raw.parse()
        .unwrap_or_else(|_| panic!("{name} must be an integer"))
}

fn config() -> &'static Config {
    CONFIG.get_or_init(|| {
        let cfg = Config::from_env();
        info!(
            live_version = %cfg.live_version,
            github_owner = %cfg.github_owner,
            github_repo = %cfg.github_repo,
            cache_dir = %cfg.cache_dir,
            max_cache_bytes = cfg.max_cache_bytes,
            max_download_bytes = cfg.max_download_bytes,
            "config loaded"
        );
        cfg
    })
}

fn version_lock(version: &str) -> Arc<Mutex<()>> {
    let locks = VERSION_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = locks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .entry(version.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn ensure_tracing() {
    TRACING_INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_target(false)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    });
}

#[wstd::http_server]
async fn main(request: Request<Body>) -> Result<Response<Body>, wstd::http::Error> {
    ensure_tracing();
    let cfg = config();
    let path = request.uri().path();
    let method = request.method().clone();
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    info!(method = %method, path = %path, host = %host, "incoming request");

    if !host.is_empty()
        && !host.starts_with("www.")
        && !host.starts_with("edge.")
        && !host.starts_with("localhost")
        && !host.starts_with("127.")
    {
        debug!(handler = "apex_redirect", path = %path, "route matched");
        return Ok(apex_redirect(path, request.uri().query()));
    }

    match path {
        "/healthz" => {
            debug!(handler = "healthz", path = %path, "route matched");
            Ok(text_response(StatusCode::OK, "ok\n"))
        }
        "/.well-known/matrix/server" => {
            debug!(handler = "matrix_server", path = %path, "route matched");
            Ok(matrix_server_response(cfg))
        }
        "/.well-known/matrix/client" => {
            debug!(handler = "matrix_client", path = %path, "route matched");
            Ok(matrix_client_response(cfg))
        }
        "/__fastboop/live" => {
            debug!(handler = "live_version", path = %path, "route matched");
            Ok(text_response(
                StatusCode::OK,
                &format!("{}\n", cfg.live_version),
            ))
        }
        p if p == "/device-permissions" || p.starts_with("/device-permissions/") => {
            debug!(handler = "device_permissions_redirect", path = %path, "route matched");
            Ok(device_permissions_redirect(path))
        }
        "/" => {
            debug!(handler = "root_redirect", path = %path, "route matched");
            Ok(root_redirect(cfg, request.uri().query()))
        }
        _ => match frontdoor_core::version::parse_version_path(path) {
            Some((version, relative)) => {
                debug!(
                    handler = "serve_versioned",
                    path = %path,
                    version = %version,
                    relative = %relative,
                    "route matched"
                );
                serve_versioned(cfg, version, relative).await
            }
            None => {
                // Bare version path without trailing slash (e.g. /v0.0.1-rc.13)
                // -> redirect to add the slash so parse_version_path matches next time
                let bare = path.strip_prefix('/').unwrap_or(path);
                if frontdoor_core::version::is_valid_version(bare) {
                    debug!(handler = "version_redirect", path = %path, "route matched");
                    return Ok(Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header("location", format!("{path}/"))
                        .header("cache-control", "no-store")
                        .header("content-length", "0")
                        .body(Body::empty())
                        .expect("version redirect response should build"));
                }
                debug!(handler = "not_found", path = %path, "route matched");
                Ok(text_response(StatusCode::NOT_FOUND, "not found\n"))
            }
        },
    }
}

async fn serve_versioned(
    cfg: &Config,
    version: &str,
    relative: &str,
) -> Result<Response<Body>, wstd::http::Error> {
    if !frontdoor_core::version::is_valid_version(version) {
        return Ok(text_response(StatusCode::NOT_FOUND, "not found\n"));
    }

    let mut normalized = relative.trim_start_matches('/').to_string();
    if normalized.is_empty() {
        normalized = "index.html".to_string();
    } else if normalized.ends_with('/') {
        normalized.push_str("index.html");
    }

    if !is_safe_relative_path(&normalized) {
        return Ok(text_response(StatusCode::NOT_FOUND, "not found\n"));
    }

    let decoded = match percent_decode_path(&normalized) {
        Ok(decoded) => decoded,
        Err(()) => {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid path encoding\n",
            ));
        }
    };
    if !is_safe_relative_path(&decoded) {
        return Ok(text_response(StatusCode::NOT_FOUND, "not found\n"));
    }

    let version_dir = cfg.web_cache_dir().join(version);
    let ready = version_dir.join(".ready");
    if fs::metadata(&ready).is_err()
        && let Err(err) = materialize_version(cfg, version).await
    {
        error!(
            version = %version,
            error = %err.message.as_str(),
            "materialization failed"
        );
        return Ok(text_response(err.status, &format!("{}\n", err.message)));
    }

    let path = match resolve_file_path(&version_dir, &decoded) {
        Ok(path) => path,
        Err(err) => return Ok(text_response(err.status, &format!("{}\n", err.message))),
    };

    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(text_response(StatusCode::NOT_FOUND, "not found\n"));
        }
        Err(err) => {
            error!(path = ?path, error = %err, "failed to read asset");
            return Ok(text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to read asset\n",
            ));
        }
    };

    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let content_type = content_type_for_ext(ext);
    let cache_control = cache_control_for_ext(ext);
    debug!(
        path = ?path,
        content_type = %content_type,
        bytes = bytes.len(),
        "resolved file for serving"
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type)
        .header("cache-control", cache_control)
        .header("content-length", bytes.len().to_string())
        .body(Body::from(bytes))
        .expect("asset response should build"))
}

async fn materialize_version(cfg: &Config, version: &str) -> Result<(), EdgeError> {
    let web_dir = cfg.web_cache_dir();
    let target_dir = web_dir.join(version);
    let ready = target_dir.join(".ready");

    if fs::metadata(&ready).is_ok() {
        info!(version = %version, "version already materialized");
        return Ok(());
    }

    fs::create_dir_all(&web_dir).map_err(io_500)?;

    let lock = version_lock(version);
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if fs::metadata(&ready).is_ok() {
        info!(version = %version, "version already materialized");
        return Ok(());
    }

    info!(version = %version, "materialization started");
    let start = Instant::now();

    let tmp_dir = create_temp_dir(&web_dir, version)?;
    let tarball_path = tmp_dir.join("release.tar.gz");
    let extract_root = tmp_dir.join("extract");
    let staged_root = tmp_dir.join("site");

    let result: Result<(), EdgeError> = async {
        fs::create_dir_all(&extract_root).map_err(io_500)?;

        let bytes_downloaded = download_release_tarball(cfg, version, &tarball_path).await?;
        info!(version = %version, bytes = bytes_downloaded, "download completed");

        let extracted_entries = match extract_release_tarball(&tarball_path, &extract_root) {
            Ok(count) => count,
            Err(err) => {
                error!(
                    version = %version,
                    error = %err.message.as_str(),
                    "extraction failed"
                );
                return Err(err);
            }
        };
        info!(
            version = %version,
            entry_count = extracted_entries,
            "extraction completed"
        );

        let site_root = resolve_extracted_site_root(&extract_root)?;
        debug!(version = %version, path = ?site_root, "site root resolved");
        copy_dir_recursive(&site_root, &staged_root)?;
        fs::write(staged_root.join(".ready"), b"").map_err(io_500)?;

        if fs::metadata(&target_dir).is_ok() {
            fs::remove_dir_all(&target_dir).map_err(io_500)?;
        }
        fs::rename(&staged_root, &target_dir).map_err(io_500)?;

        Ok(())
    }
    .await;

    if let Err(err) = result {
        if let Err(cleanup_err) = fs::remove_dir_all(&tmp_dir) {
            warn!(path = ?tmp_dir, error = %cleanup_err, "failed to clean temp dir");
        }
        return Err(err);
    }

    if let Err(cleanup_err) = fs::remove_dir_all(&tmp_dir) {
        warn!(path = ?tmp_dir, error = %cleanup_err, "failed to clean temp dir");
    }

    if cfg.max_cache_bytes > 0 {
        enforce_cache_limit(cfg);
    }

    info!(
        version = %version,
        duration = ?start.elapsed(),
        "materialization completed"
    );

    Ok(())
}

async fn download_release_tarball(
    cfg: &Config,
    version: &str,
    dest: &Path,
) -> Result<u64, EdgeError> {
    let asset_name = release_asset_name(&cfg.asset_name_template, version)?;
    let start_url = format!(
        "https://github.com/{}/{}/releases/download/{}/{}",
        cfg.github_owner, cfg.github_repo, version, asset_name
    );
    debug!(version = %version, url = %start_url, "constructed github download url");

    let mut temp_path = dest.as_os_str().to_owned();
    temp_path.push(".downloading");
    let temp_path = PathBuf::from(temp_path);

    let mut url = start_url;
    let mut redirects = 0_usize;
    let client = Client::new();

    loop {
        let request = Request::builder()
            .method("GET")
            .uri(&url)
            .body(Body::empty())
            .expect("request should build");

        let response = client.send(request).await.map_err(|err| {
            error!(
                version = %version,
                status = %"request_error",
                url = %url,
                error = %err,
                "download failed"
            );
            EdgeError::new(
                StatusCode::BAD_GATEWAY,
                format!("failed to download release asset for {version}: {err}"),
            )
        })?;

        let status = response.status();
        if is_redirect_status(status) {
            redirects += 1;
            if redirects > 5 {
                error!(version = %version, status = %status, url = %url, "download failed");
                return Err(EdgeError::new(
                    StatusCode::BAD_GATEWAY,
                    "too many redirects while downloading release asset",
                ));
            }

            let Some(location) = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
            else {
                error!(version = %version, status = %status, url = %url, "download failed");
                return Err(EdgeError::new(
                    StatusCode::BAD_GATEWAY,
                    "redirect response missing location header",
                ));
            };

            debug!(
                from_url = %url,
                to_url = %location,
                redirect_count = redirects,
                "followed download redirect"
            );
            url = location.to_string();
            continue;
        }

        if status == StatusCode::NOT_FOUND {
            error!(version = %version, status = %status, url = %url, "download failed");
            return Err(EdgeError::new(
                StatusCode::NOT_FOUND,
                format!("release asset '{asset_name}' for {version} was not found"),
            ));
        }

        if !status.is_success() {
            error!(version = %version, status = %status, url = %url, "download failed");
            return Err(EdgeError::new(
                StatusCode::BAD_GATEWAY,
                format!("failed to download release asset for {version}: {status}"),
            ));
        }

        if let Some(len) = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            && cfg.max_download_bytes > 0
            && len > cfg.max_download_bytes
        {
            error!(
                version = %version,
                status = %status,
                url = %url,
                content_length = len,
                max_download_bytes = cfg.max_download_bytes,
                "download rejected by size limit"
            );
            let _ = fs::remove_file(&temp_path);
            return Err(EdgeError::new(
                StatusCode::BAD_GATEWAY,
                format!("release asset for {version} exceeds max download size ({len} bytes)"),
            ));
        }

        let mut file = fs::File::create(&temp_path).map_err(io_500)?;
        let mut total_bytes = 0_u64;
        let mut body = response.into_body().into_boxed_body();

        loop {
            match BodyExt::frame(&mut body).await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        total_bytes = total_bytes.saturating_add(data.len() as u64);
                        if cfg.max_download_bytes > 0 && total_bytes > cfg.max_download_bytes {
                            error!(
                                version = %version,
                                status = %status,
                                url = %url,
                                bytes = total_bytes,
                                max_download_bytes = cfg.max_download_bytes,
                                "download rejected by size limit"
                            );
                            let _ = fs::remove_file(&temp_path);
                            return Err(EdgeError::new(
                                StatusCode::BAD_GATEWAY,
                                format!("release asset for {version} exceeds max download size"),
                            ));
                        }
                        if let Err(err) = file.write_all(data) {
                            let _ = fs::remove_file(&temp_path);
                            return Err(io_500(err));
                        }
                    }
                }
                Some(Err(err)) => {
                    error!(
                        version = %version,
                        status = %status,
                        url = %url,
                        error = %err,
                        "download failed"
                    );
                    let _ = fs::remove_file(&temp_path);
                    return Err(EdgeError::new(
                        StatusCode::BAD_GATEWAY,
                        format!("failed to read release response body for {version}: {err}"),
                    ));
                }
                None => break,
            }
        }

        if let Err(err) = file.flush() {
            let _ = fs::remove_file(&temp_path);
            return Err(io_500(err));
        }
        if let Err(err) = fs::rename(&temp_path, dest) {
            let _ = fs::remove_file(&temp_path);
            return Err(io_500(err));
        }
        debug!(from = ?temp_path, to = ?dest, "promoted downloaded tarball");
        return Ok(total_bytes);
    }
}

fn extract_release_tarball(tarball: &Path, extract_root: &Path) -> Result<usize, EdgeError> {
    let file = fs::File::open(tarball).map_err(|err| {
        EdgeError::new(
            StatusCode::BAD_GATEWAY,
            format!("release archive is invalid: {err}"),
        )
    })?;

    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = archive.entries().map_err(|err| {
        EdgeError::new(
            StatusCode::BAD_GATEWAY,
            format!("release archive is invalid: {err}"),
        )
    })?;
    let mut extracted_entries = 0_usize;

    while let Some(entry) = entries.next() {
        let mut entry = entry.map_err(|err| {
            EdgeError::new(
                StatusCode::BAD_GATEWAY,
                format!("release archive is invalid: {err}"),
            )
        })?;

        let entry_type = entry.header().entry_type();
        let entry_size = entry.size();
        if matches!(
            entry_type,
            EntryType::Symlink | EntryType::Link | EntryType::GNUSparse
        ) {
            return Err(EdgeError::new(
                StatusCode::BAD_GATEWAY,
                "release archive may not contain symlinks, hardlinks, or sparse files",
            ));
        }

        let rel_path = entry.path().map_err(|err| {
            EdgeError::new(
                StatusCode::BAD_GATEWAY,
                format!("release archive is invalid: {err}"),
            )
        })?;
        trace!(
            path = ?rel_path,
            entry_type = ?entry_type,
            size = entry_size,
            "extracting tar entry"
        );

        let out_path = safe_join_under(extract_root, rel_path.as_ref()).map_err(|_| {
            EdgeError::new(
                StatusCode::BAD_GATEWAY,
                "release archive contains an invalid path",
            )
        })?;

        let unpack_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| entry.unpack(&out_path)));

        match unpack_result {
            Ok(Ok(_)) => {
                extracted_entries += 1;
                continue;
            }
            Ok(Err(err)) => {
                // unpack() writes content first, then sets metadata (permissions,
                // mtime). On WASI these metadata ops always fail but the file content
                // is already on disk. If a genuine write error ever surfaces through
                // this path, the subsequent extraction steps will catch it (missing
                // index.html, corrupt files, etc).
                warn!(path = ?out_path, error = %err, "entry.unpack metadata failed (content written)");
                extracted_entries += 1;
                continue;
            }
            Err(_) => {
                warn!(path = ?out_path, "entry.unpack panicked; trying manual extraction");
            }
        }

        if entry_type.is_dir() {
            fs::create_dir_all(&out_path).map_err(io_500)?;
            extracted_entries += 1;
            continue;
        }

        if !entry_type.is_file() {
            return Err(EdgeError::new(
                StatusCode::BAD_GATEWAY,
                "release archive contains unsupported entry type",
            ));
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(io_500)?;
        }

        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(|err| {
            EdgeError::new(
                StatusCode::BAD_GATEWAY,
                format!("release archive entry could not be read: {err}"),
            )
        })?;
        fs::write(&out_path, data).map_err(io_500)?;
        extracted_entries += 1;
    }

    Ok(extracted_entries)
}

fn resolve_extracted_site_root(extract_root: &Path) -> Result<PathBuf, EdgeError> {
    let root_index = extract_root.join("index.html");
    if fs::metadata(&root_index)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
    {
        debug!(path = ?extract_root, "site root resolved");
        return Ok(extract_root.to_path_buf());
    }

    let mut dirs = Vec::new();
    for entry in fs::read_dir(extract_root).map_err(io_500)? {
        let entry = entry.map_err(io_500)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(io_500)?;
        if file_type.is_dir() {
            dirs.push(path);
        }
    }

    if dirs.len() == 1 {
        let candidate = dirs[0].join("index.html");
        if fs::metadata(&candidate)
            .map(|meta| meta.is_file())
            .unwrap_or(false)
        {
            debug!(path = ?dirs[0], "site root resolved");
            return Ok(dirs.remove(0));
        }
    }

    Err(EdgeError::new(
        StatusCode::BAD_GATEWAY,
        "release archive does not contain index.html",
    ))
}

fn resolve_file_path(site_root: &Path, request_path: &str) -> Result<PathBuf, EdgeError> {
    let candidate = safe_join_under(site_root, Path::new(request_path)).map_err(|_| {
        EdgeError::new(
            StatusCode::NOT_FOUND,
            "release archive contains an invalid path",
        )
    })?;

    if fs::metadata(&candidate)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
    {
        return Ok(candidate);
    }

    if fs::metadata(&candidate)
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        let nested_index = candidate.join("index.html");
        if fs::metadata(&nested_index)
            .map(|meta| meta.is_file())
            .unwrap_or(false)
        {
            return Ok(nested_index);
        }
    }

    let basename = Path::new(request_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if basename.contains('.') {
        return Err(EdgeError::new(StatusCode::NOT_FOUND, "not found"));
    }

    let fallback = site_root.join("index.html");
    if fs::metadata(&fallback)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
    {
        return Ok(fallback);
    }

    Err(EdgeError::new(StatusCode::NOT_FOUND, "not found"))
}

fn release_asset_name(template: &str, version: &str) -> Result<String, EdgeError> {
    if template.contains('{') {
        let mut i = 0usize;
        while let Some(rel) = template[i..].find('{') {
            let start = i + rel;
            let Some(end_rel) = template[start..].find('}') else {
                return Err(EdgeError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ASSET_NAME_TEMPLATE may only use {version} placeholders",
                ));
            };
            let end = start + end_rel;
            let key = &template[start + 1..end];
            if key != "version" {
                return Err(EdgeError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ASSET_NAME_TEMPLATE may only use {version} placeholders",
                ));
            }
            i = end + 1;
        }
    }

    Ok(template.replace("{version}", version))
}

fn create_temp_dir(web_dir: &Path, version: &str) -> Result<PathBuf, EdgeError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            EdgeError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read system time: {err}"),
            )
        })?
        .as_nanos();

    for attempt in 0_u32..100 {
        let candidate = web_dir.join(format!(".web-{version}-{nanos}-{attempt}"));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                debug!(path = ?candidate, "temp dir created");
                return Ok(candidate);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(EdgeError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to create temp dir: {err}"),
                ));
            }
        }
    }

    Err(EdgeError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to allocate unique temp dir",
    ))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), EdgeError> {
    fs::create_dir_all(dst).map_err(io_500)?;
    for entry in fs::read_dir(src).map_err(io_500)? {
        let entry = entry.map_err(io_500)?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let file_type = entry.file_type().map_err(io_500)?;

        if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if file_type.is_file() {
            trace!(from = ?from, to = ?to, "copying file");
            fs::copy(&from, &to).map_err(io_500)?;
        }
    }

    Ok(())
}

fn enforce_cache_limit(cfg: &Config) {
    if cfg.max_cache_bytes == 0 {
        return;
    }

    let web_dir = cfg.web_cache_dir();
    let mut total_bytes = match dir_size_recursive(&web_dir) {
        Ok(total) => total,
        Err(err) => {
            warn!(path = ?web_dir, error = %err, "failed to compute cache size");
            return;
        }
    };
    debug!(
        total_bytes = total_bytes,
        max_bytes = cfg.max_cache_bytes,
        "cache limit check"
    );

    if total_bytes <= cfg.max_cache_bytes {
        return;
    }

    let mut candidates: Vec<(SystemTime, PathBuf, u64)> = Vec::new();
    let read_dir = match fs::read_dir(&web_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warn!(error = %err, "failed reading cache directory entry");
                continue;
            }
        };

        let version_dir = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                warn!(path = ?version_dir, error = %err, "failed reading file type");
                continue;
            }
        };

        if !file_type.is_dir() {
            continue;
        }

        let ready = version_dir.join(".ready");
        let ready_meta = match fs::metadata(&ready) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        let mtime = ready_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let size = match dir_size_recursive(&version_dir) {
            Ok(size) => size,
            Err(err) => {
                warn!(path = ?version_dir, error = %err, "failed to size version directory");
                0
            }
        };
        candidates.push((mtime, version_dir, size));
    }

    candidates.sort_by_key(|(mtime, _, _)| *mtime);

    for (_, version_dir, size) in candidates {
        let Some(name) = version_dir.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name == cfg.live_version {
            continue;
        }
        if total_bytes <= cfg.max_cache_bytes {
            break;
        }

        info!(version = %name, bytes_freed = size, path = ?version_dir, "cache eviction");
        match fs::remove_dir_all(&version_dir) {
            Ok(()) => {
                total_bytes = total_bytes.saturating_sub(size);
            }
            Err(err) => {
                warn!(path = ?version_dir, error = %err, "failed to evict cached web version");
            }
        }
    }
}

fn dir_size_recursive(root: &Path) -> io::Result<u64> {
    let mut total = 0_u64;
    if !root.exists() {
        trace!(path = ?root, total_bytes = 0_u64, "directory size walk progress");
        return Ok(0);
    }

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        } else if file_type.is_dir() {
            total = total.saturating_add(dir_size_recursive(&entry_path)?);
        }
        trace!(path = ?entry_path, running_total = total, "directory size walk progress");
    }

    Ok(total)
}

fn matrix_server_response(cfg: &Config) -> Response<Body> {
    let body = serde_json::json!({
        "m.server": cfg.matrix_server_name,
    });
    let bytes = serde_json::to_vec(&body).expect("well-known server response should serialize");

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("content-length", bytes.len().to_string())
        .body(Body::from(bytes))
        .expect("matrix server response should build")
}

fn matrix_client_response(cfg: &Config) -> Response<Body> {
    let body = serde_json::json!({
        "m.homeserver": {
            "base_url": cfg.matrix_client_base_url,
        },
    });
    let bytes = serde_json::to_vec(&body).expect("well-known client response should serialize");

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("content-length", bytes.len().to_string())
        .body(Body::from(bytes))
        .expect("matrix client response should build")
}

fn apex_redirect(path: &str, query: Option<&str>) -> Response<Body> {
    let mut from = path.to_string();
    if let Some(query) = query {
        from.push('?');
        from.push_str(query);
    }

    let mut location = format!("https://www.fastboop.win{path}");
    if let Some(query) = query {
        location.push('?');
        location.push_str(query);
    }
    debug!(from = %from, to = %location, "issuing redirect");

    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header("location", location)
        .header("cache-control", "no-store")
        .header("content-length", "0")
        .body(Body::empty())
        .expect("apex redirect response should build")
}

fn root_redirect(cfg: &Config, query: Option<&str>) -> Response<Body> {
    let mut from = "/".to_string();
    if let Some(query) = query {
        from.push('?');
        from.push_str(query);
    }

    let mut location = format!("/{}/", cfg.live_version);
    if let Some(query) = query {
        location.push('?');
        location.push_str(query);
    }
    debug!(from = %from, to = %location, "issuing redirect");

    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header("location", location)
        .header("cache-control", "no-store")
        .header("content-length", "0")
        .body(Body::empty())
        .expect("root redirect response should build")
}

fn device_permissions_redirect(from_path: &str) -> Response<Body> {
    debug!(
        from = %from_path,
        to = "https://docs.fastboop.win/user/device-permissions/",
        "issuing redirect"
    );
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(
            "location",
            "https://docs.fastboop.win/user/device-permissions/",
        )
        .header("cache-control", "no-store")
        .header("content-length", "0")
        .body(Body::empty())
        .expect("device permissions redirect response should build")
}

fn text_response(status: StatusCode, text: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .header("content-length", text.len().to_string())
        .body(Body::from(text.to_owned()))
        .expect("text response should build")
}

fn is_redirect_status(status: StatusCode) -> bool {
    status == StatusCode::MOVED_PERMANENTLY
        || status == StatusCode::FOUND
        || status == StatusCode::TEMPORARY_REDIRECT
        || status == StatusCode::PERMANENT_REDIRECT
}

fn percent_decode_path(path: &str) -> Result<String, ()> {
    let mut out = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_value(bytes[i + 1]);
            let lo = hex_value(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }

        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(out).map_err(|_| ())
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn safe_join_under(root: &Path, rel: &Path) -> Result<PathBuf, ()> {
    let mut out = PathBuf::from(root);
    for component in rel.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return Err(()),
        }
    }
    Ok(out)
}

fn is_safe_relative_path(path: &str) -> bool {
    Path::new(path)
        .components()
        .all(|component| matches!(component, Component::CurDir | Component::Normal(_)))
}

fn io_500(err: io::Error) -> EdgeError {
    EdgeError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("filesystem operation failed: {err}"),
    )
}
