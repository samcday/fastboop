#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import shutil
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


CHUNK_SIZE = 1024 * 1024
PER_PAGE = 100
RUN_ID_RE = re.compile(r"^[0-9]+$")
SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
PATH_RE = re.compile(r"^/gha/([^/]+)/([^/]+)/([0-9]+)/?$")
USER_AGENT = "fastboop-gha-proxy/0.1"


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def parse_allowlist(raw: str) -> set[str]:
    allowlist: set[str] = set()
    for item in raw.split(","):
        entry = item.strip()
        if not entry:
            continue
        if "/" not in entry:
            raise RuntimeError(f"invalid ALLOWLIST entry '{entry}'")
        owner, repo = entry.split("/", 1)
        if not SLUG_RE.fullmatch(owner) or not SLUG_RE.fullmatch(repo):
            raise RuntimeError(f"invalid ALLOWLIST entry '{entry}'")
        allowlist.add(f"{owner.lower()}/{repo.lower()}")
    return allowlist


PORT = env_int("PORT", 8080)
CACHE_DIR = Path(os.environ.get("CACHE_DIR", "/cache"))
CACHE_MAX_BYTES = env_int("CACHE_MAX_BYTES", 0)
REQUEST_TIMEOUT_SECONDS = env_int("REQUEST_TIMEOUT_SECONDS", 300)
ALLOWLIST = parse_allowlist(os.environ.get("ALLOWLIST", ""))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()


class ProxyError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class RangeNotSatisfiable(ProxyError):
    def __init__(self, size: int, message: str = "range not satisfiable"):
        super().__init__(416, message)
        self.size = size


@dataclass(frozen=True)
class ArtifactRef:
    owner: str
    repo: str
    run_id: str


@dataclass(frozen=True)
class CacheEntry:
    blob_path: Path
    meta_path: Path
    size: int
    content_type: str
    etag: str


_CACHE_LOCKS: dict[str, threading.Lock] = {}
_CACHE_LOCKS_GUARD = threading.Lock()


def cache_key(ref: ArtifactRef) -> str:
    key = f"{ref.owner}/{ref.repo}:{ref.run_id}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()


def cache_paths(key: str) -> tuple[Path, Path]:
    blob_path = CACHE_DIR / f"{key}.blob"
    meta_path = CACHE_DIR / f"{key}.json"
    return blob_path, meta_path


def normalized_repo(owner: str, repo: str) -> str:
    return f"{owner.lower()}/{repo.lower()}"


def github_headers() -> dict[str, str]:
    if not GITHUB_TOKEN:
        raise ProxyError(500, "GITHUB_TOKEN is not configured")
    return {
        "accept": "application/vnd.github+json",
        "authorization": f"Bearer {GITHUB_TOKEN}",
        "user-agent": USER_AGENT,
        "x-github-api-version": "2022-11-28",
    }


def read_http_error_detail(err: urllib.error.HTTPError) -> str:
    try:
        body = err.read().decode("utf-8", errors="replace")
        payload = json.loads(body)
    except Exception:
        return str(err.code)
    message = payload.get("message")
    if isinstance(message, str) and message:
        return f"{err.code} {message}"
    return str(err.code)


def github_json(url: str) -> dict:
    req = urllib.request.Request(url, method="GET", headers=github_headers())
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = response.read().decode("utf-8")
            parsed = json.loads(payload)
    except urllib.error.HTTPError as err:
        status = 502
        if err.code == 404:
            status = 404
        detail = read_http_error_detail(err)
        raise ProxyError(status, f"GitHub API request failed: {detail}") from err
    except urllib.error.URLError as err:
        raise ProxyError(502, f"GitHub API request failed: {err}") from err
    except ValueError as err:
        raise ProxyError(502, "GitHub API returned invalid JSON") from err

    if not isinstance(parsed, dict):
        raise ProxyError(502, "GitHub API returned unexpected payload")
    return parsed


def download_archive(url: str, zip_path: Path) -> None:
    req = urllib.request.Request(url, method="GET", headers=github_headers())
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            with zip_path.open("wb") as output:
                shutil.copyfileobj(response, output, CHUNK_SIZE)
    except urllib.error.HTTPError as err:
        detail = read_http_error_detail(err)
        status = 502
        if err.code == 404:
            status = 404
        raise ProxyError(status, f"failed to download artifact archive: {detail}") from err
    except urllib.error.URLError as err:
        raise ProxyError(502, f"failed to download artifact archive: {err}") from err


def resolve_single_artifact(ref: ArtifactRef) -> dict:
    page = 1
    artifacts: list[dict] = []

    while True:
        url = (
            f"https://api.github.com/repos/{ref.owner}/{ref.repo}"
            f"/actions/runs/{ref.run_id}/artifacts?per_page={PER_PAGE}&page={page}"
        )
        payload = github_json(url)
        page_items = payload.get("artifacts")
        if not isinstance(page_items, list):
            raise ProxyError(502, "GitHub API response missing artifacts")

        for artifact in page_items:
            if not isinstance(artifact, dict):
                continue
            if artifact.get("expired"):
                continue
            artifacts.append(artifact)

        try:
            total_count = int(payload.get("total_count", 0))
        except (TypeError, ValueError):
            total_count = 0

        if not page_items or page * PER_PAGE >= total_count:
            break
        page += 1

    if not artifacts:
        raise ProxyError(
            404,
            f"no active artifacts found for {ref.owner}/{ref.repo} run {ref.run_id}",
        )
    if len(artifacts) != 1:
        raise ProxyError(
            409,
            (
                f"run {ref.owner}/{ref.repo}#{ref.run_id} has {len(artifacts)} active artifacts; "
                "expected exactly 1"
            ),
        )

    artifact = artifacts[0]
    archive_url = artifact.get("archive_download_url")
    if not isinstance(archive_url, str) or not archive_url:
        raise ProxyError(502, "artifact is missing archive_download_url")

    return artifact


def extract_single_file(zip_path: Path, blob_tmp_path: Path) -> tuple[int, str, str]:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            entries = [entry for entry in archive.infolist() if not entry.is_dir()]
            if len(entries) != 1:
                raise ProxyError(
                    409,
                    f"artifact archive contains {len(entries)} files; expected exactly 1",
                )

            entry = entries[0]
            digest = hashlib.sha256()

            with archive.open(entry, "r") as source, blob_tmp_path.open("wb") as output:
                while True:
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
                    output.write(chunk)

            size = blob_tmp_path.stat().st_size
            content_type, _ = mimetypes.guess_type(entry.filename)
            if not content_type:
                content_type = "application/octet-stream"
            etag = f'"sha256-{digest.hexdigest()}"'
            return size, content_type, etag
    except zipfile.BadZipFile as err:
        raise ProxyError(502, "artifact archive is not a valid zip file") from err


def load_cache_entry(blob_path: Path, meta_path: Path) -> CacheEntry | None:
    if not blob_path.exists() or not meta_path.exists():
        return None
    try:
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        size = blob_path.stat().st_size
        content_type = str(metadata["content_type"])
        etag = str(metadata["etag"])
    except Exception:
        return None
    return CacheEntry(
        blob_path=blob_path,
        meta_path=meta_path,
        size=size,
        content_type=content_type,
        etag=etag,
    )


def cache_lock_for(key: str) -> threading.Lock:
    with _CACHE_LOCKS_GUARD:
        lock = _CACHE_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _CACHE_LOCKS[key] = lock
    return lock


def enforce_cache_limit() -> None:
    if CACHE_MAX_BYTES <= 0:
        return

    entries: list[tuple[float, int, Path, Path]] = []
    total_bytes = 0
    for blob_path in CACHE_DIR.glob("*.blob"):
        meta_path = blob_path.with_suffix(".json")
        if not meta_path.exists():
            continue
        try:
            stat = blob_path.stat()
        except OSError:
            continue
        total_bytes += stat.st_size
        entries.append((stat.st_mtime, stat.st_size, blob_path, meta_path))

    entries.sort(key=lambda item: item[0])

    while total_bytes > CACHE_MAX_BYTES and len(entries) > 1:
        _, size, blob_path, meta_path = entries.pop(0)
        try:
            blob_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
            total_bytes -= size
        except OSError:
            continue


def materialize_cache_entry(ref: ArtifactRef) -> CacheEntry:
    key = cache_key(ref)
    blob_path, meta_path = cache_paths(key)

    existing = load_cache_entry(blob_path, meta_path)
    if existing is not None:
        return existing

    lock = cache_lock_for(key)
    with lock:
        existing = load_cache_entry(blob_path, meta_path)
        if existing is not None:
            return existing

        artifact = resolve_single_artifact(ref)
        archive_url = str(artifact["archive_download_url"])

        with tempfile.TemporaryDirectory(prefix=f".gha-{key}-", dir=CACHE_DIR) as tmpdir:
            tmpdir_path = Path(tmpdir)
            zip_path = tmpdir_path / "artifact.zip"
            blob_tmp_path = tmpdir_path / "blob.tmp"
            meta_tmp_path = tmpdir_path / "meta.tmp"

            download_archive(archive_url, zip_path)
            size, content_type, etag = extract_single_file(zip_path, blob_tmp_path)

            metadata = {
                "content_type": content_type,
                "etag": etag,
                "size": size,
            }
            meta_tmp_path.write_text(json.dumps(metadata, separators=(",", ":")), encoding="utf-8")

            blob_tmp_path.replace(blob_path)
            meta_tmp_path.replace(meta_path)

        enforce_cache_limit()

    created = load_cache_entry(blob_path, meta_path)
    if created is None:
        raise ProxyError(500, "failed to load cached artifact after extraction")
    return created


def parse_artifact_ref(path: str) -> ArtifactRef | None:
    match = PATH_RE.fullmatch(path)
    if match is None:
        return None

    owner = urllib.parse.unquote(match.group(1))
    repo = urllib.parse.unquote(match.group(2))
    run_id = match.group(3)

    if not SLUG_RE.fullmatch(owner) or not SLUG_RE.fullmatch(repo):
        return None
    if not RUN_ID_RE.fullmatch(run_id):
        return None

    return ArtifactRef(owner=owner, repo=repo, run_id=run_id)


def parse_range_header(range_header: str | None, size: int) -> tuple[int, int] | None:
    if range_header is None:
        return None

    value = range_header.strip()
    if "," in value:
        raise RangeNotSatisfiable(size, "multiple ranges are not supported")

    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
    if match is None:
        raise RangeNotSatisfiable(size, "invalid range header")

    start_text, end_text = match.groups()
    if not start_text and not end_text:
        raise RangeNotSatisfiable(size)

    if size <= 0:
        raise RangeNotSatisfiable(size)

    if not start_text:
        suffix_length = int(end_text)
        if suffix_length <= 0:
            raise RangeNotSatisfiable(size)
        if suffix_length >= size:
            return 0, size - 1
        return size - suffix_length, size - 1

    start = int(start_text)
    if start >= size:
        raise RangeNotSatisfiable(size)

    if end_text:
        end = int(end_text)
        if end < start:
            raise RangeNotSatisfiable(size)
        if end >= size:
            end = size - 1
    else:
        end = size - 1

    return start, end


class GhaProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gha-proxy/0.1"

    def do_OPTIONS(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/gha" or path.startswith("/gha/"):
            self.send_response(204)
            self.write_cors_headers()
            self.send_header("access-control-max-age", "86400")
            self.send_header("content-length", "0")
            self.end_headers()
            return
        self.send_error_response(404, "not found", head_only=True)

    def do_HEAD(self) -> None:
        self.handle_request(head_only=True)

    def do_GET(self) -> None:
        self.handle_request(head_only=False)

    def handle_request(self, head_only: bool) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":
            self.send_response(200)
            self.send_header("cache-control", "no-store")
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("content-length", "2")
            self.end_headers()
            if not head_only:
                self.wfile.write(b"ok")
            return

        if self.command not in ("GET", "HEAD"):
            self.send_error_response(405, "method not allowed", head_only=head_only)
            return

        ref = parse_artifact_ref(path)
        if ref is None:
            self.send_error_response(404, "not found", head_only=head_only)
            return

        if normalized_repo(ref.owner, ref.repo) not in ALLOWLIST:
            self.send_error_response(403, "repository is not in the allowlist", head_only=head_only)
            return

        try:
            entry = materialize_cache_entry(ref)
            selected_range = parse_range_header(self.headers.get("Range"), entry.size)
        except ProxyError as err:
            range_size = err.size if isinstance(err, RangeNotSatisfiable) else None
            self.send_error_response(
                err.status,
                err.message,
                head_only=head_only,
                range_size=range_size,
            )
            return

        if selected_range is None:
            status = 200
            start = 0
            end = entry.size - 1 if entry.size > 0 else -1
        else:
            status = 206
            start, end = selected_range

        length = 0 if end < start else end - start + 1

        self.send_response(status)
        self.write_cors_headers()
        self.send_header("accept-ranges", "bytes")
        self.send_header("cache-control", "public, max-age=31536000, immutable")
        self.send_header("content-length", str(length))
        self.send_header("content-type", entry.content_type)
        self.send_header("etag", entry.etag)
        if status == 206:
            self.send_header("content-range", f"bytes {start}-{end}/{entry.size}")
        self.end_headers()

        if head_only or length <= 0:
            return

        try:
            with entry.blob_path.open("rb") as source:
                source.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = source.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except BrokenPipeError:
            return

    def write_cors_headers(self) -> None:
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-methods", "GET, HEAD, OPTIONS")
        self.send_header("access-control-allow-headers", "Range, Priority, Content-Type")
        self.send_header(
            "access-control-expose-headers",
            "Accept-Ranges, Content-Length, Content-Range, ETag",
        )

    def send_error_response(
        self,
        status: int,
        message: str,
        *,
        head_only: bool,
        range_size: int | None = None,
    ) -> None:
        body = f"{message}\n".encode("utf-8")
        self.send_response(status)
        self.write_cors_headers()
        if range_size is not None:
            self.send_header("content-range", f"bytes */{range_size}")
        self.send_header("cache-control", "no-store")
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)


def main() -> None:
    if not ALLOWLIST:
        raise RuntimeError("ALLOWLIST must not be empty")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer(("0.0.0.0", PORT), GhaProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
