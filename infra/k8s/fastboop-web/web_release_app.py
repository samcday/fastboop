#!/usr/bin/env python3

from __future__ import annotations

import mimetypes
import os
import re
import shutil
import tarfile
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


CHUNK_SIZE = 1024 * 1024
VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")
VERSION_BASE_RE = re.compile(r"^/(v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?)$")
VERSION_PATH_RE = re.compile(r"^/(v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?)(/.*)$")
USER_AGENT = "fastboop-web-release-app/0.1"


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


PORT = env_int("PORT", 8080)
CACHE_DIR = Path(os.environ.get("CACHE_DIR", "/cache")).resolve()
GITHUB_OWNER = os.environ.get("GITHUB_OWNER", "samcday").strip()
GITHUB_REPO = os.environ.get("GITHUB_REPO", "fastboop").strip()
ASSET_NAME_TEMPLATE = os.environ.get(
    "ASSET_NAME_TEMPLATE", "fastboop-web-{version}.tar.gz"
).strip()
REQUEST_TIMEOUT_SECONDS = env_int("REQUEST_TIMEOUT_SECONDS", 300)
LIVE_VERSION = os.environ.get("LIVE_VERSION", "").strip()

if not LIVE_VERSION or VERSION_RE.fullmatch(LIVE_VERSION) is None:
    raise RuntimeError("LIVE_VERSION must match vX.Y.Z or vX.Y.Z-rc.N")


class WebReleaseError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class VersionRequest:
    version: str
    relative_path: str


_VERSION_LOCKS: dict[str, threading.Lock] = {}
_VERSION_LOCKS_GUARD = threading.Lock()


def version_lock(version: str) -> threading.Lock:
    with _VERSION_LOCKS_GUARD:
        lock = _VERSION_LOCKS.get(version)
        if lock is None:
            lock = threading.Lock()
            _VERSION_LOCKS[version] = lock
    return lock


def version_dir(version: str) -> Path:
    return CACHE_DIR / version


def version_ready_file(version: str) -> Path:
    return version_dir(version) / ".ready"


def assert_version(version: str) -> None:
    if VERSION_RE.fullmatch(version) is None:
        raise WebReleaseError(404, "not found")


def release_asset_name(version: str) -> str:
    try:
        name = ASSET_NAME_TEMPLATE.format(version=version)
    except KeyError as exc:
        raise RuntimeError(
            "ASSET_NAME_TEMPLATE may only use {version} placeholders"
        ) from exc
    return name


def release_asset_url(version: str) -> str:
    owner = urllib.parse.quote(GITHUB_OWNER, safe="")
    repo = urllib.parse.quote(GITHUB_REPO, safe="")
    tag = urllib.parse.quote(version, safe="")
    asset = urllib.parse.quote(release_asset_name(version), safe="")
    return f"https://github.com/{owner}/{repo}/releases/download/{tag}/{asset}"


def download_release_tarball(version: str, destination: Path) -> None:
    request = urllib.request.Request(
        release_asset_url(version),
        method="GET",
        headers={"user-agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output, CHUNK_SIZE)
    except urllib.error.HTTPError as err:
        if err.code == 404:
            raise WebReleaseError(
                404,
                (
                    f"release asset '{release_asset_name(version)}' for {version} "
                    "was not found"
                ),
            ) from err
        raise WebReleaseError(
            502, f"failed to download release asset for {version}: {err.code}"
        ) from err
    except urllib.error.URLError as err:
        raise WebReleaseError(
            502, f"failed to download release asset for {version}: {err}"
        ) from err


def assert_path_within(parent: Path, candidate: Path) -> None:
    parent_resolved = parent.resolve()
    candidate_resolved = candidate.resolve()
    if candidate_resolved == parent_resolved:
        return
    if parent_resolved in candidate_resolved.parents:
        return
    raise WebReleaseError(502, "release archive contains an invalid path")


def extract_release_tarball(tarball: Path, extract_root: Path) -> None:
    try:
        with tarfile.open(tarball, mode="r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                if member.issym() or member.islnk():
                    raise WebReleaseError(
                        502,
                        "release archive may not contain symbolic links",
                    )
                assert_path_within(extract_root, extract_root / member.name)
            archive.extractall(path=extract_root, members=members, filter="data")
    except WebReleaseError:
        raise
    except tarfile.TarError as err:
        raise WebReleaseError(502, f"release archive is invalid: {err}") from err


def resolve_extracted_site_root(extract_root: Path) -> Path:
    if (extract_root / "index.html").is_file():
        return extract_root

    candidates = [entry for entry in extract_root.iterdir() if entry.is_dir()]
    if len(candidates) == 1 and (candidates[0] / "index.html").is_file():
        return candidates[0]

    raise WebReleaseError(502, "release archive does not contain index.html")


def materialize_version(version: str) -> Path:
    assert_version(version)

    ready = version_ready_file(version)
    if ready.is_file():
        return version_dir(version)

    lock = version_lock(version)
    with lock:
        ready = version_ready_file(version)
        if ready.is_file():
            return version_dir(version)

        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix=f".web-{version}-", dir=CACHE_DIR) as tmpdir:
            tmpdir_path = Path(tmpdir)
            tarball_path = tmpdir_path / "release.tar.gz"
            extract_root = tmpdir_path / "extract"
            staged_root = tmpdir_path / "site"
            extract_root.mkdir()

            download_release_tarball(version, tarball_path)
            extract_release_tarball(tarball_path, extract_root)
            site_root = resolve_extracted_site_root(extract_root)
            shutil.copytree(site_root, staged_root)
            (staged_root / ".ready").write_text("ok\n", encoding="utf-8")

            target_dir = version_dir(version)
            if target_dir.exists():
                shutil.rmtree(target_dir)
            staged_root.replace(target_dir)

    return version_dir(version)


def parse_request(path: str) -> VersionRequest:
    match = VERSION_PATH_RE.fullmatch(path)
    if match is not None:
        version = match.group(1)
        relative_path = match.group(2)
        return VersionRequest(version=version, relative_path=relative_path)

    return VersionRequest(version=LIVE_VERSION, relative_path=path)


def safe_candidate_path(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    assert_path_within(root, candidate)
    return candidate


def resolve_file_path(site_root: Path, request_path: str) -> Path:
    decoded = urllib.parse.unquote(request_path)
    stripped = decoded.lstrip("/")

    if stripped == "":
        stripped = "index.html"
    elif stripped.endswith("/"):
        stripped = f"{stripped}index.html"

    candidate = safe_candidate_path(site_root, stripped)
    if candidate.is_file():
        return candidate

    if candidate.is_dir():
        nested_index = candidate / "index.html"
        if nested_index.is_file():
            return nested_index

    basename = Path(stripped).name
    if "." in basename:
        raise WebReleaseError(404, "not found")

    fallback = site_root / "index.html"
    if fallback.is_file():
        return fallback

    raise WebReleaseError(404, "not found")


def content_type_for(path: Path) -> str:
    if path.suffix.lower() == ".wasm":
        return "application/wasm"
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed:
        return guessed
    return "application/octet-stream"


def cache_control_for(path: Path) -> str:
    if path.suffix.lower() == ".html":
        return "no-cache"
    return "public, max-age=31536000, immutable"


class WebReleaseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fastboop-web-release-app/0.1"

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("allow", "GET, HEAD, OPTIONS")
        self.send_header("content-length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self.handle_request(head_only=False)

    def do_HEAD(self) -> None:
        self.handle_request(head_only=True)

    def handle_request(self, head_only: bool) -> None:
        path = urllib.parse.urlsplit(self.path).path

        if path == "/healthz":
            self.send_text_response(200, "ok\n", head_only=head_only)
            return

        if path == "/__fastboop/live":
            self.send_text_response(200, f"{LIVE_VERSION}\n", head_only=head_only)
            return

        base_match = VERSION_BASE_RE.fullmatch(path)
        if base_match is not None:
            version = base_match.group(1)
            self.send_redirect(f"/{version}/")
            return

        request = parse_request(path)
        try:
            site_root = materialize_version(request.version)
            file_path = resolve_file_path(site_root, request.relative_path)
        except WebReleaseError as err:
            status = err.status
            if request.version == LIVE_VERSION and err.status == 404:
                status = 503
            self.send_error_response(status, err.message, head_only=head_only)
            return

        self.send_file_response(file_path, head_only=head_only)

    def send_file_response(self, path: Path, *, head_only: bool) -> None:
        try:
            size = path.stat().st_size
        except OSError:
            self.send_error_response(404, "not found", head_only=head_only)
            return

        self.send_response(200)
        self.send_header("cache-control", cache_control_for(path))
        self.send_header("content-type", content_type_for(path))
        self.send_header("content-length", str(size))
        self.end_headers()

        if head_only:
            return

        try:
            with path.open("rb") as source:
                shutil.copyfileobj(source, self.wfile, CHUNK_SIZE)
        except BrokenPipeError:
            return

    def send_redirect(self, location: str) -> None:
        self.send_response(308)
        self.send_header("location", location)
        self.send_header("cache-control", "public, max-age=300")
        self.send_header("content-length", "0")
        self.end_headers()

    def send_text_response(self, status: int, body: str, *, head_only: bool) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("cache-control", "no-store")
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        if not head_only:
            self.wfile.write(encoded)

    def send_error_response(self, status: int, message: str, *, head_only: bool) -> None:
        body = f"{message}\n"
        self.send_text_response(status, body, head_only=head_only)


def main() -> None:
    if not GITHUB_OWNER or not GITHUB_REPO:
        raise RuntimeError("GITHUB_OWNER and GITHUB_REPO must be configured")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), WebReleaseHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
