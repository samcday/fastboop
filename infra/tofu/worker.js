const LATEST_KEY = "latest.txt";
const REDIRECT_STATUS = 302;
const GITHUB_API_BASE = "https://api.github.com";
const GHA_ARTIFACT_ROUTES = [
  {
    prefix: "/pocketblue/gha/",
    owner: "pocketblue",
    repo: "pocketblue",
  },
  {
    prefix: "/live-pocket-fedora/gha/",
    owner: "samcday",
    repo: "live-pocket-fedora",
  },
];
const GHA_PROXY_BASE_URL =
  typeof FASTBOOP_GHA_PROXY_BASE_URL === "string" && FASTBOOP_GHA_PROXY_BASE_URL.trim()
    ? FASTBOOP_GHA_PROXY_BASE_URL.trim().replace(/\/+$/, "")
    : "https://fastboop.win";
const ARTIFACT_METADATA_TTL_MS = 5 * 60 * 1000;
const SIGNED_URL_REFRESH_LEEWAY_MS = 30 * 1000;
const FALLBACK_SIGNED_URL_TTL_MS = 5 * 60 * 1000;

const artifactMetadataCache = new Map();
const signedArtifactUrlCache = new Map();

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const githubArtifact = parseGithubArtifactPath(path);

  // Handle CORS preflight requests for direct artifacts.
  if (
    request.method === "OPTIONS" &&
    (isR2DirectArtifactPath(path) || githubArtifact)
  ) {
    return handleCorsPreflightArtifact();
  }

  if (path === "/" || path === "/latest" || path === "/latest/") {
    return redirectToLatest();
  }

  if (githubArtifact) {
    return handleGithubArtifact(request, githubArtifact);
  }

  // Handle direct R2 artifact paths with range request support.
  if (isR2DirectArtifactPath(path)) {
    return handleDirectArtifact(request, path);
  }

  if (!path.startsWith("/commit/")) {
    return redirectToLatest();
  }

  const parts = path.split("/");
  const sha = parts[2];
  if (!sha) {
    return redirectToLatest();
  }

  if (path === `/commit/${sha}`) {
    return redirect(`/commit/${sha}/`);
  }

  let key = path.slice(1);
  if (key.endsWith("/")) {
    key += "index.html";
  }

  let object = await R2_BUCKET.get(key);
  if (!object) {
    const fallback = `commit/${sha}/index.html`;
    object = await R2_BUCKET.get(fallback);
    if (!object) {
      return new Response("Not found", { status: 404 });
    }
    key = fallback;
  }

  const headers = new Headers();
  const contentType = contentTypeFor(key);
  if (contentType) {
    headers.set("content-type", contentType);
  }
  headers.set("etag", object.etag);
  headers.set("cache-control", cacheControlFor(key));

  return new Response(object.body, { headers });
}

async function handleDirectArtifact(request, path) {
  // Remove leading slash for R2 key
  const key = path.slice(1);

  // Forward Range header for partial content requests
  const rangeHeader = request.headers.get("Range");

  try {
    // Get object from R2 with range support
    const object = await R2_BUCKET.get(key, {
      range: rangeHeader ? parseRangeHeader(rangeHeader) : undefined,
    });

    if (!object) {
      return new Response("Artifact not found", { status: 404 });
    }

    const headers = new Headers();

    // Set a content type for known artifact formats.
    headers.set("content-type", contentTypeFor(key) || "application/octet-stream");
    headers.set("etag", object.etag);

    // Set CORS headers for cross-origin requests.
    headers.set("access-control-allow-origin", "*");
    headers.set("access-control-allow-methods", "GET, HEAD, OPTIONS");
    headers.set("access-control-allow-headers", "Range, Priority, Content-Type");
    headers.set("access-control-expose-headers", "Content-Range, Content-Length, Accept-Ranges");

    // Enable range requests
    headers.set("accept-ranges", "bytes");

    // Cache immutably since direct artifact paths are content-addressed.
    headers.set("cache-control", "public, max-age=31536000, immutable");

    // Handle range requests properly
    if (rangeHeader && object.range) {
      headers.set("content-range", `bytes ${object.range.offset}-${object.range.offset + object.range.length - 1}/${object.size}`);
      return new Response(object.body, {
        status: 206, // Partial Content
        headers
      });
    } else {
      headers.set("content-length", object.size.toString());
      return new Response(object.body, { headers });
    }

  } catch (error) {
    console.error("Error fetching direct artifact:", error);
    return new Response("Failed to fetch artifact", { status: 500 });
  }
}

async function handleGithubArtifact(request, artifactRef) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    const headers = artifactCorsHeaders();
    headers.set("allow", "GET, HEAD, OPTIONS");
    return new Response("Method not allowed", { status: 405, headers });
  }

  try {
    const fastboopProxyResponse = await tryFastboopGhaProxy(request, artifactRef);
    if (fastboopProxyResponse) {
      return fastboopProxyResponse;
    }

    let signedUrl = await resolveSignedArtifactUrl(artifactRef);
    let upstream = await fetchSignedArtifact(request, signedUrl);

    // Signed URLs can expire while cached in-memory; refresh once and retry.
    if (upstream.status === 401 || upstream.status === 403) {
      signedUrl = await resolveSignedArtifactUrl(artifactRef, true);
      upstream = await fetchSignedArtifact(request, signedUrl);
    }

    return buildGithubArtifactProxyResponse(upstream);
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 502;
    const headers = artifactCorsHeaders();
    headers.set("cache-control", "no-store");
    console.error("Error proxying GitHub artifact:", error);
    return new Response(error?.message || "Failed to fetch artifact", {
      status,
      headers,
    });
  }
}

async function tryFastboopGhaProxy(request, artifactRef) {
  const targetUrl =
    `${GHA_PROXY_BASE_URL}/gha/` +
    `${encodeURIComponent(artifactRef.owner)}/` +
    `${encodeURIComponent(artifactRef.repo)}/` +
    `${artifactRef.runId}`;

  const headers = new Headers();
  const rangeHeader = request.headers.get("Range");
  const priorityHeader = request.headers.get("Priority");

  if (rangeHeader) {
    headers.set("Range", rangeHeader);
  }
  if (priorityHeader) {
    headers.set("Priority", priorityHeader);
  }

  try {
    const upstream = await fetch(targetUrl, {
      method: request.method,
      headers,
    });

    if (upstream.status === 409 || upstream.status >= 500) {
      return null;
    }

    return buildGithubArtifactProxyResponse(upstream);
  } catch {
    return null;
  }
}

async function resolveSignedArtifactUrl(artifactRef, forceRefresh = false) {
  const now = Date.now();
  const cacheKey = artifactCacheKey(artifactRef);

  if (!forceRefresh) {
    const cachedSigned = signedArtifactUrlCache.get(cacheKey);
    if (
      cachedSigned &&
      now + SIGNED_URL_REFRESH_LEEWAY_MS < cachedSigned.expiresAtMs
    ) {
      return cachedSigned.url;
    }
  }

  const artifact = await resolveArtifactMetadata(artifactRef, forceRefresh);
  const signedUrl = await fetchSignedArchiveUrl(artifact.archiveDownloadUrl);
  const expiresAtMs = parseSignedUrlExpiryMs(signedUrl) || now + FALLBACK_SIGNED_URL_TTL_MS;

  signedArtifactUrlCache.set(cacheKey, {
    url: signedUrl,
    expiresAtMs,
  });

  return signedUrl;
}

async function resolveArtifactMetadata(artifactRef, forceRefresh = false) {
  const now = Date.now();
  const cacheKey = artifactCacheKey(artifactRef);

  if (!forceRefresh) {
    const cachedMeta = artifactMetadataCache.get(cacheKey);
    if (cachedMeta && now < cachedMeta.expiresAtMs) {
      return cachedMeta.value;
    }
  }

  const perPage = 100;
  let page = 1;

  while (true) {
    const listUrl =
      `${GITHUB_API_BASE}/repos/${artifactRef.owner}/${artifactRef.repo}` +
      `/actions/runs/${artifactRef.runId}/artifacts?per_page=${perPage}&page=${page}`;
    const payload = await fetchGithubJson(listUrl);
    const artifacts = Array.isArray(payload?.artifacts) ? payload.artifacts : [];

    for (const artifact of artifacts) {
      if (artifact?.name !== artifactRef.artifactName) {
        continue;
      }
      if (artifact?.expired) {
        throw httpError(
          404,
          `Artifact '${artifactRef.artifactName}' from ${artifactRef.owner}/${artifactRef.repo} run ${artifactRef.runId} has expired`
        );
      }
      if (!artifact?.archive_download_url) {
        throw httpError(
          502,
          `Artifact '${artifactRef.artifactName}' from ${artifactRef.owner}/${artifactRef.repo} is missing archive download URL`
        );
      }

      const value = {
        id: artifact.id,
        archiveDownloadUrl: artifact.archive_download_url,
      };

      artifactMetadataCache.set(cacheKey, {
        value,
        expiresAtMs: now + ARTIFACT_METADATA_TTL_MS,
      });

      return value;
    }

    const totalCount = Number(payload?.total_count || 0);
    if (artifacts.length === 0 || page * perPage >= totalCount) {
      break;
    }
    page += 1;
  }

  throw httpError(
    404,
    `Artifact '${artifactRef.artifactName}' not found in ${artifactRef.owner}/${artifactRef.repo} run ${artifactRef.runId}`
  );
}

async function fetchSignedArchiveUrl(archiveDownloadUrl) {
  const response = await fetch(archiveDownloadUrl, {
    method: "GET",
    redirect: "manual",
    headers: githubApiHeaders(),
  });

  if (response.status < 300 || response.status >= 400) {
    throw await githubResponseError(
      response,
      "Failed to resolve signed artifact download URL"
    );
  }

  const signedUrl = response.headers.get("location");
  if (!signedUrl) {
    throw httpError(502, "GitHub did not return artifact redirect location");
  }
  return signedUrl;
}

async function fetchSignedArtifact(request, signedUrl) {
  const headers = new Headers();
  const rangeHeader = request.headers.get("Range");
  const priorityHeader = request.headers.get("Priority");

  if (rangeHeader) {
    headers.set("Range", rangeHeader);
  }
  if (priorityHeader) {
    headers.set("Priority", priorityHeader);
  }

  return fetch(signedUrl, {
    method: request.method,
    headers,
  });
}

function buildGithubArtifactProxyResponse(upstream) {
  const headers = artifactCorsHeaders();
  copyHeaderIfPresent(upstream.headers, headers, "accept-ranges");
  copyHeaderIfPresent(upstream.headers, headers, "content-disposition");
  copyHeaderIfPresent(upstream.headers, headers, "content-length");
  copyHeaderIfPresent(upstream.headers, headers, "content-range");
  copyHeaderIfPresent(upstream.headers, headers, "content-type");
  copyHeaderIfPresent(upstream.headers, headers, "etag");
  copyHeaderIfPresent(upstream.headers, headers, "last-modified");
  headers.set("cache-control", "no-store");

  return new Response(upstream.body, {
    status: upstream.status,
    headers,
  });
}

function artifactCacheKey(artifactRef) {
  return `${artifactRef.owner}/${artifactRef.repo}:${artifactRef.runId}:${artifactRef.artifactName}`;
}

function parseSignedUrlExpiryMs(url) {
  try {
    const parsed = new URL(url);
    const se = parsed.searchParams.get("se");
    if (!se) {
      return null;
    }
    const expiresAtMs = Date.parse(se);
    return Number.isFinite(expiresAtMs) ? expiresAtMs : null;
  } catch {
    return null;
  }
}

function parseGithubArtifactPath(path) {
  for (const route of GHA_ARTIFACT_ROUTES) {
    if (!path.startsWith(route.prefix)) {
      continue;
    }

    const remainder = path.slice(route.prefix.length);
    const sep = remainder.indexOf("/");
    if (sep <= 0) {
      return null;
    }

    const runId = remainder.slice(0, sep);
    if (!/^\d+$/.test(runId)) {
      return null;
    }

    const rawArtifactFile = remainder.slice(sep + 1);
    if (!rawArtifactFile || rawArtifactFile.includes("/")) {
      return null;
    }

    let artifactName;
    try {
      artifactName = decodeURIComponent(rawArtifactFile);
    } catch {
      return null;
    }

    if (artifactName.toLowerCase().endsWith(".zip")) {
      artifactName = artifactName.slice(0, -4);
    }

    if (!artifactName || artifactName.includes("/")) {
      return null;
    }

    return {
      runId,
      artifactName,
      owner: route.owner,
      repo: route.repo,
    };
  }

  return null;
}

function githubApiHeaders() {
  const token = typeof GITHUB_TOKEN === "string" ? GITHUB_TOKEN.trim() : "";
  if (!token) {
    throw httpError(
      500,
      "GITHUB_TOKEN worker binding is required for /pocketblue/gha/* and /live-pocket-fedora/gha/* artifact proxies"
    );
  }

  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "user-agent": "fastboop-bleeding-worker",
    "x-github-api-version": "2022-11-28",
  };
}

async function fetchGithubJson(url) {
  const response = await fetch(url, {
    method: "GET",
    headers: githubApiHeaders(),
  });

  if (!response.ok) {
    throw await githubResponseError(response, "GitHub API request failed");
  }

  return response.json();
}

async function githubResponseError(response, prefix) {
  let detail = `${response.status}`;

  try {
    const payload = await response.json();
    if (payload?.message) {
      detail = `${response.status} ${payload.message}`;
    }
  } catch {
    // noop
  }

  let status = 502;
  if (response.status === 404) {
    status = 404;
  } else if (response.status === 401) {
    status = 500;
  }

  return httpError(status, `${prefix}: ${detail}`);
}

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function copyHeaderIfPresent(from, to, name) {
  const value = from.get(name);
  if (value) {
    to.set(name, value);
  }
}

function artifactCorsHeaders() {
  return new Headers({
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, OPTIONS",
    "access-control-allow-headers": "Range, Priority, Content-Type",
    "access-control-expose-headers": "Content-Range, Content-Length, Accept-Ranges",
  });
}

function parseRangeHeader(rangeHeader) {
  // Parse "bytes=start-end" format
  const match = rangeHeader.match(/^bytes=(\d+)-(\d*)$/);
  if (!match) return undefined;
  
  const start = parseInt(match[1]);
  const end = match[2] ? parseInt(match[2]) : undefined;
  
  return end !== undefined ? { offset: start, length: end - start + 1 } : { offset: start };
}

function handleCorsPreflightArtifact() {
  return new Response(null, {
    status: 200,
    headers: artifactCorsHeadersWithMaxAge(),
  });
}

function artifactCorsHeadersWithMaxAge() {
  const headers = artifactCorsHeaders();
  headers.set("access-control-max-age", "86400");
  return headers;
}

async function redirectToLatest() {
  try {
    const latest = await loadLatest();
    return redirect(`/commit/${latest}/`);
  } catch (err) {
    if (err instanceof Response) {
      return err;
    }
    return new Response("Failed to resolve latest snapshot", { status: 502 });
  }
}

async function loadLatest() {
  const object = await R2_BUCKET.get(LATEST_KEY);
  if (!object) {
    throw new Response("latest.txt not found", { status: 503 });
  }
  const text = (await object.text()).trim();
  if (!text) {
    throw new Response("latest.txt empty", { status: 503 });
  }
  return text;
}

function redirect(path) {
  return new Response(null, {
    status: REDIRECT_STATUS,
    headers: {
      location: path,
      "cache-control": "no-store",
    },
  });
}

function cacheControlFor(key) {
  if (key.endsWith(".html")) {
    return "no-cache";
  }
  return "public, max-age=31536000, immutable";
}

function contentTypeFor(key) {
  const lower = key.toLowerCase();
  if (lower.endsWith(".html")) return "text/html; charset=utf-8";
  if (lower.endsWith(".css")) return "text/css; charset=utf-8";
  if (lower.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (lower.endsWith(".wasm")) return "application/wasm";
  if (lower.endsWith(".json")) return "application/json; charset=utf-8";
  if (lower.endsWith(".svg")) return "image/svg+xml";
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".ico")) return "image/x-icon";
  if (lower.endsWith(".txt")) return "text/plain; charset=utf-8";
  if (lower.endsWith(".map")) return "application/json; charset=utf-8";
  if (lower.endsWith(".caidx")) return "application/octet-stream";
  if (lower.endsWith(".ero")) return "application/octet-stream";
  return null;
}

function isR2DirectArtifactPath(path) {
  return (
    path.endsWith(".ero") ||
    path === "/live-pocket-fedora" ||
    path.startsWith("/live-pocket-fedora/")
  );
}
