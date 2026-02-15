const LATEST_KEY = "latest.txt";
const REDIRECT_STATUS = 302;

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Handle CORS preflight requests for direct artifacts.
  if (request.method === "OPTIONS" && isDirectArtifactPath(path)) {
    return handleCorsPreflightArtifact();
  }

  if (path === "/" || path === "/latest" || path === "/latest/") {
    return redirectToLatest();
  }

  // Handle direct artifact paths with range request support.
  if (isDirectArtifactPath(path)) {
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
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET, HEAD, OPTIONS",
      "access-control-allow-headers": "Range, Priority, Content-Type",
      "access-control-expose-headers": "Content-Range, Content-Length, Accept-Ranges",
      "access-control-max-age": "86400", // Cache preflight for 24 hours
    },
  });
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

function isDirectArtifactPath(path) {
  return path.endsWith(".ero") || path.startsWith("/live-pocket-fedora/casync/");
}
