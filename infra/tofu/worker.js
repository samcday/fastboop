const LATEST_KEY = "latest.txt";
const REDIRECT_STATUS = 302;

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Handle CORS preflight requests for .ero files
  if (request.method === "OPTIONS" && path.endsWith(".ero")) {
    return handleCorsPreflightEro();
  }

  if (path === "/" || path === "/latest" || path === "/latest/") {
    return redirectToLatest();
  }

  // Handle .ero files directly with range request support
  if (path.endsWith(".ero")) {
    return handleEroFile(request, path);
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

async function handleEroFile(request, path) {
  // Remove leading slash for R2 key
  const key = path.slice(1);
  
  // Prepare headers to forward to R2
  const requestHeaders = new Headers();
  
  // Forward Range header for partial content requests
  const rangeHeader = request.headers.get("Range");
  if (rangeHeader) {
    requestHeaders.set("Range", rangeHeader);
  }
  
  // Forward Priority headers for CloudFlare to respect
  const priorityHeader = request.headers.get("Priority");
  if (priorityHeader) {
    requestHeaders.set("Priority", priorityHeader);
  }
  
  try {
    // Get object from R2 with range support
    const object = await R2_BUCKET.get(key, {
      range: rangeHeader ? parseRangeHeader(rangeHeader) : undefined,
    });
    
    if (!object) {
      return new Response("EROFS artifact not found", { status: 404 });
    }
    
    const headers = new Headers();
    
    // Set appropriate content type for EROFS files
    headers.set("content-type", "application/octet-stream");
    headers.set("etag", object.etag);
    
    // Set CORS headers for cross-origin requests from fastboop web
    headers.set("access-control-allow-origin", "*");
    headers.set("access-control-allow-methods", "GET, HEAD, OPTIONS");
    headers.set("access-control-allow-headers", "Range, Priority, Content-Type");
    headers.set("access-control-expose-headers", "Content-Range, Content-Length, Accept-Ranges");
    
    // Enable range requests
    headers.set("accept-ranges", "bytes");
    
    // Cache immutably since EROFS artifacts are content-addressed
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
    console.error("Error fetching EROFS artifact:", error);
    return new Response("Failed to fetch EROFS artifact", { status: 500 });
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

function handleCorsPreflightEro() {
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
  if (lower.endsWith(".ero")) return "application/octet-stream";
  return null;
}
