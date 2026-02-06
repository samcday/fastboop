const LATEST_KEY = "latest.txt";
const REDIRECT_STATUS = 302;

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/" || path === "/latest" || path === "/latest/") {
    return redirectToLatest();
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
  return null;
}
