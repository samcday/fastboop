/// Returns the MIME type for a file extension (without the dot).
/// Falls back to "application/octet-stream" for unknown extensions.
pub fn content_type_for_ext(ext: &str) -> &'static str {
    match ext {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "wasm" => "application/wasm",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "zip" => "application/zip",
        "xml" => "application/xml",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        _ => "application/octet-stream",
    }
}

/// Returns the Cache-Control header value for a file extension.
/// HTML files get "no-cache", everything else gets "public, max-age=31536000, immutable".
pub fn cache_control_for_ext(ext: &str) -> &'static str {
    if ext == "html" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    }
}

#[cfg(test)]
mod tests {
    use super::{cache_control_for_ext, content_type_for_ext};

    #[test]
    fn maps_all_extensions() {
        assert_eq!(content_type_for_ext("html"), "text/html; charset=utf-8");
        assert_eq!(content_type_for_ext("css"), "text/css");
        assert_eq!(content_type_for_ext("js"), "text/javascript");
        assert_eq!(content_type_for_ext("mjs"), "text/javascript");
        assert_eq!(content_type_for_ext("wasm"), "application/wasm");
        assert_eq!(content_type_for_ext("json"), "application/json");
        assert_eq!(content_type_for_ext("svg"), "image/svg+xml");
        assert_eq!(content_type_for_ext("png"), "image/png");
        assert_eq!(content_type_for_ext("jpg"), "image/jpeg");
        assert_eq!(content_type_for_ext("jpeg"), "image/jpeg");
        assert_eq!(content_type_for_ext("gif"), "image/gif");
        assert_eq!(content_type_for_ext("ico"), "image/x-icon");
        assert_eq!(content_type_for_ext("txt"), "text/plain; charset=utf-8");
        assert_eq!(content_type_for_ext("map"), "application/json");
        assert_eq!(content_type_for_ext("gz"), "application/gzip");
        assert_eq!(content_type_for_ext("tar"), "application/x-tar");
        assert_eq!(content_type_for_ext("zip"), "application/zip");
        assert_eq!(content_type_for_ext("xml"), "application/xml");
        assert_eq!(content_type_for_ext("webp"), "image/webp");
        assert_eq!(content_type_for_ext("woff"), "font/woff");
        assert_eq!(content_type_for_ext("woff2"), "font/woff2");
        assert_eq!(content_type_for_ext("ttf"), "font/ttf");
    }

    #[test]
    fn falls_back_for_unknown_extensions() {
        assert_eq!(content_type_for_ext("unknown"), "application/octet-stream");
    }

    #[test]
    fn cache_control_policy() {
        assert_eq!(cache_control_for_ext("html"), "no-cache");
        assert_eq!(
            cache_control_for_ext("js"),
            "public, max-age=31536000, immutable"
        );
    }
}
