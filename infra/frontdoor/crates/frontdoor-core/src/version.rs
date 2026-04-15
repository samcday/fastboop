fn parse_uint(bytes: &[u8], i: &mut usize) -> bool {
    let start = *i;
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        *i += 1;
    }
    *i > start
}

/// Returns true if `s` matches `vX.Y.Z` or `vX.Y.Z-rc.N` where X, Y, Z, N are unsigned integers.
pub fn is_valid_version(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;

    if bytes.get(i) != Some(&b'v') {
        return false;
    }
    i += 1;

    if !parse_uint(bytes, &mut i) {
        return false;
    }
    if bytes.get(i) != Some(&b'.') {
        return false;
    }
    i += 1;

    if !parse_uint(bytes, &mut i) {
        return false;
    }
    if bytes.get(i) != Some(&b'.') {
        return false;
    }
    i += 1;

    if !parse_uint(bytes, &mut i) {
        return false;
    }

    if i == bytes.len() {
        return true;
    }

    if bytes.get(i) != Some(&b'-')
        || bytes.get(i + 1) != Some(&b'r')
        || bytes.get(i + 2) != Some(&b'c')
        || bytes.get(i + 3) != Some(&b'.')
    {
        return false;
    }
    i += 4;

    parse_uint(bytes, &mut i) && i == bytes.len()
}

/// Given a path like `/v1.2.3/some/file.js`, returns `Some(("v1.2.3", "some/file.js"))`.
/// The version must be valid per `is_valid_version`. The relative path has no leading slash.
/// Returns `None` if the path doesn't match.
pub fn parse_version_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix('/')?;
    let slash_idx = rest.find('/')?;

    let version = &rest[..slash_idx];
    if !is_valid_version(version) {
        return None;
    }

    let relative = &rest[slash_idx + 1..];
    Some((version, relative))
}

#[cfg(test)]
mod tests {
    use super::{is_valid_version, parse_version_path};

    #[test]
    fn valid_versions() {
        assert!(is_valid_version("v0.0.1"));
        assert!(is_valid_version("v1.2.3"));
        assert!(is_valid_version("v0.0.1-rc.13"));
        assert!(is_valid_version("v10.20.30-rc.1"));
    }

    #[test]
    fn invalid_versions() {
        assert!(!is_valid_version("v1"));
        assert!(!is_valid_version("v1.2"));
        assert!(!is_valid_version("1.2.3"));
        assert!(!is_valid_version("v1.2.3-beta.1"));
        assert!(!is_valid_version("v1.2.3-rc."));
        assert!(!is_valid_version("v1.2.3-rc"));
        assert!(!is_valid_version(""));
    }

    #[test]
    fn parse_version_paths() {
        assert_eq!(
            parse_version_path("/v0.0.1/index.html"),
            Some(("v0.0.1", "index.html"))
        );
        assert_eq!(
            parse_version_path("/v1.2.3-rc.1/assets/app.js"),
            Some(("v1.2.3-rc.1", "assets/app.js"))
        );
        assert_eq!(parse_version_path("/v0.0.1/"), Some(("v0.0.1", "")));
        assert_eq!(parse_version_path("/notaversion/file"), None);
        assert_eq!(parse_version_path("/v0.0.1"), None);
    }
}
