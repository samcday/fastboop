use alloc::string::String;
use sha2::{Digest, Sha256};

/// Computes a SHA-256 cache key from owner/repo/run_id.
/// The input is formatted as "{owner}/{repo}:{run_id}" before hashing.
pub fn cache_key(owner: &str, repo: &str, run_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(owner.as_bytes());
    hasher.update(b"/");
    hasher.update(repo.as_bytes());
    hasher.update(b":");
    hasher.update(run_id.as_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Encodes a byte slice as a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{cache_key, hex_encode};
    use sha2::{Digest, Sha256};

    #[test]
    fn cache_key_is_deterministic() {
        let key = cache_key("samcday", "fastboop", "12345");
        assert_eq!(key.len(), 32);
        assert_eq!(
            key,
            [
                0x31, 0x1a, 0x81, 0x24, 0xe8, 0x4b, 0xb5, 0x70, 0x08, 0x23, 0x06, 0xf4, 0x37, 0xe3,
                0xf0, 0xb0, 0xc7, 0xee, 0xe1, 0x9e, 0x11, 0xe9, 0x2c, 0xdf, 0x68, 0x85, 0xa6, 0xab,
                0xc1, 0x4d, 0x21, 0x09,
            ]
        );
    }

    #[test]
    fn hex_encodes_bytes() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn hex_encodes_known_sha256_hash() {
        let digest = Sha256::digest(b"abc");
        assert_eq!(
            hex_encode(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
