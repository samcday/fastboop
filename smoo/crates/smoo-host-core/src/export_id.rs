use crate::BlockSource;
use core::hash::Hasher;

const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;

/// A tiny no_std-friendly 32-bit hasher (FNV-1a) for export_id derivation.
#[derive(Clone, Copy, Debug)]
pub struct ExportHasher32 {
    state: u32,
}

impl ExportHasher32 {
    pub const fn new() -> Self {
        Self {
            state: FNV_OFFSET_BASIS,
        }
    }
}

impl Default for ExportHasher32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for ExportHasher32 {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.state ^= u32::from(*byte);
            self.state = self.state.wrapping_mul(FNV_PRIME);
        }
    }

    fn finish(&self) -> u64 {
        self.state as u64
    }
}

/// Allows a block source to feed its stable identity into an export_id hash.
pub trait ExportIdentity {
    fn write_export_id(&self, state: &mut dyn Hasher);
}

fn finalize(state: u32) -> u32 {
    if state == 0 { 1 } else { state }
}

/// Derive a stable u32 export_id with a custom hasher and identity writer.
pub fn derive_export_id_with<H: Hasher>(
    mut hasher: H,
    block_size: u32,
    block_count: u64,
    write_identity: impl FnOnce(&mut H),
) -> u32 {
    hasher.write_u32(block_size);
    hasher.write_u64(block_count);
    write_identity(&mut hasher);
    finalize(hasher.finish() as u32)
}

/// Derive an export_id by hashing a caller-provided identity string plus geometry.
///
/// Kept as a convenience wrapper around the generic helper.
pub fn derive_export_id(source_id: &str, block_size: u32, block_count: u64) -> u32 {
    derive_export_id_with(ExportHasher32::new(), block_size, block_count, |state| {
        state.write(source_id.as_bytes());
    })
}

/// Derive an export_id from a [`BlockSource`] by letting it feed identity bytes.
pub fn derive_export_id_from_source<S: BlockSource + ExportIdentity + ?Sized>(
    source: &S,
    block_count: u64,
) -> u32 {
    derive_export_id_with(
        ExportHasher32::new(),
        source.block_size(),
        block_count,
        |state| {
            ExportIdentity::write_export_id(source, state);
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ExportHasher32, ExportIdentity, derive_export_id, derive_export_id_from_source,
        derive_export_id_with,
    };
    use alloc::boxed::Box;
    use core::hash::Hasher;

    #[test]
    fn export_id_changes_with_inputs() {
        let base = derive_export_id("file:/dev/null", 512, 1024);
        assert_ne!(base, derive_export_id("file:/dev/null", 4096, 1024));
        assert_ne!(base, derive_export_id("file:/dev/null", 512, 2048));
        assert_ne!(
            base,
            derive_export_id("http:https://example.com/disk.img", 512, 1024)
        );
    }

    #[test]
    fn export_id_never_zero() {
        assert_ne!(derive_export_id("", 0, 0), 0);
    }

    #[test]
    fn export_id_stable() {
        let id = derive_export_id("random:1234", 4096, 16);
        assert_eq!(id, derive_export_id("random:1234", 4096, 16));
    }

    #[test]
    fn derive_export_id_with_custom_hasher() {
        let id = derive_export_id_with(ExportHasher32::default(), 512, 8, |h| {
            h.write(b"abc");
        });
        assert_ne!(id, 0);
    }

    #[derive(Clone)]
    struct FakeSource(&'static str, u32);

    impl ExportIdentity for FakeSource {
        fn write_export_id(&self, state: &mut dyn Hasher) {
            state.write(self.0.as_bytes());
            state.write_u32(self.1);
        }
    }

    #[async_trait::async_trait]
    impl crate::BlockSource for FakeSource {
        fn block_size(&self) -> u32 {
            512
        }

        async fn total_blocks(&self) -> crate::BlockSourceResult<u64> {
            Ok(0)
        }

        async fn read_blocks(&self, _lba: u64, _buf: &mut [u8]) -> crate::BlockSourceResult<usize> {
            Ok(0)
        }

        async fn write_blocks(&self, _lba: u64, _buf: &[u8]) -> crate::BlockSourceResult<usize> {
            Ok(0)
        }
    }

    #[test]
    fn export_id_from_source_includes_identity() {
        let a = FakeSource("a", 1);
        let b = FakeSource("b", 1);
        assert_ne!(
            derive_export_id_from_source(&a, 1),
            derive_export_id_from_source(&b, 1)
        );
    }

    #[test]
    fn export_hasher_default_state_non_zero() {
        let h = ExportHasher32::default();
        assert_ne!(h.finish(), 0);
    }
}
