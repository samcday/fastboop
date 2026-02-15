use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use async_trait::async_trait;
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use sha2::{Digest, Sha256, Sha512_256};
use tracing::{debug, trace};

use crate::index::{CasyncChunkId, CasyncIndex, CasyncIndexValidation};

#[derive(Clone, Copy, Debug)]
pub struct CasyncReaderConfig {
    pub block_size: u32,
    pub strict_verify: bool,
}

impl Default for CasyncReaderConfig {
    fn default() -> Self {
        Self {
            block_size: 4096,
            strict_verify: false,
        }
    }
}

#[async_trait]
pub trait CasyncIndexSource: Send + Sync {
    async fn load_index_bytes(&self) -> GibbloxResult<Vec<u8>>;
}

#[async_trait]
impl<T> CasyncIndexSource for Arc<T>
where
    T: CasyncIndexSource + ?Sized,
{
    async fn load_index_bytes(&self) -> GibbloxResult<Vec<u8>> {
        (**self).load_index_bytes().await
    }
}

#[async_trait]
pub trait CasyncChunkStore: Send + Sync {
    async fn load_chunk(&self, id: &CasyncChunkId, ctx: ReadContext) -> GibbloxResult<Vec<u8>>;
}

#[async_trait]
impl<T> CasyncChunkStore for Arc<T>
where
    T: CasyncChunkStore + ?Sized,
{
    async fn load_chunk(&self, id: &CasyncChunkId, ctx: ReadContext) -> GibbloxResult<Vec<u8>> {
        (**self).load_chunk(id, ctx).await
    }
}

pub struct CasyncBlockReader<S> {
    index: CasyncIndex,
    chunk_store: S,
    config: CasyncReaderConfig,
    total_blocks: u64,
    index_digest: CasyncChunkId,
    chunks_verified: AtomicU64,
}

impl<S> CasyncBlockReader<S>
where
    S: CasyncChunkStore,
{
    pub async fn open<I>(
        index_source: I,
        chunk_store: S,
        config: CasyncReaderConfig,
    ) -> GibbloxResult<Self>
    where
        I: CasyncIndexSource,
    {
        validate_block_size(config.block_size)?;

        let index_bytes = index_source.load_index_bytes().await?;
        trace!(
            index_bytes = index_bytes.len(),
            strict_verify = config.strict_verify,
            "loaded casync index bytes"
        );

        let index = CasyncIndex::parse(
            &index_bytes,
            CasyncIndexValidation {
                strict: config.strict_verify,
            },
        )?;

        let digest = digest_sha256(&index_bytes);
        let index_digest = CasyncChunkId::from_bytes(digest);
        let total_blocks = index.blob_size().div_ceil(config.block_size as u64);

        debug!(
            index_bytes = index_bytes.len(),
            blob_size = index.blob_size(),
            total_chunks = index.total_chunks(),
            total_blocks,
            index_digest = %index_digest,
            "casync index parsed"
        );

        Ok(Self {
            index,
            chunk_store,
            config,
            total_blocks,
            index_digest,
            chunks_verified: AtomicU64::new(0),
        })
    }

    pub fn index(&self) -> &CasyncIndex {
        &self.index
    }

    pub fn index_digest(&self) -> CasyncChunkId {
        self.index_digest
    }

    pub fn chunks_verified(&self) -> u64 {
        self.chunks_verified.load(Ordering::Relaxed)
    }

    fn blocks_from_len(&self, len: usize) -> GibbloxResult<u64> {
        if len == 0 {
            return Ok(0);
        }
        let block_size = self.config.block_size as usize;
        if !len.is_multiple_of(block_size) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok((len / block_size) as u64)
    }

    fn validate_read_range(&self, lba: u64, blocks: u64) -> GibbloxResult<()> {
        let end = lba.checked_add(blocks).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if end > self.total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested range exceeds image size",
            ));
        }
        Ok(())
    }

    async fn load_chunk_for_read(
        &self,
        chunk_idx: usize,
        ctx: ReadContext,
    ) -> GibbloxResult<Vec<u8>> {
        let Some(chunk_ref) = self.index.chunks().get(chunk_idx) else {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "chunk index out of range",
            ));
        };

        let chunk_data = self.chunk_store.load_chunk(chunk_ref.id(), ctx).await?;
        self.verify_chunk_payload(chunk_idx, &chunk_data)?;
        Ok(chunk_data)
    }

    fn verify_chunk_payload(&self, chunk_idx: usize, payload: &[u8]) -> GibbloxResult<()> {
        let Some(chunk_ref) = self.index.chunks().get(chunk_idx) else {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "chunk index out of range",
            ));
        };

        let expected_len = self.index.chunk_len(chunk_idx).ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "chunk length unavailable for index entry",
            )
        })?;
        if payload.len() as u64 != expected_len {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                format!(
                    "chunk length mismatch for {}: expected {}, got {}",
                    chunk_ref.id(),
                    expected_len,
                    payload.len()
                ),
            ));
        }

        let actual = if self.index.uses_sha512_256() {
            CasyncChunkId::from_bytes(digest_sha512_256(payload))
        } else {
            CasyncChunkId::from_bytes(digest_sha256(payload))
        };

        if actual != *chunk_ref.id() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                format!(
                    "chunk digest mismatch for {}: got {}",
                    chunk_ref.id(),
                    actual
                ),
            ));
        }

        let done = self.chunks_verified.fetch_add(1, Ordering::Relaxed) + 1;
        trace!(
            chunk_idx,
            chunk = %chunk_ref.id(),
            verified = done,
            total_chunks = self.index.total_chunks(),
            "chunk verified"
        );

        Ok(())
    }
}

#[async_trait]
impl<S> BlockReader for CasyncBlockReader<S>
where
    S: CasyncChunkStore,
{
    fn block_size(&self) -> u32 {
        self.config.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.total_blocks)
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            out,
            "casync:index={}:chunk_count={}:blob_size={}",
            self.index_digest,
            self.index.total_chunks(),
            self.index.blob_size()
        )
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let blocks = self.blocks_from_len(buf.len())?;
        self.validate_read_range(lba, blocks)?;

        let read_start = lba
            .checked_mul(self.config.block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read offset overflow")
            })?;
        if read_start >= self.index.blob_size() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested start offset is outside the image",
            ));
        }

        let requested_end = read_start.checked_add(buf.len() as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read end overflow")
        })?;
        let read_end = requested_end.min(self.index.blob_size());

        buf.fill(0);

        let mut cursor = read_start;
        let mut chunk_idx = self.index.chunk_for_offset(read_start).ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "could not map read offset to chunk index",
            )
        })?;

        while cursor < read_end {
            let (chunk_start, chunk_end) = self.index.chunk_bounds(chunk_idx).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "chunk bounds unavailable")
            })?;

            let chunk_data = self.load_chunk_for_read(chunk_idx, ctx).await?;

            let copy_start = cursor.max(chunk_start);
            let copy_end = read_end.min(chunk_end);
            if copy_end <= copy_start {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "chunk bounds did not advance read cursor",
                ));
            }

            let src_start = usize::try_from(copy_start - chunk_start).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source offset overflow")
            })?;
            let src_end = usize::try_from(copy_end - chunk_start).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source end overflow")
            })?;
            let dst_start = usize::try_from(copy_start - read_start).map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "destination offset overflow",
                )
            })?;
            let dst_end = usize::try_from(copy_end - read_start).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "destination end overflow")
            })?;

            buf[dst_start..dst_end].copy_from_slice(&chunk_data[src_start..src_end]);

            cursor = copy_end;
            chunk_idx += 1;
        }

        trace!(
            lba,
            blocks,
            bytes = buf.len(),
            effective_bytes = read_end - read_start,
            "served casync read"
        );

        Ok(buf.len())
    }
}

fn validate_block_size(block_size: u32) -> GibbloxResult<()> {
    if block_size == 0 || !block_size.is_power_of_two() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "block size must be non-zero power of two",
        ));
    }
    Ok(())
}

fn digest_sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn digest_sha512_256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha512_256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        CasyncBlockReader, CasyncChunkId, CasyncChunkStore, CasyncIndexSource, CasyncReaderConfig,
    };
    use alloc::{boxed::Box, collections::BTreeMap, format, sync::Arc, vec, vec::Vec};
    use async_trait::async_trait;
    use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
    use sha2::{Digest, Sha256};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    const CA_FORMAT_INDEX: u64 = 0x9682_4d9c_7b12_9ff9;
    const CA_FORMAT_TABLE: u64 = 0xe75b_9e11_2f17_417d;
    const CA_FORMAT_TABLE_TAIL_MARKER: u64 = 0x4b4f_050e_5549_ecd1;

    const INDEX_HEADER_SIZE: usize = 48;
    const TABLE_HEADER_SIZE: usize = 16;
    const TABLE_ITEM_SIZE: usize = 40;
    const TABLE_TAIL_SIZE: usize = 40;

    struct StaticIndexSource {
        bytes: Vec<u8>,
    }

    #[async_trait]
    impl CasyncIndexSource for StaticIndexSource {
        async fn load_index_bytes(&self) -> GibbloxResult<Vec<u8>> {
            Ok(self.bytes.clone())
        }
    }

    struct MemoryChunkStore {
        source: BTreeMap<CasyncChunkId, Vec<u8>>,
        cache: Mutex<BTreeMap<CasyncChunkId, Vec<u8>>>,
        offline: bool,
        fetch_calls: AtomicUsize,
    }

    impl MemoryChunkStore {
        fn new(source: BTreeMap<CasyncChunkId, Vec<u8>>, offline: bool) -> Self {
            Self {
                source,
                cache: Mutex::new(BTreeMap::new()),
                offline,
                fetch_calls: AtomicUsize::new(0),
            }
        }

        fn with_seed(
            source: BTreeMap<CasyncChunkId, Vec<u8>>,
            seeded: BTreeMap<CasyncChunkId, Vec<u8>>,
            offline: bool,
        ) -> Self {
            Self {
                source,
                cache: Mutex::new(seeded),
                offline,
                fetch_calls: AtomicUsize::new(0),
            }
        }

        fn fetch_calls(&self) -> usize {
            self.fetch_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl CasyncChunkStore for MemoryChunkStore {
        async fn load_chunk(
            &self,
            id: &CasyncChunkId,
            _ctx: ReadContext,
        ) -> GibbloxResult<Vec<u8>> {
            if let Some(hit) = self
                .cache
                .lock()
                .map_err(|_| GibbloxError::with_message(GibbloxErrorKind::Io, "cache poisoned"))?
                .get(id)
                .cloned()
            {
                return Ok(hit);
            }

            if self.offline {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!("offline and chunk not cached: {id}"),
                ));
            }

            let Some(payload) = self.source.get(id).cloned() else {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!("missing source chunk: {id}"),
                ));
            };

            self.fetch_calls.fetch_add(1, Ordering::SeqCst);
            self.cache
                .lock()
                .map_err(|_| GibbloxError::with_message(GibbloxErrorKind::Io, "cache poisoned"))?
                .insert(*id, payload.clone());
            Ok(payload)
        }
    }

    #[tokio::test]
    async fn reconstructs_bytes_and_zero_pads_final_block() {
        let chunks = vec![b"abcd".to_vec(), b"ef".to_vec()];
        let (index_bytes, chunk_map, _) = build_index_and_chunks(&chunks);

        let reader = CasyncBlockReader::open(
            StaticIndexSource { bytes: index_bytes },
            MemoryChunkStore::new(chunk_map, false),
            CasyncReaderConfig {
                block_size: 4,
                strict_verify: true,
            },
        )
        .await
        .expect("open reader");

        assert_eq!(reader.total_blocks().await.expect("total blocks"), 2);

        let mut buf = vec![0u8; 8];
        reader
            .read_blocks(0, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read blocks");
        assert_eq!(&buf, b"abcdef\0\0");
    }

    #[tokio::test]
    async fn chunk_store_can_cache_internally() {
        let chunks = vec![b"aaaa".to_vec(), b"bbbb".to_vec()];
        let (index_bytes, chunk_map, _) = build_index_and_chunks(&chunks);

        let chunk_store = Arc::new(MemoryChunkStore::new(chunk_map, false));
        let reader = CasyncBlockReader::open(
            StaticIndexSource { bytes: index_bytes },
            Arc::clone(&chunk_store),
            CasyncReaderConfig {
                block_size: 4,
                strict_verify: true,
            },
        )
        .await
        .expect("open reader");

        let mut first = vec![0u8; 8];
        reader
            .read_blocks(0, &mut first, ReadContext::FOREGROUND)
            .await
            .expect("first read");

        let mut second = vec![0u8; 8];
        reader
            .read_blocks(0, &mut second, ReadContext::FOREGROUND)
            .await
            .expect("second read");

        assert_eq!(&first, b"aaaabbbb");
        assert_eq!(&second, b"aaaabbbb");
        assert_eq!(chunk_store.fetch_calls(), 2);
    }

    #[tokio::test]
    async fn offline_mode_errors_on_missing_chunk() {
        let chunks = vec![b"abcd".to_vec()];
        let (index_bytes, chunk_map, _) = build_index_and_chunks(&chunks);

        let reader = CasyncBlockReader::open(
            StaticIndexSource { bytes: index_bytes },
            MemoryChunkStore::new(chunk_map, true),
            CasyncReaderConfig {
                block_size: 4,
                strict_verify: true,
            },
        )
        .await
        .expect("open reader");

        let mut buf = vec![0u8; 4];
        let err = reader
            .read_blocks(0, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect_err("offline miss should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::Io);
    }

    #[tokio::test]
    async fn corrupt_cached_chunk_fails_verification() {
        let chunks = vec![b"abcd".to_vec()];
        let (index_bytes, chunk_map, chunk_ids) = build_index_and_chunks(&chunks);
        let mut seeded = BTreeMap::new();
        seeded.insert(chunk_ids[0], b"zzzz".to_vec());

        let reader = CasyncBlockReader::open(
            StaticIndexSource { bytes: index_bytes },
            MemoryChunkStore::with_seed(chunk_map, seeded, false),
            CasyncReaderConfig {
                block_size: 4,
                strict_verify: true,
            },
        )
        .await
        .expect("open reader");

        let mut buf = vec![0u8; 4];
        let err = reader
            .read_blocks(0, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect_err("corrupt cached payload should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::Io);
    }

    fn build_index_and_chunks(
        chunks: &[Vec<u8>],
    ) -> (
        Vec<u8>,
        BTreeMap<CasyncChunkId, Vec<u8>>,
        Vec<CasyncChunkId>,
    ) {
        let mut out = Vec::new();
        let mut chunk_map = BTreeMap::new();
        let mut chunk_ids = Vec::new();

        out.extend_from_slice(&(INDEX_HEADER_SIZE as u64).to_le_bytes());
        out.extend_from_slice(&CA_FORMAT_INDEX.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&4096u64.to_le_bytes());
        out.extend_from_slice(&(128 * 1024 * 1024u64).to_le_bytes());

        out.extend_from_slice(&u64::MAX.to_le_bytes());
        out.extend_from_slice(&CA_FORMAT_TABLE.to_le_bytes());

        let mut end = 0u64;
        for chunk in chunks {
            let digest = Sha256::digest(chunk);
            let mut digest_arr = [0u8; 32];
            digest_arr.copy_from_slice(&digest);
            let chunk_id = CasyncChunkId::from_bytes(digest_arr);

            end += chunk.len() as u64;
            out.extend_from_slice(&end.to_le_bytes());
            out.extend_from_slice(&digest_arr);

            chunk_map.insert(chunk_id, chunk.clone());
            chunk_ids.push(chunk_id);
        }

        let table_size =
            (TABLE_HEADER_SIZE + (chunks.len() * TABLE_ITEM_SIZE) + TABLE_TAIL_SIZE) as u64;
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&(INDEX_HEADER_SIZE as u64).to_le_bytes());
        out.extend_from_slice(&table_size.to_le_bytes());
        out.extend_from_slice(&CA_FORMAT_TABLE_TAIL_MARKER.to_le_bytes());

        (out, chunk_map, chunk_ids)
    }
}
