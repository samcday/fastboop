#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};
use async_trait::async_trait;
use core::{
    cell::UnsafeCell,
    fmt,
    hint::spin_loop,
    sync::atomic::{AtomicBool, Ordering},
};
use futures_channel::oneshot;
use gibblox_core::{
    BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext,
    derive_block_identity_id,
};
use tracing::trace;

const CACHE_MAGIC: [u8; 7] = *b"GIBBLX!";
const CACHE_VERSION: u8 = 1;
const CACHE_PREFIX_LEN: usize = 28;
const CACHE_DIRTY_OFFSET: u64 = 8;
const DEFAULT_FLUSH_BATCHES: u32 = 64;
const ZERO_CHUNK_LEN: usize = 4096;

/// Backend I/O abstraction for a single cache file.
///
/// Implementations are expected to be internally synchronized; the cache wrapper may call these
/// methods concurrently from multiple tasks.
#[async_trait]
pub trait CacheOps: Send + Sync {
    /// Read bytes at a fixed offset. Returns the number of bytes read.
    async fn read_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<usize>;

    /// Write all bytes at a fixed offset.
    async fn write_at(&self, offset: u64, data: &[u8]) -> GibbloxResult<()>;

    /// Resize the underlying cache file.
    async fn set_len(&self, len: u64) -> GibbloxResult<()>;

    /// Persist pending data and metadata changes.
    async fn flush(&self) -> GibbloxResult<()>;
}

#[async_trait]
impl<T> CacheOps for Arc<T>
where
    T: CacheOps + ?Sized,
{
    async fn read_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<usize> {
        (**self).read_at(offset, out).await
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> GibbloxResult<()> {
        (**self).write_at(offset, data).await
    }

    async fn set_len(&self, len: u64) -> GibbloxResult<()> {
        (**self).set_len(len).await
    }

    async fn flush(&self) -> GibbloxResult<()> {
        (**self).flush().await
    }
}

/// Read-only block reader wrapper that consults a local file-style cache.
///
/// The cache file contains a compact header, a per-block validity bitmap, and raw backing bytes.
/// Misses are fetched from the inner reader, written into the data region, and marked valid.
pub struct CachedBlockReader<S, C> {
    inner: S,
    cache: C,
    block_size: u32,
    total_blocks: u64,
    bitmap_offset: u64,
    data_offset: u64,
    flush_every_batches: u32,
    state: SpinLock<CacheState>,
    in_flight: SpinLock<InFlight>,
    mutation_lock: AsyncLock,
}

impl<S, C> CachedBlockReader<S, C>
where
    S: BlockReader,
    C: CacheOps,
{
    /// Construct a cached reader using the default write-batch flush policy.
    pub async fn new(inner: S, cache: C) -> GibbloxResult<Self> {
        Self::with_flush_batch_limit(inner, cache, DEFAULT_FLUSH_BATCHES).await
    }

    /// Construct a cached reader with a custom write-batch flush threshold.
    pub async fn with_flush_batch_limit(
        inner: S,
        cache: C,
        flush_every_batches: u32,
    ) -> GibbloxResult<Self> {
        if flush_every_batches == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "flush batch limit must be non-zero",
            ));
        }
        let block_size = inner.block_size();
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let total_blocks = inner.total_blocks().await?;
        let layout = CacheLayout::new(block_size, total_blocks)?;
        let identity = cached_reader_identity_string(&inner);
        let opened = open_or_initialize_cache(&cache, &layout, &identity).await?;
        trace!(
            block_size,
            total_blocks,
            bitmap_offset = opened.mapping.bitmap_offset,
            data_offset = opened.mapping.data_offset,
            flush_every_batches,
            "cached block reader initialized"
        );

        Ok(Self {
            inner,
            cache,
            block_size,
            total_blocks,
            bitmap_offset: opened.mapping.bitmap_offset,
            data_offset: opened.mapping.data_offset,
            flush_every_batches,
            state: SpinLock::new(CacheState {
                valid: opened.valid,
                dirty: false,
                batches_since_flush: 0,
            }),
            in_flight: SpinLock::new(InFlight::new()),
            mutation_lock: AsyncLock::new(),
        })
    }

    /// Force a cache flush and clear the dirty bit if there are pending writes.
    pub async fn flush_cache(&self) -> GibbloxResult<()> {
        let _guard = self.mutation_lock.lock().await;
        trace!("cache flush requested explicitly");
        self.flush_locked_if_needed(true).await
    }

    fn block_size_usize(&self) -> usize {
        self.block_size as usize
    }

    fn validate_range(&self, lba: u64, blocks: u64) -> GibbloxResult<()> {
        let end = lba.checked_add(blocks).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if end > self.total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested range exceeds total blocks",
            ));
        }
        Ok(())
    }

    fn blocks_from_len(&self, len: usize) -> GibbloxResult<u64> {
        if len == 0 {
            return Ok(0);
        }
        if !len.is_multiple_of(self.block_size_usize()) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok((len / self.block_size_usize()) as u64)
    }

    fn data_offset_for_block(&self, block_idx: u64) -> GibbloxResult<u64> {
        let block_bytes = block_idx
            .checked_mul(self.block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "block offset overflow")
            })?;
        self.data_offset.checked_add(block_bytes).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "data offset overflow")
        })
    }

    fn snapshot_segments(&self, lba: u64, blocks: u64) -> Vec<(u64, u64, bool)> {
        let guard = self.state.lock();
        let mut segments = Vec::new();
        let mut block = lba;
        while block < lba + blocks {
            let hit = bit_is_set(&guard.valid, block);
            let mut len = 1u64;
            while block + len < lba + blocks && bit_is_set(&guard.valid, block + len) == hit {
                len += 1;
            }
            segments.push((block, len, hit));
            block += len;
        }
        segments
    }

    fn invalidate_range(&self, start_block: u64, blocks: u64) {
        let mut guard = self.state.lock();
        clear_bits(&mut guard.valid, start_block, blocks);
    }

    async fn fill_from_cache(
        &self,
        lba: u64,
        blocks: u64,
        buf: &mut [u8],
    ) -> GibbloxResult<Vec<u64>> {
        let mut missing = Vec::new();
        let bs = self.block_size_usize();
        let segments = self.snapshot_segments(lba, blocks);

        for (start_block, len_blocks, hit) in segments {
            if !hit {
                missing.extend(start_block..start_block + len_blocks);
                continue;
            }

            let block_offset = (start_block - lba) as usize;
            let byte_start = block_offset.checked_mul(bs).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "buffer offset overflow")
            })?;
            let byte_len = (len_blocks as usize).checked_mul(bs).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "buffer length overflow")
            })?;
            let byte_end = byte_start.checked_add(byte_len).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "buffer end overflow")
            })?;
            let out = &mut buf[byte_start..byte_end];

            let data_offset = self.data_offset_for_block(start_block)?;
            let full = read_exact_at(&self.cache, data_offset, out).await?;
            if !full {
                self.invalidate_range(start_block, len_blocks);
                missing.extend(start_block..start_block + len_blocks);
            }
        }

        trace!(
            lba,
            blocks,
            missing = missing.len(),
            "cache read pass complete"
        );

        Ok(missing)
    }

    fn mark_in_flight(&self, blocks: &[u64]) -> (Vec<u64>, Vec<oneshot::Receiver<()>>) {
        let mut to_fetch = Vec::new();
        let mut waiters = Vec::new();
        let mut guard = self.in_flight.lock();
        for block in blocks {
            match guard.waiters.get_mut(block) {
                Some(pending) => {
                    let (tx, rx) = oneshot::channel();
                    pending.push(tx);
                    waiters.push(rx);
                }
                None => {
                    guard.waiters.insert(*block, Vec::new());
                    to_fetch.push(*block);
                }
            }
        }
        trace!(
            requested = blocks.len(),
            to_fetch = to_fetch.len(),
            waiting = waiters.len(),
            "updated in-flight block registry"
        );
        (to_fetch, waiters)
    }

    fn take_waiters(&self, start_block: u64, len_blocks: u64) -> Vec<oneshot::Sender<()>> {
        let mut guard = self.in_flight.lock();
        let mut senders = Vec::new();
        for block in start_block..(start_block + len_blocks) {
            if let Some(mut pending) = guard.waiters.remove(&block) {
                senders.append(&mut pending);
            }
        }
        senders
    }

    fn coalesce(blocks: &[u64]) -> Vec<(u64, u64)> {
        if blocks.is_empty() {
            return Vec::new();
        }
        let mut ranges = Vec::new();
        let mut start = blocks[0];
        let mut len = 1u64;
        for pair in blocks.windows(2) {
            if let [prev, curr] = pair {
                if *curr == *prev + 1 {
                    len += 1;
                } else {
                    ranges.push((start, len));
                    start = *curr;
                    len = 1;
                }
            }
        }
        ranges.push((start, len));
        ranges
    }

    async fn ensure_dirty_locked(&self) -> GibbloxResult<()> {
        let should_mark = {
            let mut guard = self.state.lock();
            if guard.dirty {
                false
            } else {
                guard.dirty = true;
                true
            }
        };
        if should_mark {
            trace!("marking cache dirty");
            write_dirty_flag(&self.cache, true).await?;
        }
        Ok(())
    }

    fn mark_valid_and_collect_bitmap_write(
        &self,
        start_block: u64,
        blocks: u64,
    ) -> GibbloxResult<(u64, Vec<u8>, bool)> {
        let end_block = start_block.checked_add(blocks).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "block range overflow")
        })?;
        let first_byte = (start_block / 8) as usize;
        let last_byte = ((end_block - 1) / 8) as usize;

        let mut guard = self.state.lock();
        set_bits(&mut guard.valid, start_block, blocks);
        guard.batches_since_flush = guard.batches_since_flush.saturating_add(1);
        let should_flush = guard.batches_since_flush >= self.flush_every_batches;
        let chunk = guard.valid[first_byte..=last_byte].to_vec();
        let bitmap_offset = self.bitmap_offset + first_byte as u64;
        Ok((bitmap_offset, chunk, should_flush))
    }

    async fn flush_locked_if_needed(&self, force: bool) -> GibbloxResult<()> {
        let should_flush = {
            let guard = self.state.lock();
            if !guard.dirty {
                false
            } else {
                force || guard.batches_since_flush >= self.flush_every_batches
            }
        };
        if !should_flush {
            return Ok(());
        }

        trace!(force, "flushing cache data and metadata");

        self.cache.flush().await?;
        write_dirty_flag(&self.cache, false).await?;
        self.cache.flush().await?;

        let mut guard = self.state.lock();
        guard.dirty = false;
        guard.batches_since_flush = 0;
        trace!("cache flush completed");
        Ok(())
    }

    async fn fetch_and_populate(
        &self,
        ranges: &[(u64, u64)],
        ctx: ReadContext,
    ) -> GibbloxResult<()> {
        let bs = self.block_size_usize();
        for (start_block, len_blocks) in ranges {
            trace!(
                start_block,
                len_blocks, "fetching missing range from inner source"
            );
            let expected_bytes = (*len_blocks as usize).checked_mul(bs).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range too large")
            })?;
            let mut buf = vec![0u8; expected_bytes];
            let result = async {
                let read = self.inner.read_blocks(*start_block, &mut buf, ctx).await?;
                if read != expected_bytes {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "inner source returned short read",
                    ));
                }

                let _mutation_guard = self.mutation_lock.lock().await;
                self.ensure_dirty_locked().await?;

                let data_offset = self.data_offset_for_block(*start_block)?;
                self.cache.write_at(data_offset, &buf).await?;

                let (bitmap_offset, bitmap_chunk, should_flush) =
                    self.mark_valid_and_collect_bitmap_write(*start_block, *len_blocks)?;
                self.cache.write_at(bitmap_offset, &bitmap_chunk).await?;
                trace!(
                    start_block,
                    len_blocks,
                    bytes = expected_bytes,
                    should_flush,
                    "cache range populated"
                );
                if should_flush {
                    self.flush_locked_if_needed(false).await?;
                }

                Ok(())
            }
            .await;

            let senders = self.take_waiters(*start_block, *len_blocks);
            for sender in senders {
                let _ = sender.send(());
            }
            result?;
        }
        Ok(())
    }
}

#[async_trait]
impl<S, C> BlockReader for CachedBlockReader<S, C>
where
    S: BlockReader,
    C: CacheOps,
{
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.total_blocks)
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        write_cached_identity(&self.inner, out)
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        let blocks = self.blocks_from_len(buf.len())?;
        if blocks == 0 {
            return Ok(0);
        }
        self.validate_range(lba, blocks)?;

        let missing = self.fill_from_cache(lba, blocks, buf).await?;
        if missing.is_empty() {
            trace!(lba, blocks, "cache hit");
            return Ok(buf.len());
        }

        trace!(lba, blocks, missing = missing.len(), "cache miss");

        let (to_fetch, waiters) = self.mark_in_flight(&missing);
        if !to_fetch.is_empty() {
            self.fetch_and_populate(&Self::coalesce(&to_fetch), ctx)
                .await?;
        }
        for waiter in waiters {
            let _ = waiter.await;
        }

        let final_missing = self.fill_from_cache(lba, blocks, buf).await?;
        if !final_missing.is_empty() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "cache fetch did not populate all blocks",
            ));
        }
        Ok(buf.len())
    }
}

fn write_cached_identity<S: BlockReader + ?Sized>(
    inner: &S,
    out: &mut dyn fmt::Write,
) -> fmt::Result {
    out.write_str("cached:(")?;
    inner.write_identity(out)?;
    out.write_str(")")
}

pub fn cached_reader_identity_string<S: BlockReader + ?Sized>(inner: &S) -> String {
    let mut identity = String::new();
    let _ = write_cached_identity(inner, &mut identity);
    identity
}

pub fn derive_cached_reader_identity_id<S: BlockReader + ?Sized>(
    inner: &S,
    total_blocks: u64,
) -> u32 {
    derive_block_identity_id(inner.block_size(), total_blocks, |writer| {
        write_cached_identity(inner, writer)
    })
}

struct CacheLayout {
    block_size: u32,
    total_blocks: u64,
    bitmap_bytes: u64,
    data_bytes: u64,
}

impl CacheLayout {
    fn new(block_size: u32, total_blocks: u64) -> GibbloxResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let bitmap_bytes = total_blocks.div_ceil(8);
        if bitmap_bytes > usize::MAX as u64 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "bitmap exceeds addressable memory",
            ));
        }
        let data_bytes = total_blocks.checked_mul(block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "cache too large")
        })?;

        Ok(Self {
            block_size,
            total_blocks,
            bitmap_bytes,
            data_bytes,
        })
    }

    fn bitmap_len_usize(&self) -> usize {
        self.bitmap_bytes as usize
    }
}

struct CacheMapping {
    bitmap_offset: u64,
    data_offset: u64,
    total_len: u64,
}

impl CacheMapping {
    fn new(layout: &CacheLayout, identity_len: usize) -> GibbloxResult<Self> {
        if identity_len > u32::MAX as usize {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "identity too large",
            ));
        }
        let bitmap_offset = (CACHE_PREFIX_LEN as u64)
            .checked_add(identity_len as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "metadata overflow")
            })?;
        let data_offset = bitmap_offset
            .checked_add(layout.bitmap_bytes)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "bitmap overflow")
            })?;
        let total_len = data_offset.checked_add(layout.data_bytes).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "cache length overflow")
        })?;
        Ok(Self {
            bitmap_offset,
            data_offset,
            total_len,
        })
    }
}

struct CacheHeader {
    dirty: bool,
    block_size: u32,
    total_blocks: u64,
    identity_len: u32,
}

impl CacheHeader {
    fn encode_prefix(&self) -> [u8; CACHE_PREFIX_LEN] {
        let mut out = [0u8; CACHE_PREFIX_LEN];
        out[0..7].copy_from_slice(&CACHE_MAGIC);
        out[7] = CACHE_VERSION;
        out[8] = if self.dirty { 1 } else { 0 };
        out[9] = 0;
        out[10..12].copy_from_slice(&0u16.to_le_bytes());
        out[12..16].copy_from_slice(&self.block_size.to_le_bytes());
        out[16..24].copy_from_slice(&self.total_blocks.to_le_bytes());
        out[24..28].copy_from_slice(&self.identity_len.to_le_bytes());
        out
    }

    fn decode_prefix(prefix: &[u8; CACHE_PREFIX_LEN]) -> Option<Self> {
        if prefix[0..7] != CACHE_MAGIC {
            return None;
        }
        if prefix[7] != CACHE_VERSION {
            return None;
        }
        let dirty = match prefix[8] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let block_size = u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]);
        let total_blocks = u64::from_le_bytes([
            prefix[16], prefix[17], prefix[18], prefix[19], prefix[20], prefix[21], prefix[22],
            prefix[23],
        ]);
        let identity_len = u32::from_le_bytes([prefix[24], prefix[25], prefix[26], prefix[27]]);
        Some(Self {
            dirty,
            block_size,
            total_blocks,
            identity_len,
        })
    }
}

struct OpenedCache {
    mapping: CacheMapping,
    valid: Vec<u8>,
}

async fn open_or_initialize_cache<C: CacheOps>(
    cache: &C,
    layout: &CacheLayout,
    identity: &str,
) -> GibbloxResult<OpenedCache> {
    trace!(
        block_size = layout.block_size,
        total_blocks = layout.total_blocks,
        "opening cache state"
    );
    let mut prefix = [0u8; CACHE_PREFIX_LEN];
    let have_prefix = read_exact_at(cache, 0, &mut prefix).await?;
    if !have_prefix {
        trace!("cache prefix missing; initializing cache file");
        return initialize_cache(cache, layout, identity).await;
    }

    let Some(header) = CacheHeader::decode_prefix(&prefix) else {
        trace!("cache header invalid; reinitializing cache file");
        return initialize_cache(cache, layout, identity).await;
    };
    if header.block_size != layout.block_size || header.total_blocks != layout.total_blocks {
        trace!("cache geometry mismatch; reinitializing cache file");
        return initialize_cache(cache, layout, identity).await;
    }

    let identity_len = header.identity_len as usize;
    let mapping = CacheMapping::new(layout, identity_len)?;
    let mut stored_identity = vec![0u8; identity_len];
    if !read_exact_at(cache, CACHE_PREFIX_LEN as u64, &mut stored_identity).await? {
        trace!("cache identity bytes missing; reinitializing cache file");
        return initialize_cache(cache, layout, identity).await;
    }
    if stored_identity.as_slice() != identity.as_bytes() {
        trace!("cache identity mismatch; reinitializing cache file");
        return initialize_cache(cache, layout, identity).await;
    }

    cache.set_len(mapping.total_len).await?;

    let mut valid = vec![0u8; layout.bitmap_len_usize()];
    if !read_exact_at(cache, mapping.bitmap_offset, &mut valid).await? {
        trace!("cache bitmap missing; reinitializing cache file");
        return initialize_cache(cache, layout, identity).await;
    }

    if header.dirty {
        trace!("cache opened dirty; clearing bitmap");
        valid.fill(0);
        write_zero_region(cache, mapping.bitmap_offset, layout.bitmap_bytes).await?;
        write_dirty_flag(cache, false).await?;
        cache.flush().await?;
    }

    trace!("cache state opened successfully");

    Ok(OpenedCache { mapping, valid })
}

async fn initialize_cache<C: CacheOps>(
    cache: &C,
    layout: &CacheLayout,
    identity: &str,
) -> GibbloxResult<OpenedCache> {
    let identity_len = identity.len();
    let mapping = CacheMapping::new(layout, identity_len)?;

    cache.set_len(0).await?;
    cache.set_len(mapping.total_len).await?;

    let header = CacheHeader {
        dirty: false,
        block_size: layout.block_size,
        total_blocks: layout.total_blocks,
        identity_len: identity_len as u32,
    }
    .encode_prefix();

    cache.write_at(0, &header).await?;
    cache
        .write_at(CACHE_PREFIX_LEN as u64, identity.as_bytes())
        .await?;
    write_zero_region(cache, mapping.bitmap_offset, layout.bitmap_bytes).await?;
    cache.flush().await?;

    trace!(
        block_size = layout.block_size,
        total_blocks = layout.total_blocks,
        identity_len,
        "cache file initialized"
    );

    Ok(OpenedCache {
        mapping,
        valid: vec![0u8; layout.bitmap_len_usize()],
    })
}

async fn write_dirty_flag<C: CacheOps>(cache: &C, dirty: bool) -> GibbloxResult<()> {
    let value = [if dirty { 1u8 } else { 0u8 }];
    cache.write_at(CACHE_DIRTY_OFFSET, &value).await
}

async fn read_exact_at<C: CacheOps>(
    cache: &C,
    mut offset: u64,
    out: &mut [u8],
) -> GibbloxResult<bool> {
    let mut filled = 0usize;
    while filled < out.len() {
        let read = cache.read_at(offset, &mut out[filled..]).await?;
        if read == 0 {
            return Ok(false);
        }
        filled = filled.checked_add(read).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read size overflow")
        })?;
        offset = offset.checked_add(read as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read offset overflow")
        })?;
    }
    Ok(true)
}

async fn write_zero_region<C: CacheOps>(cache: &C, mut offset: u64, len: u64) -> GibbloxResult<()> {
    if len == 0 {
        return Ok(());
    }
    let mut remaining = len;
    let zero = [0u8; ZERO_CHUNK_LEN];
    while remaining > 0 {
        let write_len = remaining.min(ZERO_CHUNK_LEN as u64) as usize;
        cache.write_at(offset, &zero[..write_len]).await?;
        offset = offset.checked_add(write_len as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "zero-fill offset overflow")
        })?;
        remaining -= write_len as u64;
    }
    Ok(())
}

struct InFlight {
    waiters: BTreeMap<u64, Vec<oneshot::Sender<()>>>,
}

impl InFlight {
    fn new() -> Self {
        Self {
            waiters: BTreeMap::new(),
        }
    }
}

struct CacheState {
    valid: Vec<u8>,
    dirty: bool,
    batches_since_flush: u32,
}

fn bit_is_set(bits: &[u8], idx: u64) -> bool {
    let byte_idx = (idx / 8) as usize;
    let mask = 1u8 << (idx % 8);
    bits[byte_idx] & mask != 0
}

fn set_bits(bits: &mut [u8], start: u64, len: u64) {
    for idx in start..start + len {
        let byte_idx = (idx / 8) as usize;
        let mask = 1u8 << (idx % 8);
        bits[byte_idx] |= mask;
    }
}

fn clear_bits(bits: &mut [u8], start: u64, len: u64) {
    for idx in start..start + len {
        let byte_idx = (idx / 8) as usize;
        let mask = 1u8 << (idx % 8);
        bits[byte_idx] &= !mask;
    }
}

/// In-memory cache file implementation useful for tests and embedded callers.
pub struct MemoryCacheOps {
    state: SpinLock<Vec<u8>>,
}

impl MemoryCacheOps {
    pub fn new() -> Self {
        Self {
            state: SpinLock::new(Vec::new()),
        }
    }
}

impl Default for MemoryCacheOps {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheOps for MemoryCacheOps {
    async fn read_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let guard = self.state.lock();
        let start = match usize::try_from(offset) {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        if start >= guard.len() {
            return Ok(0);
        }
        let available = guard.len() - start;
        let copy_len = available.min(out.len());
        out[..copy_len].copy_from_slice(&guard[start..start + copy_len]);
        Ok(copy_len)
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> GibbloxResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut guard = self.state.lock();
        let start = usize::try_from(offset).map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset exceeds memory cache")
        })?;
        let end = start.checked_add(data.len()).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "write overflow")
        })?;
        if end > guard.len() {
            guard.resize(end, 0);
        }
        guard[start..end].copy_from_slice(data);
        Ok(())
    }

    async fn set_len(&self, len: u64) -> GibbloxResult<()> {
        let len = usize::try_from(len).map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "length exceeds memory cache")
        })?;
        let mut guard = self.state.lock();
        guard.resize(len, 0);
        Ok(())
    }

    async fn flush(&self) -> GibbloxResult<()> {
        Ok(())
    }
}

/// Minimal spin-based lock suitable for short critical sections in `no_std + alloc`.
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
        SpinLockGuard { lock: self }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> core::ops::Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: protected by `SpinLock::lock` and released in guard drop.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> core::ops::DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: protected by `SpinLock::lock` and released in guard drop.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// A tiny async lock built on top of `SpinLock` and oneshot waiters.
pub struct AsyncLock {
    state: SpinLock<AsyncLockState>,
}

struct AsyncLockState {
    locked: bool,
    waiters: Vec<oneshot::Sender<()>>,
}

impl AsyncLock {
    pub fn new() -> Self {
        Self {
            state: SpinLock::new(AsyncLockState {
                locked: false,
                waiters: Vec::new(),
            }),
        }
    }

    pub async fn lock(&self) -> AsyncLockGuard<'_> {
        loop {
            let waiter = {
                let mut guard = self.state.lock();
                if !guard.locked {
                    guard.locked = true;
                    None
                } else {
                    let (tx, rx) = oneshot::channel();
                    guard.waiters.push(tx);
                    Some(rx)
                }
            };

            if let Some(waiter) = waiter {
                let _ = waiter.await;
                continue;
            }

            return AsyncLockGuard { lock: self };
        }
    }

    fn unlock(&self) {
        let maybe_next = {
            let mut guard = self.state.lock();
            if let Some(next) = guard.waiters.pop() {
                Some(next)
            } else {
                guard.locked = false;
                None
            }
        };
        if let Some(next) = maybe_next {
            let _ = next.send(());
        }
    }
}

impl Default for AsyncLock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AsyncLockGuard<'a> {
    lock: &'a AsyncLock,
}

impl Drop for AsyncLockGuard<'_> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}
