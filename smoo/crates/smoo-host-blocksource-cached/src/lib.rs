#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use async_trait::async_trait;
use core::{
    cell::UnsafeCell,
    hash::Hasher,
    hint::spin_loop,
    sync::atomic::{AtomicBool, Ordering},
};
use futures_channel::oneshot;
use smoo_host_core::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult, ExportIdentity,
};

/// Persistent storage for cached blocks.
///
/// Implementations are expected to be internally synchronized; the cache wrapper may call these
/// methods concurrently from multiple tasks.
#[async_trait]
pub trait CacheStore: Send + Sync {
    /// Logical block size in bytes.
    fn block_size(&self) -> u32;

    /// Total number of blocks that can be stored.
    fn total_blocks(&self) -> u64;

    /// Attempt to read a single cached block into `out`.
    ///
    /// Returns `Ok(true)` if the block was present and `out` has been filled. Returns `Ok(false)`
    /// when the block is not yet cached.
    async fn read_block(&self, block_idx: u64, out: &mut [u8]) -> BlockSourceResult<bool>;

    /// Write one or more contiguous blocks starting at `start_block`.
    ///
    /// `data` must be a multiple of `block_size()`.
    async fn write_blocks(&self, start_block: u64, data: &[u8]) -> BlockSourceResult<()>;
}

/// BlockSource wrapper that consults a pluggable cache store before forwarding to the inner
/// source. Misses are fetched from the inner source, written to the store, then served.
pub struct CachedBlockSource<S, C> {
    inner: S,
    cache: C,
    block_size: u32,
    total_blocks: u64,
    in_flight: SpinLock<InFlight>,
}

impl<S, C> CachedBlockSource<S, C>
where
    S: BlockSource,
    C: CacheStore,
{
    /// Construct a cached block source, verifying block size and total block invariants up front.
    pub async fn new(inner: S, cache: C) -> BlockSourceResult<Self> {
        let block_size = inner.block_size();
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        if block_size != cache.block_size() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "cache block size mismatch",
            ));
        }
        let total_blocks = inner.total_blocks().await?;
        if total_blocks != cache.total_blocks() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "cache and inner total blocks differ",
            ));
        }
        Ok(Self {
            inner,
            cache,
            block_size,
            total_blocks,
            in_flight: SpinLock::new(InFlight::new()),
        })
    }

    fn block_size_usize(&self) -> usize {
        self.block_size as usize
    }

    fn validate_range(&self, lba: u64, blocks: u64) -> BlockSourceResult<()> {
        let end = lba.checked_add(blocks).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "lba overflow")
        })?;
        if end > self.total_blocks {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::OutOfRange,
                "requested range exceeds total blocks",
            ));
        }
        Ok(())
    }

    fn blocks_from_len(&self, len: usize) -> BlockSourceResult<u64> {
        if len == 0 {
            return Ok(0);
        }
        if !len.is_multiple_of(self.block_size_usize()) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok((len / self.block_size_usize()) as u64)
    }

    async fn fill_from_cache(
        &self,
        lba: u64,
        blocks: u64,
        buf: &mut [u8],
    ) -> BlockSourceResult<Vec<u64>> {
        let mut missing = Vec::new();
        let bs = self.block_size_usize();
        for (idx, block) in (lba..lba + blocks).enumerate() {
            let start = idx * bs;
            let end = start + bs;
            let hit = self.cache.read_block(block, &mut buf[start..end]).await?;
            if !hit {
                missing.push(block);
            }
        }
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
        (to_fetch, waiters)
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

    async fn fetch_and_populate(&self, ranges: &[(u64, u64)]) -> BlockSourceResult<()> {
        let bs = self.block_size_usize();
        for (start_block, len_blocks) in ranges {
            let expected_bytes = (*len_blocks as usize).checked_mul(bs).ok_or_else(|| {
                BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "range too large")
            })?;
            let mut buf = vec![0u8; expected_bytes];
            let read = self.inner.read_blocks(*start_block, &mut buf).await?;
            if read != expected_bytes {
                return Err(BlockSourceError::with_message(
                    BlockSourceErrorKind::Io,
                    "inner source returned short read",
                ));
            }
            self.cache.write_blocks(*start_block, &buf).await?;
            let senders = {
                let mut guard = self.in_flight.lock();
                let mut senders = Vec::new();
                for block in *start_block..(*start_block + *len_blocks) {
                    if let Some(mut pending) = guard.waiters.remove(&block) {
                        senders.append(&mut pending);
                    }
                }
                senders
            };
            for sender in senders {
                let _ = sender.send(());
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<S, C> BlockSource for CachedBlockSource<S, C>
where
    S: BlockSource,
    C: CacheStore,
{
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        Ok(self.total_blocks)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        let blocks = self.blocks_from_len(buf.len())?;
        if blocks == 0 {
            return Ok(0);
        }
        self.validate_range(lba, blocks)?;
        let missing = self.fill_from_cache(lba, blocks, buf).await?;
        if missing.is_empty() {
            return Ok(buf.len());
        }
        let (to_fetch, waiters) = self.mark_in_flight(&missing);
        if !to_fetch.is_empty() {
            self.fetch_and_populate(&Self::coalesce(&to_fetch)).await?;
        }
        for waiter in waiters {
            let _ = waiter.await;
        }
        let final_missing = self.fill_from_cache(lba, blocks, buf).await?;
        if !final_missing.is_empty() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::Io,
                "cache fetch did not populate all blocks",
            ));
        }
        Ok(buf.len())
    }

    async fn write_blocks(&self, _lba: u64, _buf: &[u8]) -> BlockSourceResult<usize> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "cached block source is read-only",
        ))
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        Ok(())
    }

    async fn discard(&self, _lba: u64, _num_blocks: u32) -> BlockSourceResult<()> {
        Ok(())
    }
}

impl<S, C> ExportIdentity for CachedBlockSource<S, C>
where
    S: BlockSource + ExportIdentity,
    C: CacheStore,
{
    fn write_export_id(&self, state: &mut dyn Hasher) {
        state.write(b"cached:");
        ExportIdentity::write_export_id(&self.inner, state);
    }
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

/// In-memory `CacheStore` backed by a `Vec<u8>` and a validity bitmap.
pub struct MemoryCacheStore {
    block_size: u32,
    total_blocks: u64,
    state: SpinLock<MemoryState>,
}

struct MemoryState {
    data: Vec<u8>,
    valid: Vec<u8>,
}

impl MemoryCacheStore {
    pub fn new(block_size: u32, total_blocks: u64) -> BlockSourceResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let total_bytes = (total_blocks as u128)
            .checked_mul(block_size as u128)
            .ok_or_else(|| {
                BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "cache too large")
            })?;
        if total_bytes > usize::MAX as u128 {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::OutOfRange,
                "cache size exceeds addressable memory",
            ));
        }
        let data = vec![0u8; total_bytes as usize];
        let valid = vec![0u8; total_blocks.div_ceil(8) as usize];
        Ok(Self {
            block_size,
            total_blocks,
            state: SpinLock::new(MemoryState { data, valid }),
        })
    }

    fn block_size_usize(&self) -> usize {
        self.block_size as usize
    }

    fn offset(&self, block_idx: u64) -> BlockSourceResult<usize> {
        if block_idx >= self.total_blocks {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::OutOfRange,
                "block index out of bounds",
            ));
        }
        let byte_offset = (block_idx as usize)
            .checked_mul(self.block_size_usize())
            .ok_or_else(|| {
                BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "offset overflow")
            })?;
        Ok(byte_offset)
    }

    fn is_valid(valid: &[u8], block_idx: u64) -> bool {
        let byte_idx = (block_idx / 8) as usize;
        let mask = 1u8 << (block_idx % 8);
        valid[byte_idx] & mask != 0
    }

    fn mark_valid(valid: &mut [u8], start_block: u64, blocks: u64) {
        for block in start_block..start_block + blocks {
            let byte_idx = (block / 8) as usize;
            let mask = 1u8 << (block % 8);
            valid[byte_idx] |= mask;
        }
    }
}

#[async_trait]
impl CacheStore for MemoryCacheStore {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    async fn read_block(&self, block_idx: u64, out: &mut [u8]) -> BlockSourceResult<bool> {
        if out.len() != self.block_size_usize() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must equal block size",
            ));
        }
        let guard = self.state.lock();
        let offset = self.offset(block_idx)?;
        if !Self::is_valid(&guard.valid, block_idx) {
            return Ok(false);
        }
        out.copy_from_slice(&guard.data[offset..offset + self.block_size_usize()]);
        Ok(true)
    }

    async fn write_blocks(&self, start_block: u64, data: &[u8]) -> BlockSourceResult<()> {
        if !data.len().is_multiple_of(self.block_size_usize()) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "write payload must align to block size",
            ));
        }
        let blocks = (data.len() / self.block_size_usize()) as u64;
        if start_block
            .checked_add(blocks)
            .map(|end| end > self.total_blocks)
            .unwrap_or(true)
        {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::OutOfRange,
                "write exceeds cache bounds",
            ));
        }
        let mut guard = self.state.lock();
        let offset = self.offset(start_block)?;
        guard.data[offset..offset + data.len()].copy_from_slice(data);
        Self::mark_valid(&mut guard.valid, start_block, blocks);
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

impl<'a, T> core::ops::Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}
