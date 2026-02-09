#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{collections::BTreeMap, format, vec::Vec};
use async_trait::async_trait;
use core::fmt;
use futures_channel::oneshot;
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use tracing::{debug, trace};

#[derive(Clone, Copy, Debug)]
pub struct PagedLruConfig {
    pub page_blocks: u64,
    pub max_pages: usize,
}

impl Default for PagedLruConfig {
    fn default() -> Self {
        Self {
            page_blocks: 1024,
            max_pages: 100,
        }
    }
}

struct PageEntry {
    data: Vec<u8>,
}

struct State {
    pages: BTreeMap<u64, PageEntry>,
    lru: Vec<u64>,
    hits: u64,
    misses: u64,
    evictions: u64,
    last_stats_log: u64,
}

impl State {
    fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            lru: Vec::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
            last_stats_log: 0,
        }
    }

    fn touch_lru(&mut self, page_idx: u64) {
        if let Some(pos) = self.lru.iter().position(|p| *p == page_idx) {
            self.lru.remove(pos);
        }
        self.lru.push(page_idx);
    }

    fn maybe_log_stats(&mut self) {
        let total = self.hits + self.misses;
        if total == 0 || total.saturating_sub(self.last_stats_log) < 1000 {
            return;
        }
        self.last_stats_log = total;
        let hit_rate = (self.hits as f64 / total as f64) * 100.0;
        debug!(
            hits = self.hits,
            misses = self.misses,
            evictions = self.evictions,
            resident_pages = self.pages.len(),
            hit_rate = format!("{hit_rate:.1}%"),
            "paged LRU statistics"
        );
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

pub struct PagedLruBlockReader<S> {
    inner: S,
    block_size: u32,
    total_blocks: u64,
    config: PagedLruConfig,
    state: SpinLock<State>,
    in_flight: SpinLock<InFlight>,
}

impl<S> PagedLruBlockReader<S>
where
    S: BlockReader,
{
    pub async fn new(inner: S, config: PagedLruConfig) -> GibbloxResult<Self> {
        if config.page_blocks == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "page_blocks must be non-zero",
            ));
        }
        if config.max_pages == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "max_pages must be non-zero",
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
        debug!(
            page_blocks = config.page_blocks,
            max_pages = config.max_pages,
            page_bytes = config.page_blocks.saturating_mul(block_size as u64),
            total_blocks,
            "paged LRU reader initialized"
        );
        Ok(Self {
            inner,
            block_size,
            total_blocks,
            config,
            state: SpinLock::new(State::new()),
            in_flight: SpinLock::new(InFlight::new()),
        })
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
        let block_size = self.block_size as usize;
        if !len.is_multiple_of(block_size) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok((len / block_size) as u64)
    }

    fn page_for_block(&self, block: u64) -> u64 {
        block / self.config.page_blocks
    }

    fn page_bounds(&self, page_idx: u64) -> GibbloxResult<(u64, u64)> {
        let start = page_idx
            .checked_mul(self.config.page_blocks)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "page overflow")
            })?;
        if start >= self.total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "page starts past end of image",
            ));
        }
        let remaining = self.total_blocks - start;
        Ok((start, self.config.page_blocks.min(remaining)))
    }

    fn is_page_cached(&self, page_idx: u64) -> bool {
        let mut state = self.state.lock();
        if state.pages.contains_key(&page_idx) {
            state.hits = state.hits.saturating_add(1);
            state.touch_lru(page_idx);
            state.maybe_log_stats();
            return true;
        }
        false
    }

    async fn ensure_page_cached(&self, page_idx: u64, ctx: ReadContext) -> GibbloxResult<()> {
        loop {
            if self.is_page_cached(page_idx) {
                return Ok(());
            }

            let waiter = {
                let mut guard = self.in_flight.lock();
                if let Some(waiters) = guard.waiters.get_mut(&page_idx) {
                    let (tx, rx) = oneshot::channel();
                    waiters.push(tx);
                    Some(rx)
                } else {
                    guard.waiters.insert(page_idx, Vec::new());
                    None
                }
            };

            if let Some(waiter) = waiter {
                let _ = waiter.await;
                continue;
            }

            let fetch_result = self.fetch_page(page_idx, ctx).await;
            let waiters = {
                let mut guard = self.in_flight.lock();
                guard.waiters.remove(&page_idx).unwrap_or_default()
            };
            for waiter in waiters {
                let _ = waiter.send(());
            }
            fetch_result?;
            return Ok(());
        }
    }

    async fn fetch_page(&self, page_idx: u64, ctx: ReadContext) -> GibbloxResult<()> {
        let (start_block, blocks) = self.page_bounds(page_idx)?;
        let bytes = (blocks as usize)
            .checked_mul(self.block_size as usize)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "page too large")
            })?;
        let mut data = vec![0u8; bytes];
        let read = self.inner.read_blocks(start_block, &mut data, ctx).await?;
        if read != data.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "inner source returned short read",
            ));
        }

        let mut state = self.state.lock();
        state.misses = state.misses.saturating_add(1);
        if state.pages.contains_key(&page_idx) {
            state.touch_lru(page_idx);
            state.maybe_log_stats();
            return Ok(());
        }

        if state.pages.len() >= self.config.max_pages {
            if !state.lru.is_empty() {
                let evicted = state.lru.remove(0);
                state.pages.remove(&evicted);
                state.evictions = state.evictions.saturating_add(1);
                trace!(evicted_page = evicted, "paged LRU evicted page");
            }
        }

        state.pages.insert(page_idx, PageEntry { data });
        state.touch_lru(page_idx);
        state.maybe_log_stats();
        trace!(
            page_idx,
            start_block,
            blocks,
            page_bytes = bytes,
            resident_pages = state.pages.len(),
            "paged LRU fetched page"
        );
        Ok(())
    }
}

#[async_trait]
impl<S> BlockReader for PagedLruBlockReader<S>
where
    S: BlockReader,
{
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.total_blocks)
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        out.write_str("paged-lru:(")?;
        self.inner.write_identity(out)?;
        out.write_str(")")
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

        let req_start = lba;
        let req_end = lba + blocks;
        let first_page = self.page_for_block(req_start);
        let last_page = self.page_for_block(req_end - 1);

        for page_idx in first_page..=last_page {
            self.ensure_page_cached(page_idx, ctx).await?;
        }

        let block_size = self.block_size as usize;
        for page_idx in first_page..=last_page {
            let page_start = page_idx * self.config.page_blocks;
            let page_end = (page_start + self.config.page_blocks).min(self.total_blocks);
            let copy_start = req_start.max(page_start);
            let copy_end = req_end.min(page_end);
            if copy_start >= copy_end {
                continue;
            }

            let src_block_offset = (copy_start - page_start) as usize;
            let src_byte_start = src_block_offset.checked_mul(block_size).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source offset overflow")
            })?;
            let copy_blocks = (copy_end - copy_start) as usize;
            let copy_bytes = copy_blocks.checked_mul(block_size).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "copy size overflow")
            })?;
            let src_byte_end = src_byte_start.checked_add(copy_bytes).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source end overflow")
            })?;

            let dst_block_offset = (copy_start - req_start) as usize;
            let dst_byte_start = dst_block_offset.checked_mul(block_size).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "dest offset overflow")
            })?;
            let dst_byte_end = dst_byte_start.checked_add(copy_bytes).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "dest end overflow")
            })?;

            {
                let mut state = self.state.lock();
                let Some(entry) = state.pages.get(&page_idx) else {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "page missing after cache population",
                    ));
                };
                buf[dst_byte_start..dst_byte_end]
                    .copy_from_slice(&entry.data[src_byte_start..src_byte_end]);
                state.touch_lru(page_idx);
            }
        }

        Ok(buf.len())
    }
}

/// Minimal spin-based lock suitable for short critical sections in `no_std + alloc`.
pub struct SpinLock<T> {
    locked: core::sync::atomic::AtomicBool,
    value: core::cell::UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: core::sync::atomic::AtomicBool::new(false),
            value: core::cell::UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            while self.locked.load(core::sync::atomic::Ordering::Relaxed) {
                core::hint::spin_loop();
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
        self.lock
            .locked
            .store(false, core::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{PagedLruBlockReader, PagedLruConfig};
    use crate::SpinLock;
    use alloc::{sync::Arc, vec, vec::Vec};
    use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct FakeReader {
        block_size: u32,
        total_blocks: u64,
        data: Vec<u8>,
        call_count: Arc<AtomicUsize>,
        read_sizes: Arc<SpinLock<Vec<usize>>>,
        gate: Option<Arc<Notify>>,
    }

    impl FakeReader {
        fn new(block_size: u32, total_blocks: u64, gate: Option<Arc<Notify>>) -> Self {
            let mut data = Vec::new();
            let total_bytes = (block_size as usize) * (total_blocks as usize);
            for i in 0..total_bytes {
                data.push((i % 251) as u8);
            }
            Self {
                block_size,
                total_blocks,
                data,
                call_count: Arc::new(AtomicUsize::new(0)),
                read_sizes: Arc::new(SpinLock::new(Vec::new())),
                gate,
            }
        }

        fn calls(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.call_count)
        }

        fn sizes(&self) -> Arc<SpinLock<Vec<usize>>> {
            Arc::clone(&self.read_sizes)
        }
    }

    #[async_trait::async_trait]
    impl BlockReader for FakeReader {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        async fn total_blocks(&self) -> GibbloxResult<u64> {
            Ok(self.total_blocks)
        }

        fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
            out.write_str("fake")
        }

        async fn read_blocks(
            &self,
            lba: u64,
            buf: &mut [u8],
            _ctx: ReadContext,
        ) -> GibbloxResult<usize> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            self.read_sizes.lock().push(buf.len());
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            let start = (lba as usize)
                .checked_mul(self.block_size as usize)
                .ok_or_else(|| {
                    GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
                })?;
            let end = start.checked_add(buf.len()).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range overflow")
            })?;
            if end > self.data.len() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "read exceeds backing store",
                ));
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(buf.len())
        }
    }

    #[tokio::test]
    async fn small_reads_collapse_to_one_page_fetch() {
        let source = FakeReader::new(512, 16_384, None);
        let calls = source.calls();
        let sizes = source.sizes();
        let reader = PagedLruBlockReader::new(
            source,
            PagedLruConfig {
                page_blocks: 1024,
                max_pages: 100,
            },
        )
        .await
        .expect("build paged reader");

        let mut a = vec![0u8; 4096];
        reader
            .read_blocks(12, &mut a, ReadContext::FOREGROUND)
            .await
            .expect("first read");
        let mut b = vec![0u8; 4096];
        reader
            .read_blocks(16, &mut b, ReadContext::FOREGROUND)
            .await
            .expect("second read");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(sizes.lock().as_slice(), &[1024 * 512]);
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn crossing_pages_fetches_each_page_once() {
        let source = FakeReader::new(512, 16_384, None);
        let calls = source.calls();
        let sizes = source.sizes();
        let reader = PagedLruBlockReader::new(
            source,
            PagedLruConfig {
                page_blocks: 1024,
                max_pages: 100,
            },
        )
        .await
        .expect("build paged reader");

        let mut buf = vec![0u8; 4096];
        reader
            .read_blocks(1023, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("cross-page read");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(sizes.lock().as_slice(), &[1024 * 512, 1024 * 512]);
    }

    #[tokio::test]
    async fn eviction_refetches_old_pages() {
        let source = FakeReader::new(512, 16_384, None);
        let calls = source.calls();
        let reader = PagedLruBlockReader::new(
            source,
            PagedLruConfig {
                page_blocks: 1024,
                max_pages: 1,
            },
        )
        .await
        .expect("build paged reader");

        let mut buf = vec![0u8; 4096];
        reader
            .read_blocks(0, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read page 0");
        reader
            .read_blocks(1024, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read page 1");
        reader
            .read_blocks(0, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read page 0 again");

        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn in_flight_dedupes_concurrent_page_miss() {
        let gate = Arc::new(Notify::new());
        let source = FakeReader::new(512, 16_384, Some(Arc::clone(&gate)));
        let calls = source.calls();
        let reader = Arc::new(
            PagedLruBlockReader::new(
                source,
                PagedLruConfig {
                    page_blocks: 1024,
                    max_pages: 100,
                },
            )
            .await
            .expect("build paged reader"),
        );

        let a_reader = Arc::clone(&reader);
        let b_reader = Arc::clone(&reader);
        let task_a = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            a_reader
                .read_blocks(4, &mut buf, ReadContext::FOREGROUND)
                .await
                .expect("read a");
        });
        let task_b = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            b_reader
                .read_blocks(8, &mut buf, ReadContext::FOREGROUND)
                .await
                .expect("read b");
        });

        tokio::task::yield_now().await;
        gate.notify_waiters();

        let _ = task_a.await;
        let _ = task_b.await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
