use alloc::{boxed::Box, collections::BTreeMap, format, vec, vec::Vec};
use async_lock::Mutex;
use core::fmt;
use futures_channel::oneshot;
use tracing::{debug, trace};

use crate::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};

#[derive(Clone, Copy, Debug)]
pub struct LruConfig {
    pub max_entries: usize,
}

impl Default for LruConfig {
    fn default() -> Self {
        Self { max_entries: 100 }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CacheKey {
    lba: u64,
    blocks: u64,
}

struct CacheEntry {
    data: Vec<u8>,
}

struct LruState {
    entries: BTreeMap<CacheKey, CacheEntry>,
    lru: Vec<CacheKey>,
    hits: u64,
    misses: u64,
    evictions: u64,
    last_stats_log: u64,
}

impl LruState {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            lru: Vec::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
            last_stats_log: 0,
        }
    }

    fn touch_lru(&mut self, key: CacheKey) {
        if let Some(pos) = self.lru.iter().position(|entry| *entry == key) {
            self.lru.remove(pos);
        }
        self.lru.push(key);
    }

    fn maybe_log_stats(&mut self) {
        let total = self.hits + self.misses;
        if total == 0 || total.saturating_sub(self.last_stats_log) < 1000 {
            return;
        }
        self.last_stats_log = total;
        let hit_rate = (self.hits as f64 / total as f64) * 100.0;
        debug!(
            total_hits = self.hits,
            total_misses = self.misses,
            evictions = self.evictions,
            resident_entries = self.entries.len(),
            hit_rate = format!("{hit_rate:.1}%"),
            "lru block reader statistics"
        );
    }
}

struct InFlight {
    waiters: BTreeMap<CacheKey, Vec<oneshot::Sender<()>>>,
}

impl InFlight {
    fn new() -> Self {
        Self {
            waiters: BTreeMap::new(),
        }
    }
}

pub struct LruBlockReader<S> {
    inner: S,
    block_size: u32,
    total_blocks: u64,
    config: LruConfig,
    state: Mutex<LruState>,
    in_flight: Mutex<InFlight>,
}

impl<S> LruBlockReader<S>
where
    S: BlockReader,
{
    pub async fn new(inner: S, config: LruConfig) -> GibbloxResult<Self> {
        if config.max_entries == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "max_entries must be non-zero",
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
            max_entries = config.max_entries,
            block_size, total_blocks, "lru block reader initialized"
        );
        Ok(Self {
            inner,
            block_size,
            total_blocks,
            config,
            state: Mutex::new(LruState::new()),
            in_flight: Mutex::new(InFlight::new()),
        })
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

    fn bytes_for_key(&self, key: CacheKey) -> GibbloxResult<usize> {
        (key.blocks as usize)
            .checked_mul(self.block_size as usize)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "entry too large")
            })
    }

    async fn is_cached(&self, key: CacheKey) -> bool {
        let mut guard = self.state.lock().await;
        if guard.entries.contains_key(&key) {
            guard.hits = guard.hits.saturating_add(1);
            guard.touch_lru(key);
            guard.maybe_log_stats();
            return true;
        }
        false
    }

    async fn ensure_cached(&self, key: CacheKey, ctx: ReadContext) -> GibbloxResult<()> {
        loop {
            if self.is_cached(key).await {
                return Ok(());
            }

            let waiter = {
                let mut guard = self.in_flight.lock().await;
                if let Some(waiters) = guard.waiters.get_mut(&key) {
                    let (tx, rx) = oneshot::channel();
                    waiters.push(tx);
                    Some(rx)
                } else {
                    guard.waiters.insert(key, Vec::new());
                    None
                }
            };

            if let Some(waiter) = waiter {
                let _ = waiter.await;
                continue;
            }

            let fetch_result = self.fetch_entry(key, ctx).await;
            let waiters = {
                let mut guard = self.in_flight.lock().await;
                guard.waiters.remove(&key).unwrap_or_default()
            };
            for waiter in waiters {
                let _ = waiter.send(());
            }
            fetch_result?;
            return Ok(());
        }
    }

    async fn fetch_entry(&self, key: CacheKey, ctx: ReadContext) -> GibbloxResult<()> {
        let bytes = self.bytes_for_key(key)?;
        let mut data = vec![0u8; bytes];
        let read = self.inner.read_blocks(key.lba, &mut data, ctx).await?;
        if read != data.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "inner source returned short read",
            ));
        }

        let mut state = self.state.lock().await;
        state.misses = state.misses.saturating_add(1);

        if state.entries.contains_key(&key) {
            state.touch_lru(key);
            state.maybe_log_stats();
            return Ok(());
        }

        if state.entries.len() >= self.config.max_entries && !state.lru.is_empty() {
            let evicted = state.lru.remove(0);
            state.entries.remove(&evicted);
            state.evictions = state.evictions.saturating_add(1);
            trace!(
                evicted_lba = evicted.lba,
                evicted_blocks = evicted.blocks,
                "lru block reader evicted entry"
            );
        }

        state.entries.insert(key, CacheEntry { data });
        state.touch_lru(key);
        state.maybe_log_stats();
        trace!(
            lba = key.lba,
            blocks = key.blocks,
            entry_bytes = bytes,
            resident_entries = state.entries.len(),
            "lru block reader inserted entry"
        );
        Ok(())
    }

    async fn copy_cached(&self, key: CacheKey, out: &mut [u8]) -> GibbloxResult<()> {
        let mut state = self.state.lock().await;
        let Some(entry) = state.entries.get(&key) else {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "cache entry missing after cache population",
            ));
        };
        if entry.data.len() != out.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "cache entry size mismatch",
            ));
        }
        out.copy_from_slice(&entry.data);
        state.touch_lru(key);
        Ok(())
    }
}

#[async_trait::async_trait]
impl<S> BlockReader for LruBlockReader<S>
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
        out.write_str("lru:(")?;
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

        let key = CacheKey { lba, blocks };
        self.ensure_cached(key, ctx).await?;
        self.copy_cached(key, buf).await?;
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    use crate::{
        BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, LruBlockReader, LruConfig,
        PagedBlockConfig, PagedBlockReader, ReadContext,
    };

    struct FakeReader {
        block_size: u32,
        total_blocks: u64,
        data: Vec<u8>,
        call_count: Arc<AtomicUsize>,
        calls: Arc<Mutex<Vec<(u64, usize)>>>,
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
                calls: Arc::new(Mutex::new(Vec::new())),
                gate,
            }
        }

        fn calls(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.call_count)
        }

        fn requests(&self) -> Arc<Mutex<Vec<(u64, usize)>>> {
            Arc::clone(&self.calls)
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
            self.requests()
                .lock()
                .expect("lock fake call history")
                .push((lba, buf.len()));
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
    async fn paged_reader_fetches_whole_page_windows() {
        let source = FakeReader::new(512, 16_384, None);
        let calls = source.calls();
        let requests = source.requests();
        let reader = PagedBlockReader::new(source, PagedBlockConfig { page_blocks: 1024 })
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

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            requests.lock().expect("lock fake call history").as_slice(),
            &[(0, 1024 * 512), (0, 1024 * 512)]
        );
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn stacked_readers_collapse_small_reads_to_one_source_fetch() {
        let source = FakeReader::new(512, 16_384, None);
        let calls = source.calls();
        let requests = source.requests();

        let lru = LruBlockReader::new(source, LruConfig { max_entries: 100 })
            .await
            .expect("build lru reader");
        let reader = PagedBlockReader::new(lru, PagedBlockConfig { page_blocks: 1024 })
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
        assert_eq!(
            requests.lock().expect("lock fake call history").as_slice(),
            &[(0, 1024 * 512)]
        );
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn crossing_pages_fetches_each_page_once() {
        let source = FakeReader::new(512, 16_384, None);
        let calls = source.calls();
        let requests = source.requests();

        let lru = LruBlockReader::new(source, LruConfig { max_entries: 100 })
            .await
            .expect("build lru reader");
        let reader = PagedBlockReader::new(lru, PagedBlockConfig { page_blocks: 1024 })
            .await
            .expect("build paged reader");

        let mut buf = vec![0u8; 4096];
        reader
            .read_blocks(1023, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("cross-page read");
        reader
            .read_blocks(1023, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("cross-page read from cache");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            requests.lock().expect("lock fake call history").as_slice(),
            &[(0, 1024 * 512), (1024, 1024 * 512)]
        );
    }

    #[tokio::test]
    async fn lru_eviction_refetches_old_entries() {
        let source = FakeReader::new(512, 16_384, None);
        let calls = source.calls();
        let reader = LruBlockReader::new(source, LruConfig { max_entries: 1 })
            .await
            .expect("build lru reader");

        let mut buf = vec![0u8; 4096];
        reader
            .read_blocks(0, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read key a");
        reader
            .read_blocks(1024, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read key b");
        reader
            .read_blocks(0, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read key a again");

        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn lru_dedupes_concurrent_miss() {
        let gate = Arc::new(Notify::new());
        let source = FakeReader::new(512, 16_384, Some(Arc::clone(&gate)));
        let calls = source.calls();
        let reader = Arc::new(
            LruBlockReader::new(source, LruConfig { max_entries: 100 })
                .await
                .expect("build lru reader"),
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
                .read_blocks(4, &mut buf, ReadContext::FOREGROUND)
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
