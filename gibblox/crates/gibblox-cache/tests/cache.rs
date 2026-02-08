use gibblox_cache::{CachedBlockReader, MemoryCacheOps};
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

struct FakeReader {
    block_size: u32,
    total_blocks: u64,
    identity: &'static str,
    data: Vec<u8>,
    reads: Arc<AtomicUsize>,
    gate: Option<Arc<Notify>>,
}

impl FakeReader {
    fn new(block_size: u32, total_blocks: u64, gate: Option<Arc<Notify>>) -> Self {
        Self::new_with_identity("fake://disk/default", block_size, total_blocks, gate)
    }

    fn new_with_identity(
        identity: &'static str,
        block_size: u32,
        total_blocks: u64,
        gate: Option<Arc<Notify>>,
    ) -> Self {
        let mut data = Vec::new();
        let total_bytes = (block_size as usize) * (total_blocks as usize);
        for i in 0..total_bytes {
            data.push((i % 251) as u8);
        }
        Self {
            block_size,
            total_blocks,
            identity,
            data,
            reads: Arc::new(AtomicUsize::new(0)),
            gate,
        }
    }

    fn read_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.reads)
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
        write!(
            out,
            "{}:{}:{}",
            self.identity, self.block_size, self.total_blocks
        )
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        _ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.notified().await;
        }
        let block_size = self.block_size as usize;
        if !buf.len().is_multiple_of(block_size) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })? as usize;
        let end = offset + buf.len();
        if end > self.data.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "read exceeds backing store",
            ));
        }
        buf.copy_from_slice(&self.data[offset..end]);
        Ok(buf.len())
    }
}

#[tokio::test]
async fn cache_hit_after_miss() {
    let reader = FakeReader::new(512, 16, None);
    let reads = reader.read_counter();
    let cache = MemoryCacheOps::new();
    let cached = CachedBlockReader::new(reader, cache)
        .await
        .expect("cached source");

    let mut buf = vec![0u8; 1024];
    let read = cached
        .read_blocks(2, &mut buf, ReadContext::FOREGROUND)
        .await
        .expect("read blocks");
    assert_eq!(read, buf.len());
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    let mut buf2 = vec![0u8; 1024];
    let read2 = cached
        .read_blocks(2, &mut buf2, ReadContext::FOREGROUND)
        .await
        .expect("read blocks");
    assert_eq!(read2, buf2.len());
    assert_eq!(buf, buf2);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cache_inflight_dedupes_reads() {
    let gate = Arc::new(Notify::new());
    let reader = FakeReader::new(512, 8, Some(Arc::clone(&gate)));
    let reads = reader.read_counter();
    let cache = MemoryCacheOps::new();
    let cached = Arc::new(
        CachedBlockReader::new(reader, cache)
            .await
            .expect("cached source"),
    );

    let cached_a = Arc::clone(&cached);
    let cached_b = Arc::clone(&cached);
    let task_a = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        cached_a
            .read_blocks(1, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read a");
    });
    let task_b = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        cached_b
            .read_blocks(1, &mut buf, ReadContext::FOREGROUND)
            .await
            .expect("read b");
    });

    tokio::task::yield_now().await;
    gate.notify_waiters();

    let _ = task_a.await;
    let _ = task_b.await;

    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cache_persists_across_instances_after_flush() {
    let cache = Arc::new(MemoryCacheOps::new());

    let reader_a = FakeReader::new(512, 4, None);
    let reads_a = reader_a.read_counter();
    let cached_a = CachedBlockReader::new(reader_a, Arc::clone(&cache))
        .await
        .expect("cached source A");

    let mut first = vec![0u8; 512];
    cached_a
        .read_blocks(0, &mut first, ReadContext::FOREGROUND)
        .await
        .expect("read A");
    assert_eq!(reads_a.load(Ordering::SeqCst), 1);
    cached_a.flush_cache().await.expect("flush cache A");
    drop(cached_a);

    let reader_b = FakeReader::new(512, 4, None);
    let reads_b = reader_b.read_counter();
    let cached_b = CachedBlockReader::new(reader_b, Arc::clone(&cache))
        .await
        .expect("cached source B");

    let mut second = vec![0u8; 512];
    cached_b
        .read_blocks(0, &mut second, ReadContext::FOREGROUND)
        .await
        .expect("read B");
    assert_eq!(reads_b.load(Ordering::SeqCst), 0);
    assert_eq!(first, second);
}

#[tokio::test]
async fn dirty_on_open_clears_bitmap() {
    let cache = Arc::new(MemoryCacheOps::new());

    let reader_a = FakeReader::new(512, 4, None);
    let reads_a = reader_a.read_counter();
    let cached_a = CachedBlockReader::new(reader_a, Arc::clone(&cache))
        .await
        .expect("cached source A");

    let mut first = vec![0u8; 512];
    cached_a
        .read_blocks(0, &mut first, ReadContext::FOREGROUND)
        .await
        .expect("read A");
    assert_eq!(reads_a.load(Ordering::SeqCst), 1);
    drop(cached_a);

    let reader_b = FakeReader::new(512, 4, None);
    let reads_b = reader_b.read_counter();
    let cached_b = CachedBlockReader::new(reader_b, Arc::clone(&cache))
        .await
        .expect("cached source B");

    let mut second = vec![0u8; 512];
    cached_b
        .read_blocks(0, &mut second, ReadContext::FOREGROUND)
        .await
        .expect("read B");
    assert_eq!(reads_b.load(Ordering::SeqCst), 1);
    assert_eq!(first, second);
}

#[tokio::test]
async fn identity_mismatch_resets_cache_file() {
    let cache = Arc::new(MemoryCacheOps::new());

    let reader_a = FakeReader::new_with_identity("fake://disk/id-a", 512, 4, None);
    let cached_a = CachedBlockReader::new(reader_a, Arc::clone(&cache))
        .await
        .expect("cached source A");
    let mut first = vec![0u8; 512];
    cached_a
        .read_blocks(1, &mut first, ReadContext::FOREGROUND)
        .await
        .expect("read A");
    cached_a.flush_cache().await.expect("flush cache A");

    let reader_b = FakeReader::new_with_identity("fake://disk/id-b", 512, 4, None);
    let reads_b = reader_b.read_counter();
    let cached_b = CachedBlockReader::new(reader_b, Arc::clone(&cache))
        .await
        .expect("cached source B");

    let mut second = vec![0u8; 512];
    cached_b
        .read_blocks(1, &mut second, ReadContext::FOREGROUND)
        .await
        .expect("read B");
    assert_eq!(reads_b.load(Ordering::SeqCst), 1);
    assert_eq!(first, second);

    let mut third = vec![0u8; 512];
    cached_b
        .read_blocks(1, &mut third, ReadContext::FOREGROUND)
        .await
        .expect("read C");
    assert_eq!(reads_b.load(Ordering::SeqCst), 1);
    assert_eq!(second, third);
}
