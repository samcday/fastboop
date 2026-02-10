extern crate alloc;

use alloc::{boxed::Box, sync::Arc};
use async_trait::async_trait;
use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use futures_channel::mpsc::{self, Receiver, Sender};
use futures_util::stream::StreamExt;
use gibblox_core::{BlockReader, GibbloxResult, ReadContext};
use tracing::{debug, trace};

use crate::{CacheStats, CachedBlockReader};

/// Configuration for greedy prefetch behavior.
#[derive(Clone, Copy, Debug)]
pub struct GreedyConfig {
    /// Size of warm window around each foreground access (in blocks).
    pub hot_window_size: u64,

    /// Batch size for hot worker fetches (in blocks).
    pub hot_batch_size: u64,

    /// Capacity of bounded channel for hot worker hints.
    pub hot_channel_capacity: usize,

    /// Chunk size for sweep worker fetches (in blocks).
    pub sweep_chunk_size: u64,
}

impl Default for GreedyConfig {
    fn default() -> Self {
        Self {
            hot_window_size: 40_000, // ~20MB @ 512B blocks
            hot_batch_size: 2048,    // ~1MB @ 512B blocks
            hot_channel_capacity: 100,
            sweep_chunk_size: 4096, // ~2MB @ 512B blocks
        }
    }
}

/// Background worker futures that must be spawned by the caller.
pub struct GreedyWorkers {
    pub hot_worker: Pin<Box<dyn Future<Output = ()> + Send>>,
    pub sweep_workers: [Pin<Box<dyn Future<Output = ()> + Send>>; 4],
}

/// Cached block reader with eager background prefetching.
///
/// Wraps a `CachedBlockReader` and spawns background workers that:
/// - Hot worker: Widens windows around recent foreground access
/// - Sweep workers: Methodically download the entire image
///
/// The reader itself implements `BlockReader` and serves foreground reads
/// with high priority while workers fetch in the background.
pub struct GreedyCachedBlockReader<S, C> {
    inner: Arc<CachedBlockReader<S, C>>,
    hot_tx: Sender<u64>,
}

impl<S, C> GreedyCachedBlockReader<S, C>
where
    S: BlockReader + Send + 'static,
    C: crate::CacheOps + Send + 'static,
{
    /// Create a new greedy cached reader and return background worker futures.
    ///
    /// The caller must spawn the returned workers using their preferred async runtime:
    /// - Native: `tokio::spawn(workers.hot_worker);`
    /// - WASM: `wasm_bindgen_futures::spawn_local(workers.hot_worker);`
    pub async fn new(
        inner: CachedBlockReader<S, C>,
        config: GreedyConfig,
    ) -> GibbloxResult<(Self, GreedyWorkers)> {
        let inner = Arc::new(inner);
        let total_blocks = inner.total_blocks().await?;

        debug!(
            total_blocks,
            hot_window_size = config.hot_window_size,
            hot_batch_size = config.hot_batch_size,
            sweep_chunk_size = config.sweep_chunk_size,
            "creating greedy cached block reader"
        );

        // Create bounded channel for hot worker
        let (hot_tx, hot_rx) = mpsc::channel(config.hot_channel_capacity);

        // Create hot worker future
        let hot_worker_future = {
            let inner = inner.clone();
            Box::pin(hot_worker_loop(inner, hot_rx, config))
        };

        // Create 4 sweep workers with quarter partitions
        let sweep_layout = compute_sweep_workers(total_blocks);
        let sweep_futures: [Pin<Box<dyn Future<Output = ()> + Send>>; 4] = [
            {
                let (start, end) = sweep_layout[0];
                let inner = inner.clone();
                Box::pin(sweep_worker_loop(
                    inner,
                    start,
                    end,
                    config.sweep_chunk_size,
                )) as Pin<Box<dyn Future<Output = ()> + Send>>
            },
            {
                let (start, end) = sweep_layout[1];
                let inner = inner.clone();
                Box::pin(sweep_worker_loop(
                    inner,
                    start,
                    end,
                    config.sweep_chunk_size,
                )) as Pin<Box<dyn Future<Output = ()> + Send>>
            },
            {
                let (start, end) = sweep_layout[2];
                let inner = inner.clone();
                Box::pin(sweep_worker_loop(
                    inner,
                    start,
                    end,
                    config.sweep_chunk_size,
                )) as Pin<Box<dyn Future<Output = ()> + Send>>
            },
            {
                let (start, end) = sweep_layout[3];
                let inner = inner.clone();
                Box::pin(sweep_worker_loop(
                    inner,
                    start,
                    end,
                    config.sweep_chunk_size,
                )) as Pin<Box<dyn Future<Output = ()> + Send>>
            },
        ];

        let reader = Self { inner, hot_tx };
        let workers = GreedyWorkers {
            hot_worker: hot_worker_future,
            sweep_workers: sweep_futures,
        };

        Ok((reader, workers))
    }

    /// Return a snapshot of cache statistics.
    pub async fn get_stats(&self) -> GibbloxResult<CacheStats> {
        Ok(self.inner.get_stats().await)
    }
}

#[async_trait]
impl<S, C> BlockReader for GreedyCachedBlockReader<S, C>
where
    S: BlockReader + Send + 'static,
    C: crate::CacheOps + Send + 'static,
{
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        self.inner.total_blocks().await
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        out.write_str("greedy:(")?;
        self.inner.write_identity(out)?;
        out.write_str(")")
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        _ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        // Send hint to hot worker (non-blocking, drops if channel full)
        let _ = self.hot_tx.clone().try_send(lba);

        // Serve read from cache with HIGH priority
        self.inner
            .read_blocks(lba, buf, ReadContext::FOREGROUND)
            .await
    }
}

/// Yield control to the async executor.
///
/// This is critical for cooperative multitasking (wasm32) where workers must
/// explicitly yield to prevent monopolizing the single-threaded event loop.
/// On native runtimes (tokio), this still helps maintain fairness.
async fn yield_now() {
    struct YieldNow {
        yielded: bool,
    }

    impl Future for YieldNow {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    YieldNow { yielded: false }.await
}

/// Compute starting positions for 4 sweep workers.
///
/// Layout:
/// - Worker 0: Q1 [0, 25%), forward
/// - Worker 1: Q4 [75%, 100%), backward from end
/// - Worker 2: Q2 [25%, 50%), forward
/// - Worker 3: Q3 [50%, 75%), backward from 75% mark
fn compute_sweep_workers(total_blocks: u64) -> [(u64, u64); 4] {
    let quarter = total_blocks / 4;

    [
        // Worker 0: Q1 forward
        (0, quarter),
        // Worker 1: Q4 backward (start at end, move toward 3*quarter)
        (total_blocks.saturating_sub(1), 3 * quarter),
        // Worker 2: Q2 forward
        (quarter, 2 * quarter),
        // Worker 3: Q3 backward (start at 3*quarter, move toward 2*quarter)
        (3 * quarter, 2 * quarter),
    ]
}

/// Hot worker loop: reacts to foreground access, widens windows.
async fn hot_worker_loop<S, C>(
    inner: Arc<CachedBlockReader<S, C>>,
    mut rx: Receiver<u64>,
    config: GreedyConfig,
) where
    S: BlockReader,
    C: crate::CacheOps,
{
    debug!("hot worker started");

    loop {
        // Wait for first hint
        let Some(mut current_lba) = rx.next().await else {
            debug!("hot worker channel closed, exiting");
            break;
        };

        // Drain channel to get freshest lba (discard stale hints)
        loop {
            match rx.try_next() {
                Ok(Some(newer_lba)) => {
                    current_lba = newer_lba;
                }
                Ok(None) => {
                    // Channel closed
                    debug!("hot worker channel closed during drain, exiting");
                    return;
                }
                Err(_) => {
                    // Channel empty, we have the freshest lba
                    break;
                }
            }
        }

        trace!(lba = current_lba, "hot worker warming window");

        // Widen window around current_lba
        let total_blocks = match inner.total_blocks().await {
            Ok(b) => b,
            Err(e) => {
                debug!(error = ?e, "hot worker failed to get total_blocks");
                continue;
            }
        };

        let half_window = config.hot_window_size / 2;
        let start = current_lba.saturating_sub(half_window);
        let end = (current_lba + half_window).min(total_blocks);

        let mut cursor = start;
        while cursor < end {
            let batch = config.hot_batch_size.min(end - cursor);

            // Fetch with MEDIUM priority
            match inner
                .ensure_cached(cursor, batch, ReadContext::READAHEAD)
                .await
            {
                Ok(()) => {
                    trace!(lba = cursor, blocks = batch, "hot worker ensured cached");
                }
                Err(e) => {
                    debug!(error = ?e, lba = cursor, "hot worker ensure_cached failed");
                }
            }

            cursor += batch;

            // Yield to executor after every batch (critical for cooperative runtimes)
            yield_now().await;

            // Break early if new hint arrived (react to fresh access)
            match rx.try_next() {
                Ok(Some(_)) | Ok(None) => {
                    // New data or channel closed, break to outer loop
                    break;
                }
                Err(_) => {
                    // Channel empty, continue widening
                }
            }
        }
    }
}

/// Sweep worker loop: methodically downloads a partition.
async fn sweep_worker_loop<S, C>(
    inner: Arc<CachedBlockReader<S, C>>,
    start: u64,
    end: u64,
    chunk_size: u64,
) where
    S: BlockReader,
    C: crate::CacheOps,
{
    // Infer direction from start/end relationship
    let forward = start <= end;
    let direction_str = if forward { "forward" } else { "backward" };

    debug!(
        start,
        end,
        direction = direction_str,
        chunk_size,
        "sweep worker started"
    );

    let mut cursor = start;

    loop {
        // Determine batch size and fetch LBA based on direction
        let (fetch_lba, batch) = if forward {
            if cursor >= end {
                debug!(
                    start,
                    end,
                    final_cursor = cursor,
                    "sweep worker completed (forward)"
                );
                break;
            }
            let batch = chunk_size.min(end - cursor);
            (cursor, batch)
        } else {
            if cursor <= end {
                debug!(
                    start,
                    end,
                    final_cursor = cursor,
                    "sweep worker completed (backward)"
                );
                break;
            }
            let batch = chunk_size.min(cursor - end);
            (cursor.saturating_sub(batch), batch)
        };

        // Fetch with LOW priority
        match inner
            .ensure_cached(fetch_lba, batch, ReadContext::BACKGROUND)
            .await
        {
            Ok(()) => {
                trace!(
                    lba = fetch_lba,
                    blocks = batch,
                    "sweep worker ensured cached"
                );
            }
            Err(e) => {
                debug!(error = ?e, lba = fetch_lba, "sweep worker ensure_cached failed");
            }
        }

        // Advance cursor
        cursor = if forward {
            cursor + batch
        } else {
            cursor.saturating_sub(batch)
        };

        // Yield to executor after every batch (critical for cooperative runtimes)
        yield_now().await;
    }
}
