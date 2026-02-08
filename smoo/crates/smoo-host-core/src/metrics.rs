use core::time::Duration;
use metrics::{counter, gauge, histogram};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct Stat {
    count: AtomicU64,
    bytes: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl Stat {
    fn observe(&self, bytes: usize, dur: Duration) {
        let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.total_ns.fetch_add(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    fn snapshot(&self) -> StatSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let bytes = self.bytes.load(Ordering::Relaxed);
        let total_ns = self.total_ns.load(Ordering::Relaxed);
        let max_ns = self.max_ns.load(Ordering::Relaxed);
        let avg_ns = if count == 0 {
            0.0
        } else {
            total_ns as f64 / count as f64
        };
        StatSnapshot {
            count,
            bytes,
            avg_ns,
            max_ns,
        }
    }
}

#[derive(Default)]
struct QueueStat {
    max_depth: AtomicU64,
}

impl QueueStat {
    fn record(&self, depth: usize) {
        self.max_depth.fetch_max(depth as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> QueueSnapshot {
        QueueSnapshot {
            max_depth: self.max_depth.load(Ordering::Relaxed),
        }
    }
}

static BULK_OUT: Stat = Stat {
    count: AtomicU64::new(0),
    bytes: AtomicU64::new(0),
    total_ns: AtomicU64::new(0),
    max_ns: AtomicU64::new(0),
};
static BULK_IN: Stat = Stat {
    count: AtomicU64::new(0),
    bytes: AtomicU64::new(0),
    total_ns: AtomicU64::new(0),
    max_ns: AtomicU64::new(0),
};
static INTR_OUT: Stat = Stat {
    count: AtomicU64::new(0),
    bytes: AtomicU64::new(0),
    total_ns: AtomicU64::new(0),
    max_ns: AtomicU64::new(0),
};
static INTR_IN: Stat = Stat {
    count: AtomicU64::new(0),
    bytes: AtomicU64::new(0),
    total_ns: AtomicU64::new(0),
    max_ns: AtomicU64::new(0),
};

static BULK_OUT_QUEUE: QueueStat = QueueStat {
    max_depth: AtomicU64::new(0),
};
static BULK_IN_QUEUE: QueueStat = QueueStat {
    max_depth: AtomicU64::new(0),
};

#[derive(Clone, Copy, Debug, Default)]
pub struct StatSnapshot {
    pub count: u64,
    pub bytes: u64,
    pub avg_ns: f64,
    pub max_ns: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct QueueSnapshot {
    pub max_depth: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MetricsSnapshot {
    pub bulk_out: StatSnapshot,
    pub bulk_in: StatSnapshot,
    pub interrupt_out: StatSnapshot,
    pub interrupt_in: StatSnapshot,
    pub bulk_out_queue: QueueSnapshot,
    pub bulk_in_queue: QueueSnapshot,
}

pub fn observe_bulk_out(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_bulk_out_count").increment(1);
    counter!("smoo_bulk_out_bytes").increment(bytes as u64);
    histogram!("smoo_bulk_out_latency_ns").record(ns as f64);
    BULK_OUT.observe(bytes, dur);
}

pub fn observe_bulk_in(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_bulk_in_count").increment(1);
    counter!("smoo_bulk_in_bytes").increment(bytes as u64);
    histogram!("smoo_bulk_in_latency_ns").record(ns as f64);
    BULK_IN.observe(bytes, dur);
}

pub fn observe_interrupt_out(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_interrupt_out_count").increment(1);
    counter!("smoo_interrupt_out_bytes").increment(bytes as u64);
    histogram!("smoo_interrupt_out_latency_ns").record(ns as f64);
    INTR_OUT.observe(bytes, dur);
}

pub fn observe_interrupt_in(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_interrupt_in_count").increment(1);
    counter!("smoo_interrupt_in_bytes").increment(bytes as u64);
    histogram!("smoo_interrupt_in_latency_ns").record(ns as f64);
    INTR_IN.observe(bytes, dur);
}

pub fn record_bulk_out_queue(depth: usize) {
    gauge!("smoo_bulk_out_queue_depth").set(depth as f64);
    BULK_OUT_QUEUE.record(depth);
}

pub fn record_bulk_in_queue(depth: usize) {
    gauge!("smoo_bulk_in_queue_depth").set(depth as f64);
    BULK_IN_QUEUE.record(depth);
}

pub fn snapshot() -> MetricsSnapshot {
    MetricsSnapshot {
        bulk_out: BULK_OUT.snapshot(),
        bulk_in: BULK_IN.snapshot(),
        interrupt_out: INTR_OUT.snapshot(),
        interrupt_in: INTR_IN.snapshot(),
        bulk_out_queue: BULK_OUT_QUEUE.snapshot(),
        bulk_in_queue: BULK_IN_QUEUE.snapshot(),
    }
}
