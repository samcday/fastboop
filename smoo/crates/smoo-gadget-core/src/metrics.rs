use core::time::Duration;
use metrics::{counter, gauge, histogram};

pub fn observe_interrupt_in(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_gadget_interrupt_in_count").increment(1);
    counter!("smoo_gadget_interrupt_in_bytes").increment(bytes as u64);
    histogram!("smoo_gadget_interrupt_in_latency_ns").record(ns as f64);
}

pub fn observe_interrupt_out(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_gadget_interrupt_out_count").increment(1);
    counter!("smoo_gadget_interrupt_out_bytes").increment(bytes as u64);
    histogram!("smoo_gadget_interrupt_out_latency_ns").record(ns as f64);
}

pub fn observe_bulk_in(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_gadget_bulk_in_count").increment(1);
    counter!("smoo_gadget_bulk_in_bytes").increment(bytes as u64);
    histogram!("smoo_gadget_bulk_in_latency_ns").record(ns as f64);
}

pub fn observe_bulk_out(bytes: usize, dur: Duration) {
    let ns = dur.as_nanos().min(u64::MAX as u128) as u64;
    counter!("smoo_gadget_bulk_out_count").increment(1);
    counter!("smoo_gadget_bulk_out_bytes").increment(bytes as u64);
    histogram!("smoo_gadget_bulk_out_latency_ns").record(ns as f64);
}

pub fn record_pending_requests(count: usize) {
    gauge!("smoo_gadget_pending_requests").set(count as f64);
}

pub fn record_inflight_requests(count: usize) {
    gauge!("smoo_gadget_inflight_requests").set(count as f64);
}
