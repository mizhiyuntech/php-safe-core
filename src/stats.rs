//! 统计模块：记录运行时指标

use std::sync::atomic::{AtomicU64, Ordering};
use once_cell::sync::Lazy;

static RC_INTERCEPTS: AtomicU64 = AtomicU64::new(0);
static MEMORY_SAVED: AtomicU64 = AtomicU64::new(0);
static REQUESTS_HANDLED: AtomicU64 = AtomicU64::new(0);

pub struct Stats {
    pub rc_intercepts: u64,
    pub memory_saved: u64,
    pub requests_handled: u64,
}

pub fn init() {
    RC_INTERCEPTS.store(0, Ordering::Relaxed);
    MEMORY_SAVED.store(0, Ordering::Relaxed);
    REQUESTS_HANDLED.store(0, Ordering::Relaxed);
}

pub fn inc_rc_intercept() {
    RC_INTERCEPTS.fetch_add(1, Ordering::Relaxed);
}

pub fn add_memory_saved(bytes: usize) {
    MEMORY_SAVED.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn inc_request() {
    REQUESTS_HANDLED.fetch_add(1, Ordering::Relaxed);
}

pub fn get() -> Stats {
    Stats {
        rc_intercepts: RC_INTERCEPTS.load(Ordering::Relaxed),
        memory_saved: MEMORY_SAVED.load(Ordering::Relaxed),
        requests_handled: REQUESTS_HANDLED.load(Ordering::Relaxed),
    }
}

pub fn to_json() -> String {
    let s = get();
    format!(
        r#"{{"rc_intercepts":{},"memory_saved_bytes":{},"requests_handled":{}}}"#,
        s.rc_intercepts, s.memory_saved, s.requests_handled
    )
}
