use std::sync::atomic::{AtomicU64, Ordering};

static RC_INTERCEPTS: AtomicU64 = AtomicU64::new(0);
static THREATS_BLOCKED: AtomicU64 = AtomicU64::new(0);
static RATE_BLOCKS: AtomicU64 = AtomicU64::new(0);

pub struct Stats {
    pub rc_intercepts: u64,
    pub threats_blocked: u64,
    pub rate_blocks: u64,
}

pub fn init() {
    RC_INTERCEPTS.store(0, Ordering::Relaxed);
    THREATS_BLOCKED.store(0, Ordering::Relaxed);
    RATE_BLOCKS.store(0, Ordering::Relaxed);
}

pub fn inc_rc_intercept() { RC_INTERCEPTS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_threat()       { THREATS_BLOCKED.fetch_add(1, Ordering::Relaxed); }
pub fn inc_rate_block()   { RATE_BLOCKS.fetch_add(1, Ordering::Relaxed); }

pub fn get() -> Stats {
    Stats {
        rc_intercepts:   RC_INTERCEPTS.load(Ordering::Relaxed),
        threats_blocked: THREATS_BLOCKED.load(Ordering::Relaxed),
        rate_blocks:     RATE_BLOCKS.load(Ordering::Relaxed),
    }
}

pub fn to_json() -> String {
    let s = get();
    let (total, hits, sys) = crate::allocator::stats();
    format!(
        r#"{{"rc_intercepts":{},"threats_blocked":{},"rate_blocks":{},"tampered_files":{},"upload_blocked":{},"alloc_total":{},"alloc_hits":{},"alloc_sys":{}}}"#,
        s.rc_intercepts,
        s.threats_blocked,
        s.rate_blocks,
        crate::edge_guard::tamper_count(),
        crate::upload_guard::blocked_count(),
        total, hits, sys,
    )
}
