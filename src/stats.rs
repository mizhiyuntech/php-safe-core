//! 统计模块

use std::sync::atomic::{AtomicU64, Ordering};

static RC_INTERCEPTS: AtomicU64 = AtomicU64::new(0);
static CMD_BLOCKS: AtomicU64 = AtomicU64::new(0);
static FILE_BLOCKS: AtomicU64 = AtomicU64::new(0);
static RATE_BLOCKS: AtomicU64 = AtomicU64::new(0);
static SENSITIVE_BLOCKS: AtomicU64 = AtomicU64::new(0);

pub struct Stats {
    pub rc_intercepts: u64,
    pub cmd_blocks: u64,
    pub file_blocks: u64,
    pub rate_blocks: u64,
    pub sensitive_blocks: u64,
}

pub fn init() {
    RC_INTERCEPTS.store(0, Ordering::Relaxed);
    CMD_BLOCKS.store(0, Ordering::Relaxed);
    FILE_BLOCKS.store(0, Ordering::Relaxed);
    RATE_BLOCKS.store(0, Ordering::Relaxed);
    SENSITIVE_BLOCKS.store(0, Ordering::Relaxed);
}

pub fn inc_rc_intercept()    { RC_INTERCEPTS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_cmd_block()       { CMD_BLOCKS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_file_block()      { FILE_BLOCKS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_rate_block()      { RATE_BLOCKS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_sensitive_block() { SENSITIVE_BLOCKS.fetch_add(1, Ordering::Relaxed); }

pub fn get() -> Stats {
    Stats {
        rc_intercepts:    RC_INTERCEPTS.load(Ordering::Relaxed),
        cmd_blocks:       CMD_BLOCKS.load(Ordering::Relaxed),
        file_blocks:      FILE_BLOCKS.load(Ordering::Relaxed),
        rate_blocks:      RATE_BLOCKS.load(Ordering::Relaxed),
        sensitive_blocks: SENSITIVE_BLOCKS.load(Ordering::Relaxed),
    }
}

pub fn to_json() -> String {
    let s = get();
    format!(
        r#"{{"rc_intercepts":{},"cmd_blocks":{},"file_blocks":{},"rate_blocks":{},"sensitive_blocks":{}}}"#,
        s.rc_intercepts, s.cmd_blocks, s.file_blocks, s.rate_blocks, s.sensitive_blocks
    )
}
