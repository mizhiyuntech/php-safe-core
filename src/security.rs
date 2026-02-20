//! Unified security module
//! Provides safe check functions callable via PHP FFI.
//! Does NOT hook any syscalls to avoid segfault.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::Lazy;
use libc::c_char;
use std::ffi::CStr;
use crate::stats;

// ── Rate limiter state ─────────────────────────────────────

const WINDOW_SECS: u64 = 60;
const MAX_REQUESTS: u32 = 300;
const MAX_ENTRIES: usize = 10_000;

struct RateEntry { count: u32, window_start: u64 }

static RATE_MAP: Lazy<Mutex<HashMap<String, RateEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// ── Blocklists ─────────────────────────────────────────────

const BLOCKED_CMDS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat",
    "bash", "sh -c", "python", "perl", "ruby",
    "base64", "/bin/sh", "/bin/bash",
];

const BLOCKED_PATHS: &[&str] = &[
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root/.ssh", "/proc/self/environ",
    ".env", "/.git", "wp-config.php",
];

const BLOCKED_EXTS: &[&str] = &[
    ".pem", ".key", ".p12", ".pfx", ".id_rsa",
];

const SENSITIVE_PATTERNS: &[&str] = &[
    "Stack trace", "Stack Trace", "#0 /", "#1 /",
    "SQLSTATE", "DB_PASSWORD", "DB_HOST", "APP_KEY",
    "/var/www", "/home/", "password", "secret",
];

pub fn init() {
    drop(RATE_MAP.lock());
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Check if a shell command should be blocked
pub unsafe fn check_cmd(cmd: *const c_char) -> libc::c_int {
    if cmd.is_null() { return 0; }
    let s = CStr::from_ptr(cmd).to_string_lossy().to_lowercase();
    for blocked in BLOCKED_CMDS {
        if s.contains(blocked) {
            stats::inc_threat();
            eprintln!("[php-safe-core] [BLOCK] CMD: {}", s);
            return 1;
        }
    }
    0
}

/// Check if a file path should be blocked
pub unsafe fn check_path(path: *const c_char) -> libc::c_int {
    if path.is_null() { return 0; }
    let s = CStr::from_ptr(path).to_string_lossy();
    for blocked in BLOCKED_PATHS {
        if s.contains(blocked) {
            stats::inc_threat();
            eprintln!("[php-safe-core] [BLOCK] Path: {}", s);
            return 1;
        }
    }
    for ext in BLOCKED_EXTS {
        if s.ends_with(ext) {
            stats::inc_threat();
            eprintln!("[php-safe-core] [BLOCK] Ext: {}", s);
            return 1;
        }
    }
    0
}

/// Rate limit check by IP string
pub unsafe fn rate_check(ip: *const c_char) -> libc::c_int {
    if ip.is_null() { return 0; }
    let ip_str = CStr::from_ptr(ip).to_string_lossy().to_string();
    let now = now_secs();
    let mut map = match RATE_MAP.lock() { Ok(m) => m, Err(_) => return 0 };
    if map.len() >= MAX_ENTRIES { map.clear(); }
    let entry = map.entry(ip_str.clone()).or_insert(RateEntry { count: 0, window_start: now });
    if now - entry.window_start >= WINDOW_SECS {
        entry.count = 1;
        entry.window_start = now;
        return 0;
    }
    entry.count += 1;
    if entry.count > MAX_REQUESTS {
        stats::inc_rate_block();
        eprintln!("[php-safe-core] [RATE] Blocked IP: {} ({}/{}s)", ip_str, entry.count, WINDOW_SECS);
        return 1;
    }
    0
}

/// Filter sensitive output content
pub unsafe fn filter_output(buf: *const c_char) -> libc::c_int {
    if buf.is_null() { return 0; }
    let s = CStr::from_ptr(buf).to_string_lossy();
    for pattern in SENSITIVE_PATTERNS {
        if s.contains(pattern) {
            stats::inc_threat();
            eprintln!("[php-safe-core] [FILTER] Sensitive output blocked.");
            return 1;
        }
    }
    0
}
