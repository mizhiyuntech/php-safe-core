use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::Lazy;
use crate::stats;

const WINDOW_SECS: u64 = 60;
const MAX_REQUESTS: u32 = 300;
const MAX_ENTRIES: usize = 10_000;

struct Entry { count: u32, window_start: u64 }

static COUNTER: Lazy<Mutex<HashMap<String, Entry>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn init() { drop(COUNTER.lock()); }

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn check(ip: &str) -> bool {
    let now = now_secs();
    let mut map = match COUNTER.lock() { Ok(m) => m, Err(_) => return false };
    if map.len() >= MAX_ENTRIES { map.clear(); }
    let entry = map.entry(ip.to_string()).or_insert(Entry { count: 0, window_start: now });
    if now - entry.window_start >= WINDOW_SECS {
        entry.count = 1;
        entry.window_start = now;
        return false;
    }
    entry.count += 1;
    if entry.count > MAX_REQUESTS {
        stats::inc_rate_block();
        eprintln!("[php-safe-core] RATE LIMITED: ip={} count={}/{}", ip, entry.count, WINDOW_SECS);
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn php_safe_rate_check(ip: *const libc::c_char) -> libc::c_int {
    if ip.is_null() { return 0; }
    let ip_str = std::ffi::CStr::from_ptr(ip).to_string_lossy();
    if check(&ip_str) { 1 } else { 0 }
}
