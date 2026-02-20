//! 请求频率限制模块
//!
//! 基于进程级滑动窗口计数器，
//! 限制单个来源 IP 在时间窗口内的请求次数，
//! 防止暴力破解和 CC 攻击。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::Lazy;
use crate::stats;

/// 时间窗口（秒）
const WINDOW_SECS: u64 = 60;
/// 窗口内最大请求数
const MAX_REQUESTS: u32 = 300;
/// IP 记录最大条数（防内存泄漏）
const MAX_ENTRIES: usize = 10_000;

struct Entry {
    count: u32,
    window_start: u64,
}

static COUNTER: Lazy<Mutex<HashMap<String, Entry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn init() {
    // 预初始化
    let _ = COUNTER.lock();
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 检查某个 IP 是否超过频率限制
/// 返回 true 表示被限制，false 表示放行
pub fn check(ip: &str) -> bool {
    let now = now_secs();
    let mut map = match COUNTER.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };

    // 防止 map 无限增长
    if map.len() >= MAX_ENTRIES {
        map.clear();
    }

    let entry = map.entry(ip.to_string()).or_insert(Entry {
        count: 0,
        window_start: now,
    });

    // 窗口过期，重置
    if now - entry.window_start >= WINDOW_SECS {
        entry.count = 1;
        entry.window_start = now;
        return false;
    }

    entry.count += 1;

    if entry.count > MAX_REQUESTS {
        stats::inc_rate_block();
        eprintln!(
            "[php-safe-core] ⛔ 频率限制触发: IP={} 请求数={}/{}s",
            ip, entry.count, WINDOW_SECS
        );
        return true;
    }

    false
}

/// 供外部（PHP FFI）调用的频率检查接口
#[no_mangle]
pub unsafe extern "C" fn php_safe_rate_check(
    ip: *const libc::c_char,
) -> libc::c_int {
    if ip.is_null() {
        return 0;
    }
    let ip_str = std::ffi::CStr::from_ptr(ip).to_string_lossy();
    if check(&ip_str) { 1 } else { 0 }
}
