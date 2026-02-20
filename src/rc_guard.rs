//! RC 守卫模块
//!
//! PHP 的引用计数（zval.refcount）存在几类漏洞：
//!   1. Double-free：refcount 减到 0 后对象被释放，但仍有指针指向它
//!   2. Use-after-free：freed 内存被重新分配后旧引用继续读写
//!   3. 循环引用泄漏：gc 未及时触发导致内存持续增长
//!
//! 本模块通过拦截 addref/delref 操作，插入安全边界检查。

use std::collections::HashMap;
use std::sync::Mutex;
use libc::c_void;
use once_cell::sync::Lazy;
use crate::stats;

/// 已释放的指针集合（用于 use-after-free 检测）
static FREED_SET: Lazy<Mutex<HashMap<usize, u32>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// RC 最大合理值（超过此值视为溢出或错误）
const RC_MAX_SANE: u32 = 1_000_000;

/// 引用计数递增，含溢出检查
pub fn addref(refcount: *mut u32) -> u32 {
    if refcount.is_null() {
        return 0;
    }

    // 检查是否对已释放指针操作（use-after-free）
    let addr = refcount as usize;
    if let Ok(freed) = FREED_SET.lock() {
        if freed.contains_key(&addr) {
            stats::inc_rc_intercept();
            eprintln!("[php-safe-core] ⚠ 检测到 use-after-free: ptr=0x{:x}", addr);
            return 0;
        }
    }

    let current = unsafe { *refcount };

    // 溢出保护
    if current >= RC_MAX_SANE {
        stats::inc_rc_intercept();
        eprintln!("[php-safe-core] ⚠ RC溢出保护触发: refcount={}", current);
        return current;
    }

    let new_val = current.wrapping_add(1);
    unsafe { *refcount = new_val };
    new_val
}

/// 引用计数递减，含 double-free 检查
pub fn delref(refcount: *mut u32, ptr: *mut c_void) -> u32 {
    if refcount.is_null() {
        return 0;
    }

    let addr = ptr as usize;

    // double-free 检测
    if let Ok(freed) = FREED_SET.lock() {
        if freed.contains_key(&addr) {
            stats::inc_rc_intercept();
            eprintln!("[php-safe-core] ⚠ 检测到 double-free: ptr=0x{:x}", addr);
            return u32::MAX; // 返回哨兵值，调用方不应继续释放
        }
    }

    let current = unsafe { *refcount };

    if current == 0 {
        // 已是 0 仍在递减 → 潜在 double-free
        stats::inc_rc_intercept();
        eprintln!("[php-safe-core] ⚠ RC下溢保护: ptr=0x{:x}", addr);
        // 将指针加入已释放集合
        if let Ok(mut freed) = FREED_SET.lock() {
            freed.insert(addr, 0);
        }
        return 0;
    }

    let new_val = current - 1;
    unsafe { *refcount = new_val };

    if new_val == 0 && addr != 0 {
        // 记录即将释放的指针
        if let Ok(mut freed) = FREED_SET.lock() {
            freed.insert(addr, 1);
            // 限制集合大小，避免内存无限增长
            if freed.len() > 100_000 {
                freed.clear();
            }
        }
    }

    new_val
}
