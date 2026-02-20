//! RC 守卫模块
//!
//! 拦截 PHP zval 引用计数操作，防止：
//!   - double-free：refcount=0 后再次 delref
//!   - use-after-free：对已释放指针 addref
//!   - RC 溢出：refcount 超过合理上限

use std::collections::HashSet;
use std::sync::Mutex;
use libc::c_void;
use once_cell::sync::Lazy;
use crate::stats;

static FREED_SET: Lazy<Mutex<HashSet<usize>>> = Lazy::new(|| Mutex::new(HashSet::new()));

const RC_MAX_SANE: u32 = 1_000_000;

pub fn addref(refcount: *mut u32) -> u32 {
    if refcount.is_null() { return 0; }

    let addr = refcount as usize;
    if let Ok(freed) = FREED_SET.lock() {
        if freed.contains(&addr) {
            stats::inc_rc_intercept();
            return 0;
        }
    }

    let current = unsafe { *refcount };
    if current >= RC_MAX_SANE {
        stats::inc_rc_intercept();
        return current;
    }

    let new_val = current.wrapping_add(1);
    unsafe { *refcount = new_val };
    new_val
}

pub fn delref(refcount: *mut u32, ptr: *mut c_void) -> u32 {
    if refcount.is_null() { return 0; }

    let addr = ptr as usize;
    if let Ok(freed) = FREED_SET.lock() {
        if freed.contains(&addr) {
            stats::inc_rc_intercept();
            return u32::MAX;
        }
    }

    let current = unsafe { *refcount };
    if current == 0 {
        stats::inc_rc_intercept();
        if let Ok(mut freed) = FREED_SET.lock() {
            freed.insert(addr);
            if freed.len() > 100_000 { freed.clear(); }
        }
        return 0;
    }

    let new_val = current - 1;
    unsafe { *refcount = new_val };

    if new_val == 0 && addr != 0 {
        if let Ok(mut freed) = FREED_SET.lock() {
            freed.insert(addr);
            if freed.len() > 100_000 { freed.clear(); }
        }
    }
    new_val
}
