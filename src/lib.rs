//! PHP Safe Core - PHP底层安全处理器
//!
//! 通过 LD_PRELOAD 挂载到 PHP 进程，提供：
//!   - RC 漏洞防护（double-free / use-after-free / 溢出检测）
//!   - 运行时统计
//!
//! 注意：不替换 malloc/free，避免与 PHP 自身内存管理冲突。

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod rc_guard;
mod hooks;
mod stats;

use libc::{c_void, size_t};

/// 库初始化（.so 加载时自动调用）
#[no_mangle]
pub extern "C" fn php_safe_core_init() {
    stats::init();
    eprintln!("[php-safe-core] loaded: RC guard active, PHP {}", php_version());
}

/// 库卸载时输出统计
#[no_mangle]
pub extern "C" fn php_safe_core_shutdown() {
    let s = stats::get();
    eprintln!(
        "[php-safe-core] shutdown: rc_intercepts={}, requests={}",
        s.rc_intercepts, s.requests_handled,
    );
}

fn php_version() -> &'static str {
    // 编译时写入，运行时无需调用 PHP API
    env!("CARGO_PKG_VERSION")
}

// ── RC 钩子（供 PHP FFI 调用）──────────────────────

#[no_mangle]
pub extern "C" fn php_safe_rc_addref(refcount: *mut u32) -> u32 {
    rc_guard::addref(refcount)
}

#[no_mangle]
pub extern "C" fn php_safe_rc_delref(refcount: *mut u32, ptr: *mut c_void) -> u32 {
    rc_guard::delref(refcount, ptr)
}

#[no_mangle]
pub unsafe extern "C" fn php_safe_stats_json(buf: *mut u8, buf_len: size_t) -> size_t {
    let json = stats::to_json();
    let bytes = json.as_bytes();
    let copy_len = bytes.len().min(buf_len.saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
    *buf.add(copy_len) = 0;
    copy_len
}
