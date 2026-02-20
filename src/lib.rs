//! PHP Safe Core - PHP底层安全处理器
//!
//! 通过 LD_PRELOAD 劫持 PHP 的内存分配与引用计数函数，
//! 在不修改 PHP 源码的情况下修复 RC 漏洞并提升性能。

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod rc_guard;
mod mem_pool;
mod hooks;
mod stats;

use libc::{c_void, size_t};

/// 库初始化入口（动态库加载时自动调用）
#[no_mangle]
pub extern "C" fn php_safe_core_init() {
    stats::init();
    mem_pool::init();
    eprintln!("[php-safe-core] 安全处理器已加载，RC守卫已激活");
}

/// 库卸载时调用
#[no_mangle]
pub extern "C" fn php_safe_core_shutdown() {
    let s = stats::get();
    eprintln!(
        "[php-safe-core] 统计 → RC拦截: {}, 内存节省: {} KB, 请求处理: {}",
        s.rc_intercepts,
        s.memory_saved / 1024,
        s.requests_handled,
    );
}

// ───────────────────────────────────────────────
// LD_PRELOAD 钩子：替换 malloc / free / realloc
// ───────────────────────────────────────────────

/// 替换标准 malloc，接入内存池
#[no_mangle]
pub unsafe extern "C" fn malloc(size: size_t) -> *mut c_void {
    mem_pool::alloc(size)
}

/// 替换标准 free，归还内存池
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    mem_pool::dealloc(ptr)
}

/// 替换标准 realloc
#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    mem_pool::realloc(ptr, size)
}

/// 替换 calloc
#[no_mangle]
pub unsafe extern "C" fn calloc(nmemb: size_t, size: size_t) -> *mut c_void {
    let total = nmemb.saturating_mul(size);
    let ptr = mem_pool::alloc(total);
    if !ptr.is_null() {
        std::ptr::write_bytes(ptr as *mut u8, 0, total);
    }
    ptr
}

// ───────────────────────────────────────────────
// PHP RC 相关钩子（通过 PHP 扩展 API 暴露）
// ───────────────────────────────────────────────

/// PHP zval 引用计数递增钩子
/// 由扩展或外部通过 FFI 调用
#[no_mangle]
pub extern "C" fn php_safe_rc_addref(refcount: *mut u32) -> u32 {
    rc_guard::addref(refcount)
}

/// PHP zval 引用计数递减钩子（含泄漏检测）
#[no_mangle]
pub extern "C" fn php_safe_rc_delref(refcount: *mut u32, ptr: *mut c_void) -> u32 {
    rc_guard::delref(refcount, ptr)
}

/// 查询当前统计数据（JSON字符串写入 buf）
#[no_mangle]
pub unsafe extern "C" fn php_safe_stats_json(buf: *mut u8, buf_len: size_t) -> size_t {
    let json = stats::to_json();
    let bytes = json.as_bytes();
    let copy_len = bytes.len().min(buf_len.saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
    *buf.add(copy_len) = 0; // null-terminate
    copy_len
}
