#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod allocator;   // Rust global allocator (slab pool)
mod rc_guard;
mod hooks;
mod stats;
mod security;
mod mem_pool;
mod edge_guard;
mod upload_guard;

use libc::{c_void, size_t};

const BANNER: &str = "
    _~^~^~_
\\) /  o o  \\ (/      php-safe-core v0.5.0
  '_   -   _'        > RC Guard         [ACTIVE]
  / '-----' \\        > Security Monitor [ACTIVE]
                     > Rate Limiter     [ACTIVE]
  Powered by Rust    > MemPool (Slab)   [ACTIVE]
                     > Edge Guard       [ACTIVE]
                     > Upload Guard     [ACTIVE]
";

#[no_mangle]
pub extern "C" fn php_safe_core_init() {
    // allocator is always active via #[global_allocator]
    allocator::init();
    stats::init();
    mem_pool::init();
    security::init();
    edge_guard::init();
    upload_guard::init();

    eprintln!("{}", BANNER);
    eprintln!("[php-safe-core] Security processor started. PHP process is protected.");
    eprintln!("[php-safe-core] ------------------------------------------");

    let ms = mem_pool::POOL.stats();
    let (total, hits, sys) = allocator::stats();
    let hit_rate = if total > 0 { hits * 100 / total } else { 0 };
    eprintln!("[php-safe-core] MemPool  : {} tiers active", ms.tiers.len());
    eprintln!("[php-safe-core] Allocator: hit_rate={}% sys_fallback={}", hit_rate, sys);
    eprintln!("[php-safe-core] ------------------------------------------");
}

#[no_mangle]
pub extern "C" fn php_safe_core_shutdown() {
    upload_guard::shutdown();
    edge_guard::shutdown();

    let s = stats::get();
    let ms = mem_pool::POOL.stats();
    let (total, hits, sys) = allocator::stats();

    eprintln!("[php-safe-core] ------------------------------------------");
    eprintln!("[php-safe-core] Runtime Statistics:");
    eprintln!("[php-safe-core]   RC Intercepts   : {}", s.rc_intercepts);
    eprintln!("[php-safe-core]   Threats Blocked : {}", s.threats_blocked);
    eprintln!("[php-safe-core]   Rate Blocks     : {}", s.rate_blocks);
    eprintln!("[php-safe-core]   Tampered Files  : {}", edge_guard::tamper_count());
    eprintln!("[php-safe-core]   Upload Blocked  : {}", upload_guard::blocked_count());
    eprintln!("[php-safe-core]   Pool Allocs     : {}", ms.total_allocs);
    eprintln!("[php-safe-core]   Pool Reuses     : {}", ms.total_reuses);
    eprintln!("[php-safe-core]   Alloc Total     : {}", total);
    eprintln!("[php-safe-core]   Alloc Pool Hits : {}", hits);
    eprintln!("[php-safe-core]   Alloc Sys Calls : {}", sys);
    eprintln!("[php-safe-core] Shutdown complete.");
}

#[no_mangle]
pub extern "C" fn php_safe_rc_addref(refcount: *mut u32) -> u32 {
    rc_guard::addref(refcount)
}

#[no_mangle]
pub extern "C" fn php_safe_rc_delref(refcount: *mut u32, ptr: *mut c_void) -> u32 {
    rc_guard::delref(refcount, ptr)
}

#[no_mangle]
pub unsafe extern "C" fn php_safe_check_cmd(cmd: *const libc::c_char) -> libc::c_int {
    security::check_cmd(cmd)
}

#[no_mangle]
pub unsafe extern "C" fn php_safe_check_path(path: *const libc::c_char) -> libc::c_int {
    security::check_path(path)
}

#[no_mangle]
pub unsafe extern "C" fn php_safe_rate_check(ip: *const libc::c_char) -> libc::c_int {
    security::rate_check(ip)
}

#[no_mangle]
pub unsafe extern "C" fn php_safe_filter_output(buf: *const libc::c_char) -> libc::c_int {
    security::filter_output(buf)
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
