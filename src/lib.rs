#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod rc_guard;
mod hooks;
mod stats;
mod security;

use libc::{c_void, size_t};

const BANNER: &str = "
    _~^~^~_
\\) /  o o  \\ (/      php-safe-core v0.3.0
  '_   -   _'        > RC Guard         [ACTIVE]
  / '-----' \\        > Security Monitor [ACTIVE]
                     > Rate Limiter     [ACTIVE]
  Powered by Rust    > Sensitive Guard  [ACTIVE]
";

#[no_mangle]
pub extern "C" fn php_safe_core_init() {
    stats::init();
    security::init();
    eprintln!("{}", BANNER);
    eprintln!("[php-safe-core] Security processor started. PHP process is protected.");
    eprintln!("[php-safe-core] ------------------------------------------");
}

#[no_mangle]
pub extern "C" fn php_safe_core_shutdown() {
    let s = stats::get();
    eprintln!("[php-safe-core] ------------------------------------------");
    eprintln!("[php-safe-core] Runtime Statistics:");
    eprintln!("[php-safe-core]   RC Intercepts   : {}", s.rc_intercepts);
    eprintln!("[php-safe-core]   Threats Blocked : {}", s.threats_blocked);
    eprintln!("[php-safe-core]   Rate Blocks     : {}", s.rate_blocks);
    eprintln!("[php-safe-core] Shutdown complete.");
}

// ── RC 钩子（供 PHP FFI 调用）──────────────────────────────

#[no_mangle]
pub extern "C" fn php_safe_rc_addref(refcount: *mut u32) -> u32 {
    rc_guard::addref(refcount)
}

#[no_mangle]
pub extern "C" fn php_safe_rc_delref(refcount: *mut u32, ptr: *mut c_void) -> u32 {
    rc_guard::delref(refcount, ptr)
}

// ── 安全检查接口（供 PHP FFI 主动调用）────────────────────

/// 检查命令是否被允许执行（0=允许 1=拦截）
#[no_mangle]
pub unsafe extern "C" fn php_safe_check_cmd(cmd: *const libc::c_char) -> libc::c_int {
    security::check_cmd(cmd)
}

/// 检查文件路径是否允许访问（0=允许 1=拦截）
#[no_mangle]
pub unsafe extern "C" fn php_safe_check_path(path: *const libc::c_char) -> libc::c_int {
    security::check_path(path)
}

/// 检查 IP 是否超过频率限制（0=允许 1=拦截）
#[no_mangle]
pub unsafe extern "C" fn php_safe_rate_check(ip: *const libc::c_char) -> libc::c_int {
    security::rate_check(ip)
}

/// 过滤敏感输出内容，返回是否被过滤（0=正常 1=已过滤）
#[no_mangle]
pub unsafe extern "C" fn php_safe_filter_output(
    buf: *const libc::c_char,
) -> libc::c_int {
    security::filter_output(buf)
}

// ── 统计接口 ───────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn php_safe_stats_json(buf: *mut u8, buf_len: size_t) -> size_t {
    let json = stats::to_json();
    let bytes = json.as_bytes();
    let copy_len = bytes.len().min(buf_len.saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
    *buf.add(copy_len) = 0;
    copy_len
}
