#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod rc_guard;
mod hooks;
mod stats;
mod cmd_guard;
mod file_guard;
mod rate_limiter;
mod sensitive_guard;

use libc::{c_void, size_t, c_char, c_int};

const BANNER: &str = "
    _~^~^~_
\\) /  o o  \\ (/      php-safe-core v0.2.0
  '_   -   _'        > RC Guard         [ACTIVE]
  / '-----' \\        > CMD Injection     [ACTIVE]
                     > File Monitor     [ACTIVE]
  Powered by Rust    > Rate Limiter     [ACTIVE]
                     > Sensitive Guard  [ACTIVE]
";

#[no_mangle]
pub extern "C" fn php_safe_core_init() {
    stats::init();
    rate_limiter::init();
    eprintln!("{}", BANNER);
    eprintln!("[php-safe-core] Security processor started successfully.");
    eprintln!("[php-safe-core] PHP process is now protected.");
    eprintln!("[php-safe-core] ------------------------------------------");
}

#[no_mangle]
pub extern "C" fn php_safe_core_shutdown() {
    let s = stats::get();
    eprintln!("[php-safe-core] ------------------------------------------");
    eprintln!("[php-safe-core] Runtime Statistics:");
    eprintln!("[php-safe-core]   RC Intercepts   : {}", s.rc_intercepts);
    eprintln!("[php-safe-core]   CMD Blocks      : {}", s.cmd_blocks);
    eprintln!("[php-safe-core]   File Blocks     : {}", s.file_blocks);
    eprintln!("[php-safe-core]   Rate Blocks     : {}", s.rate_blocks);
    eprintln!("[php-safe-core]   Sensitive Blocks: {}", s.sensitive_blocks);
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
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    cmd_guard::intercept_execve(path, argv, envp)
}

#[no_mangle]
pub unsafe extern "C" fn popen(command: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    cmd_guard::intercept_popen(command, mode)
}

#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: u32) -> c_int {
    file_guard::intercept_open(path, flags, mode)
}

#[no_mangle]
pub unsafe extern "C" fn write(
    fd: libc::c_int,
    buf: *const c_void,
    count: size_t,
) -> libc::ssize_t {
    sensitive_guard::intercept_write(fd, buf, count)
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
