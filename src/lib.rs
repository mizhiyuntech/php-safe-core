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

// 中文字符串用普通 &str，不用 b"" 字节串，编译器支持 UTF-8
const BANNER: &str = "\n\
    _~^~^~_\n\
\\) /  o o  \\ (/      php-safe-core v0.2.0\n\
  '_   -   _'        \u{2726} RC \u9632\u62a4\u5df2\u6fc0\u6d3b\n\
  / '-----' \\        \u{2726} \u547d\u4ee4\u6ce8\u5165\u62e6\u622a\u5df2\u6fc0\u6d3b\n\
                     \u{2726} \u6587\u4ef6\u8bbf\u95ee\u76d1\u63a7\u5df2\u6fc0\u6d3b\n\
  \u{1f980} Powered by      \u{2726} \u9891\u7387\u9650\u5236\u5df2\u6fc0\u6d3b\n\
     Rust            \u{2726} \u654f\u611f\u4fe1\u606f\u4fdd\u62a4\u5df2\u6fc0\u6d3b\n";

#[no_mangle]
pub extern "C" fn php_safe_core_init() {
    stats::init();
    rate_limiter::init();
    eprintln!("{}", BANNER);
    eprintln!("[php-safe-core] \u{2705} \u5b89\u5168\u5904\u7406\u5668\u542f\u52a8\u6210\u529f | PHP \u8fdb\u7a0b\u5df2\u53d7\u4fdd\u62a4");
    eprintln!("[php-safe-core] {}", "\u2500".repeat(41));
}

#[no_mangle]
pub extern "C" fn php_safe_core_shutdown() {
    let s = stats::get();
    eprintln!("[php-safe-core] {}", "\u2500".repeat(41));
    eprintln!("[php-safe-core] \u{1f4ca} \u8fd0\u884c\u7edf\u8ba1:");
    eprintln!("[php-safe-core]   RC \u62e6\u622a     : {}", s.rc_intercepts);
    eprintln!("[php-safe-core]   \u547d\u4ee4\u62e6\u622a    : {}", s.cmd_blocks);
    eprintln!("[php-safe-core]   \u6587\u4ef6\u62e6\u622a    : {}", s.file_blocks);
    eprintln!("[php-safe-core]   \u9891\u7387\u62e6\u622a    : {}", s.rate_blocks);
    eprintln!("[php-safe-core]   \u654f\u611f\u62e6\u622a    : {}", s.sensitive_blocks);
    eprintln!("[php-safe-core] \u{1f980} \u5df2\u5b89\u5168\u9000\u51fa");
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
