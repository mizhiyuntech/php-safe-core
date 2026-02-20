//! Sensitive information protection module

use libc::{c_int, size_t, ssize_t, c_void};
use crate::stats;

const SENSITIVE_PATTERNS: &[&str] = &[
    "Stack trace",
    "Stack Trace",
    "#0 /",
    "#1 /",
    "SQLSTATE",
    "mysql_connect",
    "pg_connect",
    "/var/www",
    "/home/",
    "/usr/local",
    "DB_PASSWORD",
    "DB_HOST",
    "APP_KEY",
    "secret",
    "password",
];

const SAFE_MSG: &[u8] = b"[php-safe-core] Sensitive output has been filtered.\n";

pub unsafe fn intercept_write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    if fd != 1 && fd != 2 {
        return call_real_write(fd, buf, count);
    }
    if buf.is_null() || count == 0 {
        return call_real_write(fd, buf, count);
    }
    let slice = std::slice::from_raw_parts(buf as *const u8, count);
    let content = String::from_utf8_lossy(slice);
    for pattern in SENSITIVE_PATTERNS {
        if content.contains(pattern) {
            stats::inc_sensitive_block();
            return call_real_write(fd, SAFE_MSG.as_ptr() as *const c_void, SAFE_MSG.len());
        }
    }
    call_real_write(fd, buf, count)
}

unsafe fn call_real_write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    extern "C" {
        fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    }
    write(fd, buf, count)
}
