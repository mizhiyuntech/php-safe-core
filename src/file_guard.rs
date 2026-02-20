//! File access monitor module

use libc::{c_char, c_int};
use std::ffi::CStr;
use crate::stats;

const BLOCKED_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/proc/self/environ",
    "/.env",
    "/.git",
    "/wp-config.php",
    "/config/database",
];

const BLOCKED_EXTS: &[&str] = &[
    ".pem", ".key", ".p12", ".pfx", ".id_rsa", ".id_dsa",
];

const ALLOWED_PREFIXES: &[&str] = &[
    "/var/www",
    "/usr/share/php",
    "/tmp",
    "/proc/self/fd",
];

fn is_blocked(path: &str) -> bool {
    for allow in ALLOWED_PREFIXES {
        if path.starts_with(allow) {
            return false;
        }
    }
    for blocked in BLOCKED_PATHS {
        if path.contains(blocked) {
            return true;
        }
    }
    for ext in BLOCKED_EXTS {
        if path.ends_with(ext) {
            return true;
        }
    }
    false
}

pub unsafe fn intercept_open(path: *const c_char, flags: c_int, mode: u32) -> c_int {
    if path.is_null() {
        return call_real_open(path, flags, mode);
    }
    let path_str = CStr::from_ptr(path).to_string_lossy();
    if flags & libc::O_WRONLY == 0 && flags & libc::O_RDWR == 0 {
        if is_blocked(&path_str) {
            stats::inc_file_block();
            eprintln!("[php-safe-core] [BLOCK] File access blocked: {}", path_str);
            *libc::__errno_location() = libc::EACCES;
            return -1;
        }
    }
    call_real_open(path, flags, mode)
}

unsafe fn call_real_open(path: *const c_char, flags: c_int, mode: u32) -> c_int {
    extern "C" {
        fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    }
    open(path, flags, mode)
}
