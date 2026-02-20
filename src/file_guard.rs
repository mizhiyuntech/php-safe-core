//! 文件访问监控模块
//!
//! 拦截对敏感系统文件和异常路径的访问，
//! 防止 PHP 被利用读取 /etc/passwd、.env、私钥等文件。

use libc::{c_char, c_int};
use std::ffi::CStr;
use crate::stats;

/// 禁止访问的敏感路径前缀
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

/// 禁止访问的文件扩展名
const BLOCKED_EXTS: &[&str] = &[
    ".pem", ".key", ".p12", ".pfx",
    ".id_rsa", ".id_dsa",
];

/// 允许访问的路径前缀（白名单）
const ALLOWED_PREFIXES: &[&str] = &[
    "/var/www",
    "/usr/share/php",
    "/tmp",
    "/proc/self/fd",
];

fn is_blocked(path: &str) -> bool {
    // 白名单优先
    for allow in ALLOWED_PREFIXES {
        if path.starts_with(allow) {
            return false;
        }
    }
    // 路径黑名单
    for blocked in BLOCKED_PATHS {
        if path.contains(blocked) {
            return true;
        }
    }
    // 扩展名黑名单
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

    // 只拦截读操作（O_RDONLY = 0）
    if flags & libc::O_WRONLY == 0 && flags & libc::O_RDWR == 0 {
        if is_blocked(&path_str) {
            stats::inc_file_block();
            eprintln!("[php-safe-core] ⛔ 文件访问拦截: {}", path_str);
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
