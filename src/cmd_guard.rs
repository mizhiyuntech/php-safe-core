//! 命令注入拦截模块
//!
//! 通过 LD_PRELOAD 替换 execve / popen，
//! 阻止 PHP 进程执行危险的 shell 命令。

use libc::{c_char, c_int, FILE};
use std::ffi::CStr;
use crate::stats;

/// 危险命令黑名单关键词
const BLOCKED_CMDS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat",
    "bash", "sh", "zsh", "python", "perl", "ruby",
    "base64", "dd", "chmod", "chown", "rm -rf",
    "/bin/sh", "/bin/bash", "/usr/bin/python",
];

/// 可信路径白名单（允许执行）
const ALLOWED_PATHS: &[&str] = &[
    "/usr/bin/sendmail",
    "/usr/sbin/sendmail",
    "/usr/bin/convert",   // ImageMagick
    "/usr/bin/gs",        // Ghostscript
];

fn is_blocked(cmd: &str) -> bool {
    let cmd_lower = cmd.to_lowercase();
    // 白名单优先
    for allow in ALLOWED_PATHS {
        if cmd_lower.starts_with(allow) {
            return false;
        }
    }
    // 黑名单检测
    for blocked in BLOCKED_CMDS {
        if cmd_lower.contains(blocked) {
            return true;
        }
    }
    false
}

pub unsafe fn intercept_execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if path.is_null() {
        return call_real_execve(path, argv, envp);
    }

    let path_str = CStr::from_ptr(path).to_string_lossy();

    if is_blocked(&path_str) {
        stats::inc_cmd_block();
        eprintln!("[php-safe-core] ⛔ 命令注入拦截: {}", path_str);
        *libc::__errno_location() = libc::EPERM;
        return -1;
    }

    call_real_execve(path, argv, envp)
}

pub unsafe fn intercept_popen(command: *const c_char, mode: *const c_char) -> *mut FILE {
    if command.is_null() {
        return call_real_popen(command, mode);
    }

    let cmd_str = CStr::from_ptr(command).to_string_lossy();

    if is_blocked(&cmd_str) {
        stats::inc_cmd_block();
        eprintln!("[php-safe-core] ⛔ popen 命令拦截: {}", cmd_str);
        *libc::__errno_location() = libc::EPERM;
        return std::ptr::null_mut();
    }

    call_real_popen(command, mode)
}

unsafe fn call_real_execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    extern "C" {
        fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int;
    }
    execve(path, argv, envp)
}

unsafe fn call_real_popen(command: *const c_char, mode: *const c_char) -> *mut FILE {
    extern "C" {
        fn popen(command: *const c_char, mode: *const c_char) -> *mut FILE;
    }
    popen(command, mode)
}
