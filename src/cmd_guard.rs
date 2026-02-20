//! Command injection guard module

use libc::{c_char, c_int, FILE};
use std::ffi::CStr;
use crate::stats;

const BLOCKED_CMDS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat",
    "bash", "sh", "zsh", "python", "perl", "ruby",
    "base64", "dd", "chmod", "chown", "rm -rf",
    "/bin/sh", "/bin/bash", "/usr/bin/python",
];

const ALLOWED_PATHS: &[&str] = &[
    "/usr/bin/sendmail",
    "/usr/sbin/sendmail",
    "/usr/bin/convert",
    "/usr/bin/gs",
];

fn is_blocked(cmd: &str) -> bool {
    let cmd_lower = cmd.to_lowercase();
    for allow in ALLOWED_PATHS {
        if cmd_lower.starts_with(allow) {
            return false;
        }
    }
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
        eprintln!("[php-safe-core] [BLOCK] CMD injection blocked: {}", path_str);
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
        eprintln!("[php-safe-core] [BLOCK] popen blocked: {}", cmd_str);
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
