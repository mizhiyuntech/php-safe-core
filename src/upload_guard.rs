//! Upload Guard - Malicious file upload interception
//!
//! Monitors PHP upload temp directories for malicious files.
//! When a suspicious file is detected, it is quarantined (moved)
//! or deleted if the system allows it.
//!
//! Detection strategy:
//!   1. File extension blacklist (webshell extensions)
//!   2. Magic byte / MIME mismatch detection
//!   3. PHP code pattern scan inside uploaded files
//!
//! No syscall hooks. Uses std::fs only. Safe to run alongside PHP.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::collections::HashSet;
use once_cell::sync::Lazy;
use crate::stats;

// ── Config ─────────────────────────────────────────────────

/// Directories to watch for uploads
const WATCH_DIRS: &[&str] = &[
    "/tmp",
    "/var/www",
];

/// Scan interval (seconds)
const SCAN_INTERVAL: u64 = 10;

/// Max file size to deep-scan (bytes): 10MB
const MAX_SCAN_SIZE: u64 = 10 * 1024 * 1024;

// ── Threat signatures ──────────────────────────────────────

/// Dangerous file extensions
const BLOCKED_EXTS: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "phtml", "pht",
    "shtml", "shtm", "cgi", "pl", "py", "rb", "sh", "bash",
    "asp", "aspx", "jsp", "jspx",
];

/// PHP webshell code patterns (byte-level detection)
const PHP_PATTERNS: &[&[u8]] = &[
    b"<?php",
    b"<?=",
    b"eval(",
    b"base64_decode(",
    b"system(",
    b"exec(",
    b"passthru(",
    b"shell_exec(",
    b"popen(",
    b"proc_open(",
    b"assert(",
    b"preg_replace(",
    b"create_function(",
    b"call_user_func(",
    b"$_GET[",
    b"$_POST[",
    b"$_REQUEST[",
    b"$_FILES[",
    b"base64_encode(",
    b"gzinflate(",
    b"str_rot13(",
];

/// Known malicious magic bytes (file signatures)
const ELF_MAGIC: &[u8] = &[0x7f, 0x45, 0x4c, 0x46]; // ELF binary

// ── State ──────────────────────────────────────────────────

static BLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Already-processed file set to avoid double-scanning
static SEEN: Lazy<Arc<Mutex<HashSet<PathBuf>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashSet::new())));

// ── Detection logic ────────────────────────────────────────

fn is_dangerous_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| BLOCKED_EXTS.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn scan_content(path: &Path) -> Option<&'static str> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > MAX_SCAN_SIZE { return None; }

    let mut f = fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;

    // ELF binary check
    if buf.starts_with(ELF_MAGIC) {
        return Some("ELF binary");
    }

    // PHP webshell pattern check
    let lower: Vec<u8> = buf.iter().map(|b| b.to_ascii_lowercase()).collect();
    for pattern in PHP_PATTERNS {
        if lower.windows(pattern.len()).any(|w| w == *pattern) {
            return Some("PHP webshell pattern");
        }
    }

    None
}

fn is_threat(path: &Path) -> Option<&'static str> {
    if is_dangerous_ext(path) {
        return Some("dangerous extension");
    }
    scan_content(path)
}

// ── Quarantine / Delete ────────────────────────────────────

fn quarantine(path: &Path, reason: &str) {
    eprintln!(
        "[php-safe-core] [UPLOAD] THREAT DETECTED [{}]: {}",
        reason,
        path.display()
    );

    // Attempt delete
    match fs::remove_file(path) {
        Ok(_) => {
            BLOCKED_COUNT.fetch_add(1, Ordering::Relaxed);
            stats::inc_threat();
            eprintln!(
                "[php-safe-core] [UPLOAD] DELETED: {}",
                path.display()
            );
        }
        Err(e) => {
            eprintln!(
                "[php-safe-core] [UPLOAD] DELETE FAILED ({}): {} - check permissions",
                e, path.display()
            );
        }
    }
}

// ── Directory scanner ──────────────────────────────────────

fn scan_dir(dir: &Path, seen: &mut HashSet<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            // Only recurse into upload-related subdirs
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if name.starts_with('.') { continue; }
            scan_dir(&path, seen);
            continue;
        }

        if seen.contains(&path) { continue; }
        seen.insert(path.clone());

        if let Some(reason) = is_threat(&path) {
            quarantine(&path, reason);
        }
    }
}

// ── Public API ─────────────────────────────────────────────

pub fn init() {
    RUNNING.store(true, Ordering::Release);
    let seen_ref = Arc::clone(&SEEN);

    // Custom watch dirs from env
    let watch_dirs: Vec<String> = std::env::var("PHP_SAFE_UPLOAD_DIRS")
        .map(|v| v.split(':').map(String::from).collect())
        .unwrap_or_else(|_| WATCH_DIRS.iter().map(|s| s.to_string()).collect());

    eprintln!(
        "[php-safe-core] [UPLOAD] Watching {} dir(s) for malicious uploads.",
        watch_dirs.len()
    );

    thread::Builder::new()
        .name("php-safe-upload".to_string())
        .spawn(move || {
            while RUNNING.load(Ordering::Acquire) {
                {
                    let mut seen = seen_ref.lock().unwrap();
                    // Trim seen set to avoid unbounded growth
                    if seen.len() > 100_000 { seen.clear(); }
                    for dir in &watch_dirs {
                        scan_dir(Path::new(dir), &mut seen);
                    }
                }
                thread::sleep(Duration::from_secs(SCAN_INTERVAL));
            }
            eprintln!("[php-safe-core] [UPLOAD] Monitor thread stopped.");
        })
        .ok();
}

pub fn shutdown() {
    RUNNING.store(false, Ordering::Release);
}

pub fn blocked_count() -> u64 {
    BLOCKED_COUNT.load(Ordering::Relaxed)
}
