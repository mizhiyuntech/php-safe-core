//! Edge Guard - PHP file integrity protection
//!
//! On startup, scans PHP files under the watch path and stores
//! a SHA-256 fingerprint of each file in the internal memory pool.
//! A background thread periodically re-scans and compares hashes.
//! If tampering is detected, an alert is written to stderr (journald).
//!
//! No syscall hooks. No external commands. Pure Rust + std.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use once_cell::sync::Lazy;
use crate::stats;

/// Directory to watch (default: /var/www)
/// Can be overridden via env var PHP_SAFE_WATCH_PATH
const DEFAULT_WATCH_PATH: &str = "/var/www";

/// Scan interval in seconds
const SCAN_INTERVAL_SECS: u64 = 30;

/// Max files to track (prevent memory blowup on huge sites)
const MAX_FILES: usize = 50_000;

// ── Shared state ──────────────────────────────────────────

static TAMPER_COUNT: AtomicU64 = AtomicU64::new(0);
static NEW_FILE_COUNT: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(false);

/// path -> SHA-256 hex digest
type Snapshot = HashMap<PathBuf, String>;

static SNAPSHOT: Lazy<Arc<Mutex<Snapshot>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// ── Simple SHA-256 (pure Rust, no external crate) ─────────
// Implements FIPS 180-4 SHA-256

const K: [u32; 64] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh] =
            [h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
            a = t1.wrapping_add(t2);
        }

        h[0]=h[0].wrapping_add(a); h[1]=h[1].wrapping_add(b);
        h[2]=h[2].wrapping_add(c); h[3]=h[3].wrapping_add(d);
        h[4]=h[4].wrapping_add(e); h[5]=h[5].wrapping_add(f);
        h[6]=h[6].wrapping_add(g); h[7]=h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── File scanning ──────────────────────────────────────────

fn hash_file(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(to_hex(&sha256(&buf)))
}

fn scan_dir(root: &Path, snap: &mut Snapshot) {
    if snap.len() >= MAX_FILES { return; }
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, snap);
        } else if path.extension().and_then(|e| e.to_str()) == Some("php") {
            if let Some(hash) = hash_file(&path) {
                snap.insert(path, hash);
                if snap.len() >= MAX_FILES { return; }
            }
        }
    }
}

// ── Core logic ─────────────────────────────────────────────

fn build_snapshot(watch_path: &str) -> Snapshot {
    let mut snap = Snapshot::new();
    scan_dir(Path::new(watch_path), &mut snap);
    snap
}

fn compare_snapshot(old: &Snapshot, watch_path: &str) -> (u64, u64) {
    let new_snap = build_snapshot(watch_path);
    let mut tampered: u64 = 0;
    let mut new_files: u64 = 0;

    // Check existing files for modification
    for (path, old_hash) in old {
        match new_snap.get(path) {
            Some(new_hash) if new_hash != old_hash => {
                tampered += 1;
                stats::inc_threat();
                eprintln!(
                    "[php-safe-core] [EDGE] TAMPER DETECTED: {}",
                    path.display()
                );
            }
            None => {
                eprintln!(
                    "[php-safe-core] [EDGE] FILE DELETED: {}",
                    path.display()
                );
            }
            _ => {}
        }
    }

    // Check for newly added files
    for path in new_snap.keys() {
        if !old.contains_key(path) {
            new_files += 1;
            eprintln!(
                "[php-safe-core] [EDGE] NEW FILE: {}",
                path.display()
            );
        }
    }

    (tampered, new_files)
}

// ── Public API ─────────────────────────────────────────────

pub fn init() {
    let watch_path = std::env::var("PHP_SAFE_WATCH_PATH")
        .unwrap_or_else(|_| DEFAULT_WATCH_PATH.to_string());

    eprintln!("[php-safe-core] [EDGE] Scanning: {} ...", watch_path);

    let snap = build_snapshot(&watch_path);
    let file_count = snap.len();

    {
        let mut s = SNAPSHOT.lock().unwrap();
        *s = snap;
    }

    eprintln!(
        "[php-safe-core] [EDGE] Snapshot complete: {} PHP files indexed.",
        file_count
    );

    RUNNING.store(true, Ordering::Release);

    let snap_ref = Arc::clone(&SNAPSHOT);
    thread::Builder::new()
        .name("php-safe-edge".to_string())
        .spawn(move || {
            while RUNNING.load(Ordering::Acquire) {
                thread::sleep(Duration::from_secs(SCAN_INTERVAL_SECS));
                if !RUNNING.load(Ordering::Acquire) { break; }

                let watch = std::env::var("PHP_SAFE_WATCH_PATH")
                    .unwrap_or_else(|_| DEFAULT_WATCH_PATH.to_string());

                let old = snap_ref.lock().unwrap().clone();
                let (tampered, new_files) = compare_snapshot(&old, &watch);

                TAMPER_COUNT.fetch_add(tampered, Ordering::Relaxed);
                NEW_FILE_COUNT.fetch_add(new_files, Ordering::Relaxed);

                // Rebuild snapshot after each scan
                let new_snap = build_snapshot(&watch);
                *snap_ref.lock().unwrap() = new_snap;

                if tampered > 0 || new_files > 0 {
                    eprintln!(
                        "[php-safe-core] [EDGE] Scan done: {} tampered, {} new files.",
                        tampered, new_files
                    );
                }
            }
            eprintln!("[php-safe-core] [EDGE] Monitor thread stopped.");
        })
        .ok();
}

pub fn shutdown() {
    RUNNING.store(false, Ordering::Release);
}

pub fn tamper_count() -> u64 { TAMPER_COUNT.load(Ordering::Relaxed) }
pub fn new_file_count() -> u64 { NEW_FILE_COUNT.load(Ordering::Relaxed) }
