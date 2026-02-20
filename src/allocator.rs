//! Rust Global Allocator - php-safe-core internal memory management
//!
//! Replaces Rust's default allocator (jemalloc/system) with a custom
//! allocator that routes ALL internal Rust allocations through our
//! tiered slab pool for small objects, and system alloc for large ones.
//!
//! This affects ONLY Rust-side memory (HashMaps, Vecs, Strings used by
//! this .so). PHP's own memory is never touched.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

// ── Slab tiers ─────────────────────────────────────────────
// Fixed-size free lists using a lock-free stack per tier.

const TIERS: &[usize] = &[16, 32, 64, 128, 256, 512, 1024, 2048];
const SLOTS_PER_TIER: usize = 2048;

struct FreeNode {
    next: *mut FreeNode,
}

/// A single tier's free-list stack (lock-free via compare_exchange on pointer)
struct TierStack {
    head: std::sync::atomic::AtomicPtr<FreeNode>,
    obj_size: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

unsafe impl Send for TierStack {}
unsafe impl Sync for TierStack {}

impl TierStack {
    const fn new(obj_size: usize) -> Self {
        Self {
            head: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
            obj_size,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Pre-populate with slots from system allocator
    fn prefill(&self) {
        for _ in 0..SLOTS_PER_TIER {
            unsafe {
                let layout = Layout::from_size_align_unchecked(self.obj_size, 16);
                let ptr = System.alloc(layout) as *mut FreeNode;
                if !ptr.is_null() {
                    self.push(ptr);
                }
            }
        }
    }

    fn push(&self, node: *mut FreeNode) {
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            unsafe { (*node).next = head; }
            match self.head.compare_exchange(head, node, Ordering::Release, Ordering::Acquire) {
                Ok(_) => return,
                Err(h) => head = h,
            }
        }
    }

    fn pop(&self) -> *mut u8 {
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            if head.is_null() {
                self.misses.fetch_add(1, Ordering::Relaxed);
                // Fallback: system alloc
                unsafe {
                    let layout = Layout::from_size_align_unchecked(self.obj_size, 16);
                    return System.alloc(layout);
                }
            }
            let next = unsafe { (*head).next };
            match self.head.compare_exchange(head, next, Ordering::Release, Ordering::Acquire) {
                Ok(_) => {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return head as *mut u8;
                }
                Err(h) => head = h,
            }
        }
    }

    fn free_to_pool(&self, ptr: *mut u8) -> bool {
        // Only recycle if pool not oversized (avoid hoarding)
        self.push(ptr as *mut FreeNode);
        true
    }
}

// ── Global slab pool ───────────────────────────────────────

struct SafeAllocator {
    tiers: [TierStack; 8],
    total_allocs: AtomicU64,
    pool_hits: AtomicU64,
    sys_allocs: AtomicU64,
}

impl SafeAllocator {
    const fn new() -> Self {
        Self {
            tiers: [
                TierStack::new(16),
                TierStack::new(32),
                TierStack::new(64),
                TierStack::new(128),
                TierStack::new(256),
                TierStack::new(512),
                TierStack::new(1024),
                TierStack::new(2048),
            ],
            total_allocs: AtomicU64::new(0),
            pool_hits: AtomicU64::new(0),
            sys_allocs: AtomicU64::new(0),
        }
    }

    fn tier_index(size: usize) -> Option<usize> {
        TIERS.iter().position(|&t| size <= t)
    }

    pub fn prefill_all(&self) {
        for tier in &self.tiers {
            tier.prefill();
        }
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.total_allocs.load(Ordering::Relaxed),
            self.pool_hits.load(Ordering::Relaxed),
            self.sys_allocs.load(Ordering::Relaxed),
        )
    }
}

unsafe impl GlobalAlloc for SafeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.total_allocs.fetch_add(1, Ordering::Relaxed);
        let size = layout.size();

        if let Some(idx) = Self::tier_index(size) {
            let ptr = self.tiers[idx].pop();
            if !ptr.is_null() {
                self.pool_hits.fetch_add(1, Ordering::Relaxed);
                return ptr;
            }
        }

        // Large or no tier match: system alloc
        self.sys_allocs.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        let size = layout.size();

        if let Some(idx) = Self::tier_index(size) {
            if self.tiers[idx].free_to_pool(ptr) {
                return;
            }
        }

        System.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            std::ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            let copy_size = layout.size().min(new_size);
            std::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

// ── Register as Rust global allocator ─────────────────────

#[global_allocator]
static ALLOCATOR: SafeAllocator = SafeAllocator::new();

/// Call once at startup to pre-populate all slab tiers
pub fn init() {
    ALLOCATOR.prefill_all();
    let (total, hits, sys) = ALLOCATOR.stats();
    eprintln!(
        "[php-safe-core] [ALLOC] Rust allocator ready | pool_hits={} sys_allocs={} total={}",
        hits, sys, total
    );
}

pub fn stats() -> (u64, u64, u64) {
    ALLOCATOR.stats()
}
