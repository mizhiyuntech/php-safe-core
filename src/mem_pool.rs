//! High-performance memory pool for internal use only.
//! Uses a lock-free slab allocator for fixed-size objects
//! and a shared arena for variable-size allocations.
//! This pool is ONLY used by php-safe-core internals, NOT PHP itself.

use std::sync::atomic::{AtomicUsize, AtomicPtr, Ordering};
use std::alloc::{alloc, dealloc, Layout};
use once_cell::sync::Lazy;

/// Slab slot size tiers (bytes)
const TIERS: &[usize] = &[32, 64, 128, 256, 512, 1024];
const SLAB_CAPACITY: usize = 4096; // slots per slab

/// A single lock-free free-list slab for one size tier
struct Slab {
    tier: usize,
    stack: [AtomicPtr<u8>; SLAB_CAPACITY],
    top: AtomicUsize,
    alloc_count: AtomicUsize,
    reuse_count: AtomicUsize,
}

unsafe impl Send for Slab {}
unsafe impl Sync for Slab {}

impl Slab {
    fn new(tier: usize) -> Self {
        // Pre-allocate all slots upfront
        let stack: [AtomicPtr<u8>; SLAB_CAPACITY] =
            std::array::from_fn(|_| AtomicPtr::new(std::ptr::null_mut()));

        let slab = Self {
            tier,
            stack,
            top: AtomicUsize::new(0),
            alloc_count: AtomicUsize::new(0),
            reuse_count: AtomicUsize::new(0),
        };

        // Pre-populate the free list
        for i in 0..SLAB_CAPACITY {
            let layout = Layout::from_size_align(tier, 8).unwrap();
            let ptr = unsafe { alloc(layout) };
            if !ptr.is_null() {
                slab.stack[i].store(ptr, Ordering::Relaxed);
            }
        }
        slab.top.store(SLAB_CAPACITY, Ordering::Release);
        slab
    }

    /// Pop a slot from the free list (lock-free)
    fn pop(&self) -> Option<*mut u8> {
        loop {
            let top = self.top.load(Ordering::Acquire);
            if top == 0 { return None; }
            match self.top.compare_exchange(top, top - 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    let ptr = self.stack[top - 1].swap(std::ptr::null_mut(), Ordering::AcqRel);
                    if !ptr.is_null() {
                        self.reuse_count.fetch_add(1, Ordering::Relaxed);
                        return Some(ptr);
                    }
                }
                Err(_) => continue,
            }
        }
    }

    /// Push a slot back to the free list (lock-free)
    fn push(&self, ptr: *mut u8) -> bool {
        loop {
            let top = self.top.load(Ordering::Acquire);
            if top >= SLAB_CAPACITY { return false; }
            match self.top.compare_exchange(top, top + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    self.stack[top].store(ptr, Ordering::Release);
                    return true;
                }
                Err(_) => continue,
            }
        }
    }

    fn alloc(&self) -> *mut u8 {
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        if let Some(ptr) = self.pop() {
            return ptr;
        }
        // Slab exhausted: fallback to system alloc
        let layout = Layout::from_size_align(self.tier, 8).unwrap();
        unsafe { alloc(layout) }
    }

    fn free(&self, ptr: *mut u8) {
        if !self.push(ptr) {
            // Slab full: return to system
            let layout = Layout::from_size_align(self.tier, 8).unwrap();
            unsafe { dealloc(ptr, layout) };
        }
    }
}

/// Global pool of slabs, one per tier
pub struct MemPool {
    slabs: Vec<Slab>,
    pub total_allocs: AtomicUsize,
    pub total_reuses: AtomicUsize,
}

unsafe impl Send for MemPool {}
unsafe impl Sync for MemPool {}

impl MemPool {
    fn new() -> Self {
        Self {
            slabs: TIERS.iter().map(|&t| Slab::new(t)).collect(),
            total_allocs: AtomicUsize::new(0),
            total_reuses: AtomicUsize::new(0),
        }
    }

    fn tier_index(size: usize) -> Option<usize> {
        TIERS.iter().position(|&t| size <= t)
    }

    pub fn alloc(&self, size: usize) -> *mut u8 {
        self.total_allocs.fetch_add(1, Ordering::Relaxed);
        if let Some(idx) = Self::tier_index(size) {
            let ptr = self.slabs[idx].alloc();
            if self.slabs[idx].reuse_count.load(Ordering::Relaxed) > 0 {
                self.total_reuses.fetch_add(1, Ordering::Relaxed);
            }
            return ptr;
        }
        // Large alloc: direct system
        let layout = Layout::from_size_align(size, 8).unwrap();
        unsafe { alloc(layout) }
    }

    pub fn free(&self, ptr: *mut u8, size: usize) {
        if ptr.is_null() { return; }
        if let Some(idx) = Self::tier_index(size) {
            self.slabs[idx].free(ptr);
            return;
        }
        let layout = Layout::from_size_align(size, 8).unwrap();
        unsafe { dealloc(ptr, layout) };
    }

    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_allocs: self.total_allocs.load(Ordering::Relaxed),
            total_reuses: self.total_reuses.load(Ordering::Relaxed),
            tiers: TIERS.iter().enumerate().map(|(i, &size)| TierStat {
                size,
                allocs: self.slabs[i].alloc_count.load(Ordering::Relaxed),
                reuses: self.slabs[i].reuse_count.load(Ordering::Relaxed),
                free_slots: self.slabs[i].top.load(Ordering::Relaxed),
            }).collect(),
        }
    }
}

pub struct PoolStats {
    pub total_allocs: usize,
    pub total_reuses: usize,
    pub tiers: Vec<TierStat>,
}

pub struct TierStat {
    pub size: usize,
    pub allocs: usize,
    pub reuses: usize,
    pub free_slots: usize,
}

pub static POOL: Lazy<MemPool> = Lazy::new(MemPool::new);

pub fn init() {
    let s = POOL.stats();
    eprintln!(
        "[php-safe-core] MemPool ready: {} tiers, {} slots/tier pre-allocated",
        s.tiers.len(), SLAB_CAPACITY
    );
}
