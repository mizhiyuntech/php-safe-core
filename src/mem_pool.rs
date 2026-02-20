//! 内存池模块
//!
//! PHP 频繁分配/释放小块内存（zval、HashTable 桶等），
//! 标准 glibc malloc 在高并发下存在锁竞争。
//!
//! 本模块实现分级内存池（Slab Allocator）：
//!   - 小块 (≤64B)：固定 slab，零锁路径
//!   - 中块 (≤4KB)：分级 free-list
//!   - 大块 (>4KB)：直接 mmap，绕过 brk 碎片

use libc::{c_void, size_t, mmap, munmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FAILED};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use crate::stats;

const SMALL_MAX: usize = 64;
const MEDIUM_MAX: usize = 4096;
const SLAB_COUNT: usize = 8; // 8, 16, 24, 32, 40, 48, 56, 64
const SLAB_SLAB_SIZE: usize = 65536; // 64KB per slab page

struct Slab {
    free_list: Vec<*mut u8>,
    obj_size: usize,
}

unsafe impl Send for Slab {}

struct Pool {
    slabs: [Mutex<Slab>; SLAB_COUNT],
    medium_free: [Mutex<Vec<*mut u8>>; 7], // 128,256,512,1024,2048,4096
}

unsafe impl Send for Pool {}
unsafe impl Sync for Pool {}

static POOL: Lazy<Pool> = Lazy::new(|| {
    Pool {
        slabs: std::array::from_fn(|i| {
            Mutex::new(Slab {
                free_list: Vec::new(),
                obj_size: (i + 1) * 8,
            })
        }),
        medium_free: std::array::from_fn(|_| Mutex::new(Vec::new())),
    }
});

/// 初始化内存池
pub fn init() {
    // 预热 slab：为每个 slab 预分配第一页
    for i in 0..SLAB_COUNT {
        let obj_size = (i + 1) * 8;
        let _ = fill_slab(i, obj_size);
    }
}

fn fill_slab(idx: usize, obj_size: usize) -> bool {
    let page = unsafe {
        mmap(
            std::ptr::null_mut(),
            SLAB_SLAB_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == MAP_FAILED {
        return false;
    }
    let mut slab = POOL.slabs[idx].lock();
    let count = SLAB_SLAB_SIZE / obj_size;
    for j in 0..count {
        let ptr = unsafe { (page as *mut u8).add(j * obj_size) };
        slab.free_list.push(ptr);
    }
    true
}

/// 分配内存
pub unsafe fn alloc(size: size_t) -> *mut c_void {
    if size == 0 {
        return std::ptr::null_mut();
    }

    if size <= SMALL_MAX {
        let idx = (size.saturating_sub(1)) / 8;
        let obj_size = (idx + 1) * 8;
        {
            let mut slab = POOL.slabs[idx].lock();
            if let Some(ptr) = slab.free_list.pop() {
                stats::add_memory_saved(obj_size.saturating_sub(size));
                return ptr as *mut c_void;
            }
        }
        // slab 空了，重新填充
        fill_slab(idx, obj_size);
        let mut slab = POOL.slabs[idx].lock();
        if let Some(ptr) = slab.free_list.pop() {
            return ptr as *mut c_void;
        }
    } else if size <= MEDIUM_MAX {
        let idx = medium_index(size);
        let bucket_size = medium_bucket_size(idx);
        {
            let mut bucket = POOL.medium_free[idx].lock();
            if let Some(ptr) = bucket.pop() {
                stats::add_memory_saved(bucket_size.saturating_sub(size));
                return ptr as *mut c_void;
            }
        }
    }

    // 大块或无空闲：直接 mmap
    let ptr = mmap(
        std::ptr::null_mut(),
        size + std::mem::size_of::<usize>(),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if ptr == MAP_FAILED {
        return std::ptr::null_mut();
    }
    // 在头部存储 size，供 free 使用
    *(ptr as *mut usize) = size;
    (ptr as *mut u8).add(std::mem::size_of::<usize>()) as *mut c_void
}

/// 释放内存（归还池或 munmap）
pub unsafe fn dealloc(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    // 尝试从头部读取 size（大块路径）
    let header_ptr = (ptr as *mut u8).sub(std::mem::size_of::<usize>());
    let stored_size = *(header_ptr as *mut usize);

    if stored_size > MEDIUM_MAX {
        munmap(header_ptr as *mut c_void, stored_size + std::mem::size_of::<usize>());
        return;
    }

    if stored_size <= SMALL_MAX && stored_size > 0 {
        let idx = (stored_size.saturating_sub(1)) / 8;
        let mut slab = POOL.slabs[idx].lock();
        slab.free_list.push(ptr as *mut u8);
        return;
    }

    if stored_size <= MEDIUM_MAX && stored_size > SMALL_MAX {
        let idx = medium_index(stored_size);
        let mut bucket = POOL.medium_free[idx].lock();
        bucket.push(ptr as *mut u8);
        return;
    }

    // 降级：使用系统 free
    libc_free(ptr);
}

/// realloc 实现
pub unsafe fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    if ptr.is_null() {
        return alloc(size);
    }
    if size == 0 {
        dealloc(ptr);
        return std::ptr::null_mut();
    }
    let new_ptr = alloc(size);
    if !new_ptr.is_null() {
        // 保守 copy：复制 size 字节
        std::ptr::copy_nonoverlapping(ptr as *const u8, new_ptr as *mut u8, size);
        dealloc(ptr);
    }
    new_ptr
}

fn medium_index(size: usize) -> usize {
    match size {
        0..=128 => 0,
        129..=256 => 1,
        257..=512 => 2,
        513..=1024 => 3,
        1025..=2048 => 4,
        2049..=4096 => 5,
        _ => 6,
    }
}

fn medium_bucket_size(idx: usize) -> usize {
    [128, 256, 512, 1024, 2048, 4096, 8192][idx.min(6)]
}

unsafe fn libc_free(ptr: *mut c_void) {
    // 直接调用真正的 free（通过 dlsym 或 #[link] 绕过）
    extern "C" {
        fn free(ptr: *mut c_void);
    }
    free(ptr)
}
