//! 系统钩子：利用 constructor/destructor 实现自动初始化
//!
//! 当 libphp_safe_core.so 通过 LD_PRELOAD 加载时，
//! __attribute__((constructor)) 等价函数会在 main() 之前自动执行。

use libc::c_void;

/// 库加载时自动调用（等价于 GCC __attribute__((constructor))）
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static CONSTRUCTOR: extern "C" fn() = {
    extern "C" fn init() {
        crate::php_safe_core_init();
    }
    init
};

/// 库卸载时自动调用（等价于 GCC __attribute__((destructor))）
#[used]
#[cfg_attr(target_os = "linux", link_section = ".fini_array")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_term_func")]
static DESTRUCTOR: extern "C" fn() = {
    extern "C" fn fini() {
        crate::php_safe_core_shutdown();
    }
    fini
};

/// 提供 PHP 扩展可调用的函数表（供 php-safe-ext 使用）
#[repr(C)]
pub struct SafeCoreVTable {
    pub addref: unsafe extern "C" fn(*mut u32) -> u32,
    pub delref: unsafe extern "C" fn(*mut u32, *mut c_void) -> u32,
    pub stats_json: unsafe extern "C" fn(*mut u8, usize) -> usize,
}

#[no_mangle]
pub static PHP_SAFE_CORE_VTABLE: SafeCoreVTable = SafeCoreVTable {
    addref: crate::php_safe_rc_addref,
    delref: crate::php_safe_rc_delref,
    stats_json: crate::php_safe_stats_json,
};
