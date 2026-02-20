//! 自动 constructor/destructor（库加载/卸载时触发）

#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
static CONSTRUCTOR: extern "C" fn() = {
    extern "C" fn init() { crate::php_safe_core_init(); }
    init
};

#[used]
#[cfg_attr(target_os = "linux", link_section = ".fini_array")]
static DESTRUCTOR: extern "C" fn() = {
    extern "C" fn fini() { crate::php_safe_core_shutdown(); }
    fini
};
