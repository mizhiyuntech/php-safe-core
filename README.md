# php-safe-core

**PHP 底层安全处理器** — 用 Rust 编写的动态库，通过 `LD_PRELOAD` 劫持 PHP 运行时，在不修改 PHP 源码或扩展的前提下：

- ✅ 修复 **RC（引用计数）漏洞**（double-free / use-after-free / RC溢出/下溢）
- ✅ 引入 **Slab 内存池**，降低 malloc 锁竞争，提升 PHP 内存分配性能
- ✅ 提供实时统计接口（JSON）
- ✅ 支持 GitHub Actions 自动编译 `.so`，开箱即用

---

## 工作原理

```
PHP 进程启动
     │
     ▼
LD_PRELOAD 加载 libphp_safe_core.so
     │
     ├─► 替换 malloc / free / realloc / calloc
     │       └─► Slab 分级内存池（小块零锁、大块 mmap）
     │
     ├─► 注册 RC 钩子（addref / delref）
     │       └─► 检测 double-free / use-after-free / 溢出
     │
     └─► 统计模块记录运行指标
```

---

## 快速开始

### 方式一：使用预编译 `.so`（推荐）

从 [Releases](../../releases) 下载对应架构的 `.so` 文件：

```
libphp_safe_core.so         # x86_64 Linux
libphp_safe_core_aarch64.so # ARM64 Linux
```

**使 PHP-FPM 加载（推荐生产用法）：**

```bash
# 复制到系统目录
sudo cp libphp_safe_core.so /usr/local/lib/

# 方法 A：PHP-FPM 全局注入
# 编辑 /etc/php/8.x/fpm/pool.d/www.conf，添加：
env[LD_PRELOAD] = /usr/local/lib/libphp_safe_core.so

# 重启 FPM
sudo systemctl restart php8.2-fpm

# 方法 B：单次测试
LD_PRELOAD=/usr/local/lib/libphp_safe_core.so php your_script.php
```

**使 Apache+mod_php 加载：**

```bash
# 编辑 /etc/apache2/envvars，添加：
export LD_PRELOAD=/usr/local/lib/libphp_safe_core.so

sudo systemctl restart apache2
```

**Nginx + PHP-FPM Docker 示例：**

```dockerfile
FROM php:8.2-fpm
COPY libphp_safe_core.so /usr/local/lib/
ENV LD_PRELOAD=/usr/local/lib/libphp_safe_core.so
```

---

### 方式二：本地编译

```bash
# 依赖：Rust 1.75+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/yourname/php-safe-core
cd php-safe-core
cargo build --release

# 产物
ls target/release/libphp_safe_core.so
```

---

## 查看统计数据

库提供 C 可调用接口，也可通过 PHP FFI 查询：

```php
<?php
// 需要 PHP FFI 扩展 + 已加载 libphp_safe_core.so
$ffi = FFI::cdef('
    size_t php_safe_stats_json(char *buf, size_t len);
', '/usr/local/lib/libphp_safe_core.so');

$buf = FFI::new('char[512]');
$len = $ffi->php_safe_stats_json($buf, 512);
$json = FFI::string($buf, $len);

$stats = json_decode($json, true);
echo "RC 拦截次数: {$stats['rc_intercepts']}\n";
echo "内存节省: " . round($stats['memory_saved_bytes'] / 1024, 2) . " KB\n";
```

---

## GitHub Actions 自动编译

推送 tag 即可触发自动构建并发布 Release：

```bash
git tag v1.0.0
git push origin v1.0.0
```

Actions 将自动编译 `x86_64` 和 `aarch64` 两个版本，上传到 GitHub Release。

---

## 文件结构

```
php-safe-core/
├── Cargo.toml              # 依赖配置（极简：libc, once_cell, dashmap, parking_lot）
├── src/
│   ├── lib.rs              # 入口 + LD_PRELOAD 钩子
│   ├── rc_guard.rs         # RC漏洞防护（double-free/use-after-free/溢出）
│   ├── mem_pool.rs         # Slab 分级内存池
│   ├── hooks.rs            # 自动 constructor/destructor + VTable
│   └── stats.rs            # 原子统计计数器
└── .github/workflows/
    └── build.yml           # CI/CD 多架构编译
```

---

## 依赖说明

| 依赖 | 用途 |
|------|------|
| `libc` | 系统调用（mmap, munmap 等） |
| `once_cell` | 全局懒初始化 |
| `parking_lot` | 高性能 Mutex（比标准库快 ~3x） |
| `dashmap` | 并发 HashMap（freed 指针集合） |

---

## 注意事项

- **仅支持 Linux**（依赖 `LD_PRELOAD` 机制和 `mmap`）
- macOS 理论可行但未测试（SIP 可能阻止 LD_PRELOAD）
- Windows 不支持（无 LD_PRELOAD）
- 建议先在**测试环境**验证后再上生产
- 与 Xdebug、Valgrind 同时使用时可能有冲突

---

## License

MIT
