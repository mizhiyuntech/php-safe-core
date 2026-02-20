#!/bin/bash
# ============================================================
# php-safe-core 安装脚本
# 用法：chmod +x install.sh && ./install.sh
# 注意：仅建议在测试环境使用，生产环境请充分验证后再部署
# ============================================================

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

SO_NAME="libphp_safe_core.so"
INSTALL_DIR="/usr/local/lib"
SO_TARGET="$INSTALL_DIR/$SO_NAME"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

echo -e "${CYAN}"
echo "=================================================="
echo "   php-safe-core 安装脚本"
echo "=================================================="
echo -e "${NC}"

# ── 警告提示 ──────────────────────────────────────────
echo -e "${YELLOW}⚠  警告：本工具建议仅在【测试环境】使用。${NC}"
echo -e "${YELLOW}   生产环境部署前请确保已充分验证，以防项目崩溃。${NC}"
echo ""
read -rp "确认继续安装？(输入 yes 继续，其他任意键退出): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "已取消安装。"
    exit 0
fi
echo ""

# ── 检查 root 权限 ────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ 请以 root 权限运行本脚本（sudo ./install.sh）${NC}"
    exit 1
fi

# ── 检查 .so 文件是否存在 ─────────────────────────────
if [ ! -f "$SO_NAME" ]; then
    echo -e "${RED}✗ 未找到 $SO_NAME，请将 .so 文件与本脚本放在同一目录下。${NC}"
    exit 1
fi
echo -e "${GREEN}✔ 找到 $SO_NAME${NC}"

# ── 检查 PHP 是否安装 ─────────────────────────────────
if ! command -v php &>/dev/null; then
    echo -e "${RED}✗ 未检测到 PHP，请先安装 PHP 后再运行本脚本。${NC}"
    exit 1
fi
PHP_VERSION=$(php -r 'echo PHP_VERSION;')
echo -e "${GREEN}✔ 检测到 PHP 版本：$PHP_VERSION${NC}"

# ── 复制 .so 到系统目录 ───────────────────────────────
echo ""
echo -e "${CYAN}► 正在安装 $SO_NAME 到 $INSTALL_DIR ...${NC}"

# 若旧版本存在则备份
if [ -f "$SO_TARGET" ]; then
    cp "$SO_TARGET" "${SO_TARGET}${BACKUP_SUFFIX}"
    echo -e "${YELLOW}  已备份旧版本 → ${SO_TARGET}${BACKUP_SUFFIX}${NC}"
fi

cp "$SO_NAME" "$SO_TARGET"
chmod 755 "$SO_TARGET"
echo -e "${GREEN}✔ $SO_NAME 已安装至 $SO_TARGET${NC}"

# ── 刷新动态库缓存 ────────────────────────────────────
ldconfig
echo -e "${GREEN}✔ ldconfig 缓存已刷新${NC}"

# ── 检测 PHP 运行模式并注入 LD_PRELOAD ───────────────
echo ""
echo -e "${CYAN}► 正在检测 PHP 运行模式并注入 LD_PRELOAD ...${NC}"

INJECTED=0

# PHP-FPM
FPM_CONF=$(find /etc/php* /etc/php-fpm* /usr/local/etc/php* -name "www.conf" 2>/dev/null | head -1)
if [ -n "$FPM_CONF" ]; then
    if grep -q "LD_PRELOAD" "$FPM_CONF"; then
        sed -i "s|.*env\[LD_PRELOAD\].*|env[LD_PRELOAD] = $SO_TARGET|" "$FPM_CONF"
        echo -e "${GREEN}✔ 已更新 PHP-FPM 配置：$FPM_CONF${NC}"
    else
        echo "" >> "$FPM_CONF"
        echo "env[LD_PRELOAD] = $SO_TARGET" >> "$FPM_CONF"
        echo -e "${GREEN}✔ 已写入 PHP-FPM 配置：$FPM_CONF${NC}"
    fi
    INJECTED=1

    # 重启 PHP-FPM
    if command -v systemctl &>/dev/null; then
        FPM_SERVICE=$(systemctl list-units --type=service --no-pager 2>/dev/null | grep -oE 'php[0-9.]*-fpm' | head -1)
        if [ -n "$FPM_SERVICE" ]; then
            systemctl restart "$FPM_SERVICE" && \
                echo -e "${GREEN}✔ 已重启 $FPM_SERVICE${NC}" || \
                echo -e "${YELLOW}⚠ 重启 $FPM_SERVICE 失败，请手动重启${NC}"
        fi
    fi
fi

# Apache mod_php
APACHE_ENVVARS=$(find /etc/apache2 /etc/httpd -name "envvars" 2>/dev/null | head -1)
if [ -n "$APACHE_ENVVARS" ]; then
    if grep -q "LD_PRELOAD" "$APACHE_ENVVARS"; then
        sed -i "s|.*LD_PRELOAD.*|export LD_PRELOAD=$SO_TARGET|" "$APACHE_ENVVARS"
    else
        echo "export LD_PRELOAD=$SO_TARGET" >> "$APACHE_ENVVARS"
    fi
    echo -e "${GREEN}✔ 已写入 Apache envvars：$APACHE_ENVVARS${NC}"
    INJECTED=1

    if command -v systemctl &>/dev/null && systemctl is-active apache2 &>/dev/null; then
        systemctl restart apache2 && \
            echo -e "${GREEN}✔ 已重启 Apache${NC}" || \
            echo -e "${YELLOW}⚠ 重启 Apache 失败，请手动重启${NC}"
    elif command -v systemctl &>/dev/null && systemctl is-active httpd &>/dev/null; then
        systemctl restart httpd && \
            echo -e "${GREEN}✔ 已重启 httpd${NC}" || \
            echo -e "${YELLOW}⚠ 重启 httpd 失败，请手动重启${NC}"
    fi
fi

# 未检测到任何已知运行模式
if [ "$INJECTED" -eq 0 ]; then
    echo -e "${YELLOW}⚠ 未自动检测到 PHP-FPM 或 Apache 配置文件。${NC}"
    echo -e "  请手动将以下内容添加到你的服务配置中：${NC}"
    echo ""
    echo -e "  ${CYAN}LD_PRELOAD=$SO_TARGET${NC}"
    echo ""
fi

# ── 验证加载 ──────────────────────────────────────────
echo ""
echo -e "${CYAN}► 验证 .so 可正常被 PHP 加载 ...${NC}"
LOAD_TEST=$(LD_PRELOAD="$SO_TARGET" php -r 'echo "ok";' 2>&1)
if echo "$LOAD_TEST" | grep -q "ok"; then
    echo -e "${GREEN}✔ 验证通过，PHP 可正常加载 $SO_NAME${NC}"
else
    echo -e "${RED}✗ 验证失败，输出如下：${NC}"
    echo "$LOAD_TEST"
    echo -e "${YELLOW}  建议检查 .so 架构是否与服务器匹配（x86_64 / aarch64）${NC}"
fi

# ── 完成 ──────────────────────────────────────────────
echo ""
echo -e "${GREEN}=================================================="
echo "   安装完成！"
echo "=================================================="
echo -e "${NC}"
echo "  .so 路径  : $SO_TARGET"
echo "  PHP 版本  : $PHP_VERSION"
echo ""
echo -e "${YELLOW}  如需卸载，删除 $SO_TARGET 并移除 LD_PRELOAD 配置后重启服务即可。${NC}"
echo ""
