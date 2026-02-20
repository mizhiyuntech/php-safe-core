#!/bin/bash
# ============================================================
# php-safe-core 安装/更新脚本 v2.0
# 用法: chmod +x install.sh && sudo ./install.sh
# ============================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

SO_NAME="libphp_safe_core.so"
INSTALL_DIR="/usr/local/lib"
SO_TARGET="$INSTALL_DIR/$SO_NAME"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ── 标题 ───────────────────────────────────────────────────
echo -e "${CYAN}"
echo "=================================================="
echo "   php-safe-core 安全处理器 v0.2.0"
echo "   功能: RC防护 | 命令拦截 | 文件监控"
echo "         频率限制 | 敏感信息保护"
echo "=================================================="
echo -e "${NC}"

echo -e "${YELLOW}[警告] 本工具建议仅在【测试环境】使用。${NC}"
echo -e "${YELLOW}       生产环境请充分验证后再部署，以防服务崩溃。${NC}"
echo ""

# ── 菜单 ───────────────────────────────────────────────────
echo "请选择操作："
echo "  1) 全新安装"
echo "  2) 更新程序（替换 .so 文件）"
echo "  3) 卸载"
echo "  0) 退出"
echo ""
printf "请输入选项 [0-3]: "
read -r CHOICE
echo ""
CHOICE=$(printf '%s' "$CHOICE" | tr -d '[:space:]' | tr -d '\r\n')

case "$CHOICE" in
    1) MODE="install" ;;
    2) MODE="update" ;;
    3) MODE="uninstall" ;;
    0) echo "已退出。"; exit 0 ;;
    *) echo -e "${RED}无效选项，已退出。${NC}"; exit 1 ;;
esac

# ── Root 检查 ───────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[错误] 请使用 root 权限运行: sudo ./install.sh${NC}"
    exit 1
fi

# ══════════════════════════════════════════════════════════
# 卸载
# ══════════════════════════════════════════════════════════
if [ "$MODE" = "uninstall" ]; then
    echo -e "${CYAN}[*] 正在卸载 php-safe-core ...${NC}"

    rm -f "$SO_TARGET" && echo -e "${GREEN}[OK] 已删除 $SO_TARGET${NC}"
    rm -f "/etc/profile.d/php-safe-core.sh" && echo -e "${GREEN}[OK] 已删除 profile.d 配置${NC}"

    if [ -f /etc/environment ]; then
        sed -i '/LD_PRELOAD.*php_safe_core/d' /etc/environment
        echo -e "${GREEN}[OK] 已从 /etc/environment 移除 LD_PRELOAD${NC}"
    fi

    # 移除 systemd drop-in
    for CONF in /etc/systemd/system/*.service.d/php-safe-core.conf; do
        [ -f "$CONF" ] && rm -f "$CONF" && echo -e "${GREEN}[OK] 已删除 $CONF${NC}"
    done
    systemctl daemon-reload 2>/dev/null || true

    echo ""
    echo -e "${YELLOW}[提示] 请从面板手动重启 PHP 服务使卸载生效。${NC}"
    exit 0
fi

# ══════════════════════════════════════════════════════════
# 安装 / 更新
# ══════════════════════════════════════════════════════════

# 检查 .so 文件
if [ ! -f "$SO_NAME" ]; then
    echo -e "${RED}[错误] 未找到 $SO_NAME，请将 .so 文件与本脚本放在同一目录。${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] 找到 $SO_NAME${NC}"

# 检查 PHP
if ! command -v php &>/dev/null; then
    echo -e "${RED}[错误] 未检测到 PHP，请先安装 PHP。${NC}"
    exit 1
fi
PHP_VERSION=$(php -r 'echo PHP_VERSION;')
echo -e "${GREEN}[OK] 检测到 PHP $PHP_VERSION${NC}"

# 备份旧版本
echo ""
echo -e "${CYAN}[*] 正在安装 $SO_NAME ...${NC}"
mkdir -p "$INSTALL_DIR"
if [ -f "$SO_TARGET" ]; then
    cp "$SO_TARGET" "${SO_TARGET}${BACKUP_SUFFIX}"
    echo -e "${YELLOW}[备份] 旧版本已备份: ${SO_TARGET}${BACKUP_SUFFIX}${NC}"
fi

cp "$SO_NAME" "$SO_TARGET"
chmod 755 "$SO_TARGET"
ldconfig 2>/dev/null || true
echo -e "${GREEN}[OK] 已安装至 $SO_TARGET${NC}"

# 验证 .so
echo ""
echo -e "${CYAN}[*] 验证 .so 能否被 PHP 正常加载 ...${NC}"
LOAD_TEST=$(LD_PRELOAD="$SO_TARGET" php -r 'echo "php-safe-core-ok";' 2>&1) || true
if echo "$LOAD_TEST" | grep -q "php-safe-core-ok" 2>/dev/null; then
    echo -e "${GREEN}[OK] 验证通过，PHP 可正常加载 .so${NC}"
    VERIFIED=1
else
    echo -e "${RED}[失败] .so 加载验证失败，错误信息:${NC}"
    echo "$LOAD_TEST"
    echo -e "${YELLOW}[提示] 请检查 .so 架构是否与服务器匹配 (x86_64 / aarch64)${NC}"
    VERIFIED=0
fi

# 仅全新安装时注入全局 LD_PRELOAD
if [ "$MODE" = "install" ]; then
    echo ""
    echo -e "${CYAN}[*] 注入 LD_PRELOAD 到系统环境 ...${NC}"

    ENV_FILE="/etc/environment"
    if grep -q "LD_PRELOAD" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|.*LD_PRELOAD.*|LD_PRELOAD=$SO_TARGET|" "$ENV_FILE"
        echo -e "${GREEN}[OK] 已更新 $ENV_FILE${NC}"
    else
        echo "LD_PRELOAD=$SO_TARGET" >> "$ENV_FILE"
        echo -e "${GREEN}[OK] 已写入 $ENV_FILE${NC}"
    fi

    PROFILE_FILE="/etc/profile.d/php-safe-core.sh"
    echo "export LD_PRELOAD=$SO_TARGET" > "$PROFILE_FILE"
    chmod 644 "$PROFILE_FILE"
    echo -e "${GREEN}[OK] 已写入 $PROFILE_FILE${NC}"

    # systemd drop-in 注入
    if command -v systemctl &>/dev/null; then
        PHP_SERVICES=$(systemctl list-units --type=service --no-pager 2>/dev/null \
            | grep -oE 'php[0-9.]*[-_]fpm[^ ]*' | sed 's/\.service//' | sort -u)
        for SVC in $PHP_SERVICES; do
            OVERRIDE_DIR="/etc/systemd/system/${SVC}.service.d"
            mkdir -p "$OVERRIDE_DIR"
            cat > "$OVERRIDE_DIR/php-safe-core.conf" << EOF
[Service]
Environment="LD_PRELOAD=$SO_TARGET"
EOF
            echo -e "${GREEN}[OK] 已写入 systemd drop-in: $OVERRIDE_DIR/php-safe-core.conf${NC}"
        done
        systemctl daemon-reload 2>/dev/null || true
    fi
fi

# ── 汇总 ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}=================================================="
if [ "$MODE" = "install" ]; then
    echo "   安装完成"
else
    echo "   更新完成"
fi
echo "=================================================="
echo -e "${NC}"
echo "  .so 路径  : $SO_TARGET"
echo "  PHP 版本  : $PHP_VERSION"
if [ "$VERIFIED" -eq 1 ]; then
    echo -e "  加载验证  : ${GREEN}通过${NC}"
else
    echo -e "  加载验证  : ${RED}失败，请检查架构${NC}"
fi
echo ""
echo -e "${YELLOW}[提示] 请从面板手动重启 PHP 服务使变更生效。${NC}"
echo -e "${YELLOW}       重启后执行以下命令确认运行状态:${NC}"
echo -e "  ${CYAN}journalctl -u php-fpm-83 --no-pager | grep php-safe-core${NC}"
echo ""
