#!/bin/bash
# ============================================================
# php-safe-core installer
# Usage: chmod +x install.sh && sudo ./install.sh
# WARNING: Test environment only.
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
echo "   php-safe-core installer"
echo "=================================================="
echo -e "${NC}"

echo -e "${YELLOW}[WARNING] For TEST environment only.${NC}"
echo -e "${YELLOW}          Do NOT deploy to production without verification.${NC}"
echo ""
echo "Continue? (type y or yes to proceed)"
printf "> "
read -r CONFIRM
echo ""
CONFIRM=$(printf '%s' "$CONFIRM" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]' | tr -d '\r\n')
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "yes" ]; then
    echo "Installation cancelled."
    exit 0
fi

# ── Root check ─────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root: sudo ./install.sh${NC}"
    exit 1
fi

# ── Check .so file ─────────────────────────────────────────
if [ ! -f "$SO_NAME" ]; then
    echo -e "${RED}[ERROR] $SO_NAME not found in current directory.${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Found $SO_NAME${NC}"

# ── Check PHP ──────────────────────────────────────────────
if ! command -v php &>/dev/null; then
    echo -e "${RED}[ERROR] PHP not found.${NC}"
    exit 1
fi
PHP_BIN=$(command -v php)
PHP_VERSION=$(php -r 'echo PHP_VERSION;')
echo -e "${GREEN}[OK] PHP $PHP_VERSION ($PHP_BIN)${NC}"

# ── Install .so ────────────────────────────────────────────
echo ""
echo -e "${CYAN}[*] Installing $SO_NAME ...${NC}"
mkdir -p "$INSTALL_DIR"
if [ -f "$SO_TARGET" ]; then
    cp "$SO_TARGET" "${SO_TARGET}${BACKUP_SUFFIX}"
    echo -e "${YELLOW}[INFO] Old version backed up: ${SO_TARGET}${BACKUP_SUFFIX}${NC}"
fi
cp "$SO_NAME" "$SO_TARGET"
chmod 755 "$SO_TARGET"
ldconfig 2>/dev/null || true
echo -e "${GREEN}[OK] Installed: $SO_TARGET${NC}"

# ── Verify .so loads with PHP ──────────────────────────────
echo ""
echo -e "${CYAN}[*] Verifying .so loads correctly ...${NC}"
LOAD_TEST=$(LD_PRELOAD="$SO_TARGET" php -r 'echo "php-safe-core-ok";' 2>&1)
if echo "$LOAD_TEST" | grep -q "php-safe-core-ok"; then
    echo -e "${GREEN}[OK] .so verified: PHP loads it successfully.${NC}"
    VERIFIED=1
else
    echo -e "${RED}[FAIL] .so failed to load. Output:${NC}"
    echo "$LOAD_TEST"
    echo -e "${YELLOW}[HINT] Architecture mismatch? Use x86_64 .so for x86_64, aarch64 for ARM.${NC}"
    VERIFIED=0
fi

# ── Inject LD_PRELOAD globally ─────────────────────────────
echo ""
echo -e "${CYAN}[*] Injecting LD_PRELOAD into system environment ...${NC}"

# /etc/environment (covers most panel environments including AcePanel)
ENV_FILE="/etc/environment"
if grep -q "LD_PRELOAD" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|.*LD_PRELOAD.*|LD_PRELOAD=$SO_TARGET|" "$ENV_FILE"
    echo -e "${GREEN}[OK] Updated LD_PRELOAD in $ENV_FILE${NC}"
else
    echo "LD_PRELOAD=$SO_TARGET" >> "$ENV_FILE"
    echo -e "${GREEN}[OK] Added LD_PRELOAD to $ENV_FILE${NC}"
fi

# /etc/profile.d/ (shell login)
PROFILE_FILE="/etc/profile.d/php-safe-core.sh"
echo "export LD_PRELOAD=$SO_TARGET" > "$PROFILE_FILE"
chmod 644 "$PROFILE_FILE"
echo -e "${GREEN}[OK] Added $PROFILE_FILE${NC}"

# ── Auto-detect and restart PHP service ───────────────────
echo ""
echo -e "${CYAN}[*] Detecting and restarting PHP service ...${NC}"

RESTARTED=0

# Search all possible PHP-FPM service names
if command -v systemctl &>/dev/null; then
    PHP_SERVICES=$(systemctl list-units --type=service --no-pager 2>/dev/null \
        | grep -oE 'php[0-9.]*[-_]fpm[^ ]*' | sed 's/\.service//' | sort -u)

    for SVC in $PHP_SERVICES; do
        if systemctl is-active "$SVC" &>/dev/null; then
            # Inject into the drop-in override
            OVERRIDE_DIR="/etc/systemd/system/${SVC}.service.d"
            mkdir -p "$OVERRIDE_DIR"
            cat > "$OVERRIDE_DIR/php-safe-core.conf" << EOF
[Service]
Environment="LD_PRELOAD=$SO_TARGET"
EOF
            systemctl daemon-reload
            systemctl restart "$SVC" && {
                echo -e "${GREEN}[OK] Restarted $SVC with LD_PRELOAD injected.${NC}"
                RESTARTED=1
            } || echo -e "${YELLOW}[WARN] Failed to restart $SVC.${NC}"
        fi
    done
fi

# Fallback: search by process name
if [ "$RESTARTED" -eq 0 ]; then
    for PROC in php-fpm php-fpm8 php-fpm7 php8.3-fpm php8.2-fpm php8.1-fpm php7.4-fpm; do
        if pgrep -x "$PROC" &>/dev/null; then
            pkill -x "$PROC" 2>/dev/null || true
            sleep 1
            if command -v "$PROC" &>/dev/null; then
                "$PROC" &
                echo -e "${GREEN}[OK] Restarted $PROC.${NC}"
                RESTARTED=1
                break
            fi
        fi
    done
fi

# Restart Apache if running
for APACHE in apache2 httpd; do
    if command -v systemctl &>/dev/null && systemctl is-active "$APACHE" &>/dev/null; then
        OVERRIDE_DIR="/etc/systemd/system/${APACHE}.service.d"
        mkdir -p "$OVERRIDE_DIR"
        cat > "$OVERRIDE_DIR/php-safe-core.conf" << EOF
[Service]
Environment="LD_PRELOAD=$SO_TARGET"
EOF
        systemctl daemon-reload
        systemctl restart "$APACHE" && {
            echo -e "${GREEN}[OK] Restarted $APACHE.${NC}"
            RESTARTED=1
        } || true
    fi
done

if [ "$RESTARTED" -eq 0 ]; then
    echo -e "${YELLOW}[INFO] No running PHP service found to restart automatically.${NC}"
    echo -e "${YELLOW}       If you use a panel (e.g. AcePanel), please restart PHP from the panel.${NC}"
fi

# ── Summary ────────────────────────────────────────────────
echo ""
echo -e "${CYAN}=================================================="
echo "   Installation Summary"
echo "=================================================="
echo -e "${NC}"
echo "  .so path  : $SO_TARGET"
echo "  PHP ver   : $PHP_VERSION"
if [ "$VERIFIED" -eq 1 ]; then
    echo -e "  .so test  : ${GREEN}PASSED${NC}"
else
    echo -e "  .so test  : ${RED}FAILED - check architecture${NC}"
fi
if [ "$RESTARTED" -eq 1 ]; then
    echo -e "  PHP svc   : ${GREEN}Restarted successfully${NC}"
else
    echo -e "  PHP svc   : ${YELLOW}Please restart manually from your panel${NC}"
fi
echo ""
echo -e "${YELLOW}To uninstall: rm $SO_TARGET $PROFILE_FILE"
echo -e "  Remove LD_PRELOAD from $ENV_FILE and restart PHP.${NC}"
echo ""
