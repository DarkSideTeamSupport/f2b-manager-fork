#!/bin/bash
#
# Скрипт удаления f2b-manager
# ─────────────────────────────────────────────────────────────
# Порядок действий:
#   1. Остановить и отключить сервис f2b-manager в systemd
#   2. Удалить файл сервиса systemd
#   3. Удалить каталог приложения /opt/f2b-manager (после подтверждения)
#   4. Удалить CLI-обёртку /usr/local/bin/f2b-manager и скрипт-мост
#   5. Запросить удаление каталога конфигурации /etc/f2b-manager (по умолчанию сохраняется)
#   6. Запросить удаление базы состояния и журналов (по умолчанию сохраняются)
#
# Примечание:
#   - Скрипт удаляет только f2b-manager, но не fail2ban.
#     Для удаления fail2ban выполните /uninstall в Telegram
#     или вручную: f2b-manager fail2ban uninstall
#
# Использование:
#   sudo bash uninstall.sh        интерактивное удаление
#   sudo bash uninstall.sh -y     автоматическое подтверждение со значениями по умолчанию
#   sudo bash uninstall.sh --help показать справку
#
set -uo pipefail

# ── Константы путей ───────────────────────────────────────
INSTALL_DIR="/opt/f2b-manager"
CONFIG_DIR="/etc/f2b-manager"
BIN_DIR="/usr/local/bin"
WRAPPER="${BIN_DIR}/f2b-manager"
NOTIFY_DST="${BIN_DIR}/f2b-notify.sh"
SERVICE_DST="/etc/systemd/system/f2b-manager.service"
STATE_DIR="/var/lib/f2b-manager"
LOG_FILE="/var/log/f2b-manager.log"

# ── Цветной вывод ─────────────────────────────────────────
if [ -t 1 ]; then
    C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
    C_CYAN='\033[0;36m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_BOLD=''; C_RESET=''
fi

log()  { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
err()  { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }
ok()   { echo -e "${C_GREEN}[ OK ]${C_RESET} $*"; }

# ── Разбор аргументов ─────────────────────────────────────
FORCE=0
for a in "$@"; do
    case "$a" in
        -y|--yes) FORCE=1 ;;
        --help|-h) echo "Использование: sudo bash uninstall.sh [-y]"; exit 0 ;;
        *) err "Неизвестный аргумент: $a"; exit 1 ;;
    esac
done

echo -e "${C_BOLD}=== Удаление f2b-manager ===${C_RESET}"

if [ "$(id -u)" -ne 0 ]; then
    err "Запустите с правами root: sudo bash uninstall.sh"
    exit 1
fi

# Функция интерактивного подтверждения: по умолчанию No (кроме -y)
confirm() {
    if [ "$FORCE" -eq 1 ]; then return 0; fi
    local ans
    read -r -p "$1 [y/N] " ans
    case "$ans" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

# ── 1. Остановка и отключение сервиса ─────────────────────
log "Остановка сервиса f2b-manager..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop f2b-manager 2>/dev/null && ok "Сервис остановлен" \
        || warn "Сервис не запущен или не может быть остановлен (возможно, не установлен)"
    systemctl disable f2b-manager 2>/dev/null && ok "Сервис отключён" \
        || warn "Сервис не включён, disable пропущен"
else
    # Не systemd: попытаться остановить процесс через pidof / pkill
    pkill -f "python -m f2b_manager" 2>/dev/null && ok "Предпринята попытка остановки работающего процесса" \
        || warn "Работающих процессов не обнаружено"
fi

# ── 2. Удаление файла сервиса systemd ──────────────────────
if [ -f "$SERVICE_DST" ]; then
    rm -f "$SERVICE_DST"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
    fi
    ok "Файл сервиса systemd удалён: $SERVICE_DST"
else
    log "Файл сервиса не существует (пропущено): $SERVICE_DST"
fi

# ── 3. Удаление каталога приложения ───────────────────────
if [ -d "$INSTALL_DIR" ]; then
    if confirm "Удалить каталог приложения $INSTALL_DIR?"; then
        rm -rf "$INSTALL_DIR"
        ok "Удалено: $INSTALL_DIR"
    else
        warn "Сохранено: $INSTALL_DIR"
    fi
else
    log "Каталог приложения не существует (пропущено): $INSTALL_DIR"
fi

# ── 4. Удаление CLI-обёртки и скрипта-моста ───────────────
[ -f "$WRAPPER" ] && rm -f "$WRAPPER" && ok "Удалено: $WRAPPER"
[ -f "$NOTIFY_DST" ] && rm -f "$NOTIFY_DST" && ok "Удалено: $NOTIFY_DST"
# Совместимость со старыми версиями: удалить возможную символическую ссылку Python
[ -L "${BIN_DIR}/f2b-manager-python" ] && rm -f "${BIN_DIR}/f2b-manager-python"

# ── 5. Конфигурация ───────────────────────────────────────
if [ -d "$CONFIG_DIR" ]; then
    if confirm "Удалить каталог конфигурации $CONFIG_DIR (включая config.yaml)? Выберите N, чтобы сохранить конфигурацию для переустановки"; then
        # Создать резервную копию перед удалением
        BACKUP="${CONFIG_DIR}.backup.$(date +%Y%m%d%H%M%S)"
        cp -r "$CONFIG_DIR" "$BACKUP" 2>/dev/null || true
        rm -rf "$CONFIG_DIR"
        ok "Каталог конфигурации удалён (резервная копия: $BACKUP)"
    else
        warn "Каталог конфигурации сохранён: $CONFIG_DIR"
    fi
fi

# ── 6. База состояния и журналы (необязательно) ───────────
if [ -d "$STATE_DIR" ] || [ -f "$LOG_FILE" ]; then
    if confirm "Удалить также базу состояния ($STATE_DIR) и журнал ($LOG_FILE)? Выберите N, чтобы сохранить историю"; then
        [ -d "$STATE_DIR" ] && rm -rf "$STATE_DIR"
        [ -f "$LOG_FILE" ] && rm -f "$LOG_FILE"
        ok "База состояния и журнал удалены"
    else
        warn "База состояния и журнал сохранены"
    fi
fi

echo
echo -e "${C_GREEN}${C_BOLD}✅ Удаление завершено.${C_RESET}"
echo
echo "Примечание: сервис fail2ban продолжает управляться системой и не затронут."
echo "            Для удаления fail2ban выполните: f2b-manager fail2ban uninstall"
