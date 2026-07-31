#!/bin/bash
#
# geoip-update.sh — обновление базы MaxMind GeoLite2 Country
# ─────────────────────────────────────────────────────────────
# Путь после развёртывания: /usr/local/bin/geoip-update.sh
# Путь к базе: /var/lib/GeoIP/GeoLite2-Country.mmdb
#
# Возможности:
#   - загрузка базы GeoLite2-Country с сайта MaxMind (требуется License Key);
#   - загрузка с публичного зеркала P3TERX (License Key не нужен, --mirror);
#   - автоматическое резервное копирование старой базы перед загрузкой;
#   - регистрация еженедельного автоматического обновления через --cron.
#
# MaxMind License Key:
#   База GeoLite2 бесплатна, но нужно зарегистрировать учётную запись MaxMind
#   и создать License Key:
#     1. Зарегистрируйте бесплатную учётную запись на https://www.maxmind.com/
#     2. Откройте Account → Services → My License Key.
#     3. Нажмите «Generate new license key» и скопируйте Key.
#     4. Передайте его через переменную окружения или файл ключа:
#          export GEOIP_LICENSE_KEY="ВАШ_КЛЮЧ"
#        либо: echo "ВАШ_КЛЮЧ" > /etc/f2b-manager/geoip.key
#
# Использование:
#   sudo bash geoip-update.sh                обновить по License Key из переменной/файла
#   sudo bash geoip-update.sh --mirror       использовать зеркало P3TERX
#   sudo bash geoip-update.sh --setup        показать настройку и регистрацию еженедельного cron
#   sudo bash geoip-update.sh --cron         зарегистрировать еженедельное обновление в crontab
#   sudo bash geoip-update.sh --help         показать справку
#
set -uo pipefail

GEOIP_DIR="/var/lib/GeoIP"
DB_NAME="GeoLite2-Country.mmdb"
DB_PATH="${GEOIP_DIR}/${DB_NAME}"
TMP_DIR="$(mktemp -d)"
ARCHIVE="${TMP_DIR}/geo.tar.gz"
LICENSE_KEY="${GEOIP_LICENSE_KEY:-}"
KEY_FILE="${GEOIP_KEY_FILE:-/etc/f2b-manager/geoip.key}"

MODE="official"   # official | mirror
SETUP_ONLY=0
INSTALL_CRON=0

# ── Цвета ──────────────────────────────────────────────────
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

cleanup() { rm -rf "$TMP_DIR" 2>/dev/null || true; }
trap cleanup EXIT

# ── Разбор аргументов ──────────────────────────────────────
for a in "$@"; do
    case "$a" in
        --mirror) MODE="mirror" ;;
        --setup) SETUP_ONLY=1 ;;
        --cron) INSTALL_CRON=1 ;;
        --help|-h) echo "Использование: sudo bash geoip-update.sh [--mirror|--setup|--cron]"; exit 0 ;;
        *) err "Неизвестный аргумент: $a"; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    err "Запустите с правами root: sudo bash geoip-update.sh"
    exit 1
fi

# ── Только вывод инструкции по настройке ───────────────────
if [ "$SETUP_ONLY" -eq 1 ]; then
    echo -e "${C_BOLD}Настройка базы GeoIP${C_RESET}"
    echo
    echo "1) Получите MaxMind License Key:"
    echo "   Зарегистрируйтесь на https://www.maxmind.com/ → Account → My License Key → Generate"
    echo
    echo "2) Передайте Key одним из способов:"
    echo "   a) переменная окружения: export GEOIP_LICENSE_KEY=\"ВАШ_КЛЮЧ\""
    echo "   b) файл ключа: echo \"ВАШ_КЛЮЧ\" > /etc/f2b-manager/geoip.key"
    echo
    echo "3) Запустите обновление: sudo bash geoip-update.sh"
    echo "   или используйте зеркало: sudo bash geoip-update.sh --mirror (Key не нужен)"
    echo
    echo "4) Зарегистрируйте еженедельное обновление: sudo bash geoip-update.sh --cron"
    echo
    echo "В config.yaml должны быть указаны:"
    echo "  notify.geoip.enabled: true"
    echo "  notify.geoip.method: local"
    echo "  notify.geoip.db_path: /var/lib/GeoIP/GeoLite2-Country.mmdb"
    exit 0
fi

# ── Регистрация cron ───────────────────────────────────────
if [ "$INSTALL_CRON" -eq 1 ]; then
    CRON_LINE="0 3 * * 0 /usr/local/bin/geoip-update.sh >> /var/log/geoip-update.log 2>&1"
    # Убедиться, что скрипт развёрнут
    if [ ! -f /usr/local/bin/geoip-update.sh ]; then
        SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
        cp "$SRC" /usr/local/bin/geoip-update.sh 2>/dev/null || cp "${BASH_SOURCE[0]}" /usr/local/bin/geoip-update.sh
        chmod 755 /usr/local/bin/geoip-update.sh
        ok "Развёрнуто: /usr/local/bin/geoip-update.sh"
    fi
    if command -v crontab >/dev/null 2>&1; then
        ( crontab -l 2>/dev/null | grep -v "geoip-update.sh"; echo "$CRON_LINE" ) | crontab -
        ok "Еженедельное обновление зарегистрировано на воскресенье, 03:00 (crontab)"
        echo "   Журнал: /var/log/geoip-update.log"
    else
        err "Команда crontab не обнаружена. Добавьте вручную: $CRON_LINE"
        exit 1
    fi
    exit 0
fi

# ── Подготовка каталога ─────────────────────────────────────
mkdir -p "$GEOIP_DIR"

# ── Резервное копирование старой базы ───────────────────────
if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "${DB_PATH}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    log "Старая база сохранена в резервной копии"
fi

# ── Загрузка ───────────────────────────────────────────────
download_official() {
    # Прочитать Key: сначала переменная окружения, затем файл ключа
    if [ -z "$LICENSE_KEY" ] && [ -f "$KEY_FILE" ]; then
        LICENSE_KEY="$(head -n1 "$KEY_FILE" | tr -d '[:space:]')"
    fi
    if [ -z "$LICENSE_KEY" ]; then
        err "MaxMind License Key не указан."
        echo "  Сначала выполните: sudo bash geoip-update.sh --setup"
        echo "  Или временно укажите: sudo GEOIP_LICENSE_KEY=ВАШ_КЛЮЧ bash geoip-update.sh"
        return 1
    fi
    local url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz"
    log "Загрузка GeoLite2-Country с сайта MaxMind..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$ARCHIVE" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$ARCHIVE" "$url" || return 1
    else
        err "Не найдены curl или wget"; return 1
    fi
    return 0
}

download_mirror() {
    # Публичное зеркало P3TERX (Key не нужен, обновления могут задерживаться)
    local url="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    log "Загрузка GeoLite2-Country.mmdb с зеркала P3TERX..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$DB_PATH" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$DB_PATH" "$url" || return 1
    else
        err "Не найдены curl или wget"; return 1
    fi
    # Зеркало выдаёт mmdb напрямую, распаковка не требуется
    if [ -s "$DB_PATH" ]; then
        chmod 644 "$DB_PATH"
        ok "База GeoIP обновлена: $DB_PATH"
        return 0
    fi
    return 1
}

if [ "$MODE" = "mirror" ]; then
    if download_mirror; then
        echo -e "${C_GREEN}${C_BOLD}✅ База GeoIP обновлена (зеркало)${C_RESET}"
        exit 0
    else
        err "Не удалось загрузить данные с зеркала"
        exit 1
    fi
fi

# Официальный режим: загрузить и распаковать tar.gz
if ! download_official; then
    err "Не удалось загрузить данные с официального сайта. Используйте зеркало: sudo bash geoip-update.sh --mirror"
    exit 1
fi

log "Распаковка базы..."
tar -xzf "$ARCHIVE" -C "$TMP_DIR" 2>/dev/null || { err "Не удалось распаковать архив: файл может быть повреждён"; exit 1; }
EXTRACTED="$(find "$TMP_DIR" -name "$DB_NAME" | head -n1)"
if [ -z "$EXTRACTED" ] || [ ! -s "$EXTRACTED" ]; then
    err "Распакованный файл базы не найден"
    exit 1
fi

mv "$EXTRACTED" "$DB_PATH"
chmod 644 "$DB_PATH"
ok "База GeoIP обновлена: $DB_PATH"

# Очистка лишних резервных копий (оставить только 3 последние)
ls -1t "${DB_PATH}".bak.* 2>/dev/null | tail -n +4 | xargs -r rm -f 2>/dev/null || true

echo -e "${C_GREEN}${C_BOLD}✅ База GeoIP обновлена${C_RESET}"
echo "   Путь: $DB_PATH"
echo "   Рекомендуется зарегистрировать еженедельное обновление: sudo bash geoip-update.sh --cron"
