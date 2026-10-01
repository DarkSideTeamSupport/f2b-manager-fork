#!/bin/bash
#
# Скрипт быстрой установки f2b-manager
# ─────────────────────────────────────────────────────────────
# Пути после развёртывания:
#   Приложение: /opt/f2b-manager
#   Конфигурация: /etc/f2b-manager/config.yaml (права 600)
#   Виртуальное окружение: /opt/f2b-manager/venv
#   Сервис: /etc/systemd/system/f2b-manager.service
#   Скрипт-мост: /usr/local/bin/f2b-notify.sh
#   CLI-обёртка: /usr/local/bin/f2b-manager
#
# Использование:
#   sudo bash install.sh                интерактивная установка
#   sudo bash install.sh --no-fail2ban пропустить установку fail2ban
#   sudo bash install.sh --help         показать справку
#
set -euo pipefail

# ── Константы путей ───────────────────────────────────────
INSTALL_DIR="/opt/f2b-manager"
CONFIG_DIR="/etc/f2b-manager"
VENV_DIR="${INSTALL_DIR}/venv"
BIN_DIR="/usr/local/bin"
WRAPPER="${BIN_DIR}/f2b-manager"
NOTIFY_DST="${BIN_DIR}/f2b-notify.sh"
SERVICE_SRC_REL="systemd/f2b-manager.service"
SERVICE_DST="/etc/systemd/system/f2b-manager.service"
CONFIG_SRC_REL="config/config.example.yaml"
CONFIG_DST="${CONFIG_DIR}/config.yaml"

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
SKIP_FAIL2BAN=0
for a in "$@"; do
    case "$a" in
        --no-fail2ban) SKIP_FAIL2BAN=1 ;;
        --help|-h) echo "Использование: sudo bash install.sh [--no-fail2ban]"; exit 0 ;;
        *) err "Неизвестный аргумент: $a"; exit 1 ;;
    esac
done

# ── Определение каталога скрипта (curl|bash и локальный запуск) ──
REPO_URL="https://github.com/DarkSideTeamSupport/f2b-manager-fork.git"
CLONED=0

# Попытаться определить каталог скрипта (для локального запуска)
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# Если каталог скрипта не существует или не содержит f2b_manager/, это режим curl|bash.
# Сначала необходимо клонировать репозиторий во временный каталог.
if [ -z "$SCRIPT_DIR" ] || [ ! -d "${SCRIPT_DIR}/f2b_manager" ]; then
    log "Обнаружен удалённый режим установки, загрузка кода проекта..."
    SCRIPT_DIR="/tmp/f2b-manager-install"
    rm -rf "$SCRIPT_DIR"
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 "$REPO_URL" "$SCRIPT_DIR"
        CLONED=1
    else
        # Если git отсутствует, загрузить tarball через curl
        log "git не обнаружен, загружается tarball..."
        curl -fsSL "https://github.com/DarkSideTeamSupport/f2b-manager-fork/archive/refs/heads/main.tar.gz" \
            | tar xz -C /tmp/
        mv /tmp/f2b-manager-fork-main "$SCRIPT_DIR"
    fi
    ok "Код проекта загружен в $SCRIPT_DIR"
fi

echo -e "${C_BOLD}=== Установка f2b-manager ===${C_RESET}"

# ── 0. Проверка окружения ─────────────────────────────────
if [ "$(uname -s)" != "Linux" ]; then
    err "Этот скрипт установки поддерживает только Linux"
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    err "Запустите с правами root: sudo bash install.sh"
    exit 1
fi
ok "Проверка окружения пройдена (root / Linux)"

# ── 1. Проверка Python 3.10+ ──────────────────────────────
PY_BIN=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
            PY_BIN="$cand"; break
        fi
    fi
done
if [ -z "$PY_BIN" ]; then
    err "Python 3.10+ не обнаружен. Установите Python 3.10 или новее."
    echo "  Debian/Ubuntu: apt-get install -y python3 python3-venv python3-pip"
    echo "  CentOS/RHEL:   dnf install -y python3"
    exit 1
fi
PY_VER="$("$PY_BIN" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"

# ── Определение пакетного менеджера ────────────────────────
PKG_MGR=""
if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt-get"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
fi

# ── Установка системных зависимостей ───────────────────────
install_sys_pkg() {
    local pkgs_apt="$1" pkgs_dnf="$2" pkgs_apk="$3"
    if [ -z "$PKG_MGR" ]; then
        warn "Пакетный менеджер не обнаружен. Установите вручную: $pkgs_apt"
        return 1
    fi
    log "Установка системных зависимостей: $pkgs_apt (через $PKG_MGR)..."
    case "$PKG_MGR" in
        apt-get) apt-get update -qq && apt-get install -y $pkgs_apt ;;
        dnf|yum) $PKG_MGR install -y $pkgs_dnf ;;
        apk)     apk add --no-cache $pkgs_apk ;;
    esac
}

# ── Автоматическая установка системных зависимостей ─────────
# git (нужен для удалённого режима)
if ! command -v git >/dev/null 2>&1; then
    warn "git недоступен, попытка автоматической установки..."
    if install_sys_pkg "git" "git" "git"; then
        ok "git установлен"
    else
        warn "Не удалось установить git; часть возможностей может быть недоступна"
    fi
fi

ok "Проверка версии Python пройдена: $PY_VER ($PY_BIN)"

# ── 2. Создание каталогов ─────────────────────────────────
log "Создание каталогов: $INSTALL_DIR / $CONFIG_DIR"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
ok "Каталоги созданы"

# ── 3. Копирование файлов приложения ──────────────────────
log "Копирование файлов приложения в $INSTALL_DIR"
cp -r "${SCRIPT_DIR}/f2b_manager" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/pyproject.toml" "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
ok "Файлы приложения скопированы"

# ── 4. Создание виртуального окружения и установка зависимостей ──
# При ошибке создания venv автоматически установить python3-venv и повторить попытку
create_venv() {
    "$PY_BIN" -m venv "$VENV_DIR" 2>/dev/null
}

if [ ! -d "$VENV_DIR" ] || [ ! -f "$VENV_DIR/bin/pip" ]; then
    rm -rf "$VENV_DIR"
    log "Создание виртуального окружения: $VENV_DIR"
    if create_venv; then
        ok "Виртуальное окружение создано"
    else
        # Обычно причина ошибки — отсутствие python3-venv / ensurepip
        warn "Не удалось создать виртуальное окружение, автоматическая установка python3-venv..."
        # Определить имя пакета по версии (например, python3.11-venv)
        PY_MAJOR_MINOR="$("$PY_BIN" -c 'import sys; print(f"python{sys.version_info[0]}.{sys.version_info[1]}")')"
        if install_sys_pkg "${PY_MAJOR_MINOR}-venv python3-pip" "python3-virtualenv python3-pip" "py3-virtualenv py3-pip"; then
            ok "python3-venv установлен, повторная попытка создания виртуального окружения..."
            rm -rf "$VENV_DIR"
            if create_venv; then
                ok "Виртуальное окружение создано"
            else
                err "Виртуальное окружение всё ещё не удалось создать. Выполните вручную: apt install ${PY_MAJOR_MINOR}-venv"
                exit 1
            fi
        else
            err "Не удалось установить python3-venv. Установите пакет вручную и повторите попытку."
            echo "  Debian/Ubuntu: apt-get install -y ${PY_MAJOR_MINOR}-venv python3-pip"
            echo "  CentOS/RHEL:   dnf install -y python3-virtualenv"
            exit 1
        fi
    fi
else
    log "Виртуальное окружение уже существует, используется: $VENV_DIR"
fi
log "Обновление pip..."
"$VENV_DIR/bin/pip" install --upgrade pip >/dev/null 2>&1 \
    || warn "Не удалось обновить pip (это не помешает дальнейшей установке)"
log "Установка зависимостей Python (может занять несколько минут)..."
"$VENV_DIR/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
ok "Зависимости установлены"

# ── 5. Создание CLI-обёртки ───────────────────────────────
log "Создание CLI-обёртки: $WRAPPER"
cat > "$WRAPPER" <<'EOF'
#!/bin/bash
# CLI-обёртка f2b-manager
# Установить PYTHONPATH для импорта пакета f2b_manager, затем вызвать основную программу
export PYTHONPATH="/opt/f2b-manager:${PYTHONPATH:-}"
export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8:replace}"
# Без аргументов по умолчанию открывать меню управления
if [ $# -eq 0 ]; then
    set -- menu
fi
exec /opt/f2b-manager/venv/bin/python -m f2b_manager "$@"
EOF
chmod 755 "$WRAPPER"
ok "CLI-обёртка создана"

# ── 6. Развёртывание конфигурации ──────────────────────────
if [ ! -f "$CONFIG_DST" ]; then
    log "Создание конфигурации: $CONFIG_DST (копирование шаблона)"
    cp "${SCRIPT_DIR}/${CONFIG_SRC_REL}" "$CONFIG_DST"
    chmod 600 "$CONFIG_DST"
    warn "Конфигурация создана. Укажите bot_token в $CONFIG_DST перед запуском сервиса."
else
    log "Конфигурация уже существует, создание пропущено: $CONFIG_DST"
fi

# ── 7. Установка и настройка fail2ban ──────────────────────
if [ "$SKIP_FAIL2BAN" -eq 1 ]; then
    log "Установка fail2ban пропущена (--no-fail2ban)"
else
    log "Установка и настройка fail2ban (f2b-manager fail2ban install)..."
    if "$WRAPPER" fail2ban install; then
        ok "fail2ban установлен"
    else
        warn "Не удалось установить fail2ban. Повторите позже через Telegram-команду /install или установите вручную."
    fi
fi

# ── 7a. Развёртывание action telegram-notify ────────────────
log "Развёртывание конфигурации action telegram-notify"
if [ -d /etc/fail2ban/action.d ]; then
    if [ -f "${SCRIPT_DIR}/config/telegram-notify.conf" ]; then
        cp "${SCRIPT_DIR}/config/telegram-notify.conf" /etc/fail2ban/action.d/
        chmod 644 /etc/fail2ban/action.d/telegram-notify.conf
        ok "Action telegram-notify развёрнут"

        # Если jail.local существует, но не содержит telegram-notify, добавить action
        if [ -f /etc/fail2ban/jail.local ] && ! grep -q 'telegram-notify' /etc/fail2ban/jail.local; then
            warn "Action telegram-notify не настроен в jail.local, добавление..."
            # Добавить строку action в раздел sshd
            sed -i '/^\[sshd\]/a\action = %(action_)s\n         telegram-notify[name=%(__name__)s]' /etc/fail2ban/jail.local
            if command -v fail2ban-client >/dev/null 2>&1; then
                fail2ban-client reload 2>/dev/null || warn "Не удалось перезагрузить fail2ban. Выполните вручную: fail2ban-client reload"
            fi
            ok "jail.local обновлён, fail2ban перезагружен"
        fi
    else
        err "Не найден config/telegram-notify.conf"
    fi
else
    warn "Каталог /etc/fail2ban/action.d не обнаружен, развёртывание action пропущено"
fi

# ── 8. Развёртывание сервиса systemd ───────────────────────
log "Развёртывание сервиса systemd"
if [ -f "${SCRIPT_DIR}/${SERVICE_SRC_REL}" ]; then
    cp "${SCRIPT_DIR}/${SERVICE_SRC_REL}" "$SERVICE_DST"
    chmod 644 "$SERVICE_DST"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable f2b-manager >/dev/null 2>&1 \
            || warn "Не удалось включить сервис через systemctl (не systemd-окружение?)"
        ok "Сервис systemd развёрнут и включён для автозапуска"
    else
        warn "systemctl не обнаружен, регистрация сервиса пропущена (управляйте процессом вручную)"
    fi
else
    err "Не найден файл сервиса systemd: ${SCRIPT_DIR}/${SERVICE_SRC_REL}"
fi

# ── 9. Развёртывание скрипта-моста notify ──────────────────
log "Развёртывание скрипта-моста notify: $NOTIFY_DST"
if [ -f "${SCRIPT_DIR}/scripts/f2b-notify.sh" ]; then
    cp "${SCRIPT_DIR}/scripts/f2b-notify.sh" "$NOTIFY_DST"
    chmod 755 "$NOTIFY_DST"
    ok "Скрипт notify развёрнут"
else
    err "Не найден scripts/f2b-notify.sh"
fi

# ── Создание команды f2b ───────────────────────────────────
log "Создание команды f2b"
ln -sf "$WRAPPER" /usr/local/bin/f2b
ok "Команда создана: введите f2b, чтобы открыть меню управления"

# ── Завершение ─────────────────────────────────────────────
echo
echo -e "${C_GREEN}${C_BOLD}✅ f2b-manager установлен!${C_RESET}"
echo

# ── Запуск мастера настройки (только при интерактивном TTY) ─
if [ -t 0 ] && [ -t 1 ]; then
    log "Запуск мастера настройки..."
    "$WRAPPER" menu || warn "Не удалось запустить меню; выполните команду f2b позже"
else
    warn "Нет интерактивного терминала — меню пропущено"
    echo -e "  Откройте меню на сервере: ${C_YELLOW}f2b${C_RESET}"
fi

echo
echo -e "${C_GREEN}Настройка завершена!${C_RESET}"
echo -e "Запустить сервис: ${C_YELLOW}systemctl start f2b-manager${C_RESET}"
echo -e "Просмотреть журнал: ${C_YELLOW}journalctl -u f2b-manager -f${C_RESET}"
echo -e "Снова открыть меню: ${C_YELLOW}f2b${C_RESET}"
echo
echo "Чтобы использовать определение местоположения IP, запустите f2b и выберите соответствующий пункт"
echo "Для удаления выполните: bash /opt/f2b-manager/uninstall.sh"

# ── Очистка временного каталога загрузки ───────────────────
if [ "$CLONED" -eq 1 ] && [ -d "$SCRIPT_DIR" ]; then
    rm -rf "$SCRIPT_DIR"
fi
