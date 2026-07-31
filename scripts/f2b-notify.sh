#!/bin/bash
# ───────────────────────────────────────────────────────────
# f2b-notify.sh — скрипт-мост уведомлений Fail2ban → f2b-manager
# ───────────────────────────────────────────────────────────
# Вызывается action fail2ban и передаёт события блокировки, разблокировки,
# запуска и остановки подкоманде notify CLI f2b-manager. CLI формирует
# сообщение и отправляет уведомление через Telegram Bot.
#
# Путь после развёртывания: /usr/local/bin/f2b-notify.sh
# Права:                   755 (root:root)
#
# Принципы:
#   - всегда завершаться с exit 0, не мешая работе fail2ban;
#   - выполнять действие асинхронно, не блокируя цепочку action fail2ban;
#   - перенаправлять вывод в /dev/null, не засоряя журнал fail2ban.
#
# Аргументы:
#   $1 — тип события: ban / unban / start / stop
#   $2 — значение (зависит от типа события):
#         ban:   IP-адрес
#         unban: IP-адрес
#         start: имя jail
#         stop:  имя jail
#   $3 — имя jail (для ban/unban)
#   $4 — количество неудачных попыток (только для ban)
#   $5 — совпавшая строка журнала (только для ban; может отсутствовать)
# ───────────────────────────────────────────────────────────

set -e

# ── Аргументы ───────────────────────────────
EVENT="${1:-}"
IP="${2:-}"
JAIL="${3:-}"
FAILURES="${4:-0}"
MATCHES="${5:-}"

# ── Проверка аргументов ──────────────────────
if [ -z "$EVENT" ]; then
    # Вызов без аргументов: тихий выход
    exit 0
fi

# ── Путь к CLI (поиск в порядке приоритета) ──
F2B_MANAGER=""
if command -v f2b-manager >/dev/null 2>&1; then
    F2B_MANAGER="f2b-manager"
elif [ -x /usr/local/bin/f2b-manager ]; then
    F2B_MANAGER="/usr/local/bin/f2b-manager"
elif [ -x /opt/f2b-manager/venv/bin/python ]; then
    # Резервный вариант для среды разработки/развёртывания
    F2B_MANAGER="/opt/f2b-manager/venv/bin/python -m f2b_manager"
else
    # f2b-manager не установлен: записать в syslog и тихо завершиться
    logger -t f2b-notify "CLI f2b-manager не найден, уведомление пропущено"
    exit 0
fi

# ── Передача события (синхронный вызов) ──────
# Синхронное выполнение с ограничением в 30 секунд
# Вывод перенаправляется в /dev/null, чтобы не засорять журнал fail2ban
timeout 30 $F2B_MANAGER notify \
    --event "$EVENT" \
    --ip "$IP" \
    --jail "$JAIL" \
    --failures "$FAILURES" \
    --matches "$MATCHES" \
    >/dev/null 2>&1 || true

# Всегда возвращать 0
exit 0
