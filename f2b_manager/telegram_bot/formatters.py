"""
f2b_manager.telegram_bot.formatters
====================================

Инструменты форматирования сообщений (HTML).

Весь текст для Telegram экранируется в HTML, чтобы предотвратить инъекции.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage.models import (
        BanEvent, DailyStat, Fail2banStatus, InstallResult,
        JailInfo, JailStatus,
    )


# ──────────────────────────────────────────────
# Базовые инструменты
# ──────────────────────────────────────────────

def esc(text) -> str:
    """HTML-экранирование с безопасной обработкой None."""
    if text is None:
        return ""
    return html.escape(str(text), quote=False)


def _state_emoji(state: str) -> str:
    """Emoji состояния службы."""
    if state == "running":
        return "\U0001f7e2"  # 🟢
    if state == "stopped":
        return "\U0001f534"  # 🔴
    return "\u26a0\ufe0f"  # ⚠️


# ──────────────────────────────────────────────
# Форматирование состояния
# ──────────────────────────────────────────────

def format_status(status: "Fail2banStatus") -> str:
    """Форматирует общее состояние Fail2ban."""
    state = status.state.value if hasattr(status.state, "value") else str(status.state)
    emoji = _state_emoji(state)

    lines = [
        f"\U0001f4cb <b>Обзор состояния Fail2ban</b>",
        "",
        f"{emoji} <b>Состояние службы:</b> {esc(state)}",
        f"\u23f1 <b>Время работы:</b> {esc(status.uptime) or 'Неизвестно'}",
        f"\U0001f4e6 <b>Версия:</b> <code>{esc(status.version) or 'Неизвестно'}</code>",
        f"\U0001f510 <b>Количество jail:</b> <code>{status.jail_count}</code>",
        f"\U0001f6ab <b>Всего блокировок:</b> <code>{status.total_bans}</code>",
    ]
    return "\n".join(lines)


def format_jails(jails: list["JailInfo"]) -> str:
    """Форматирует список jail."""
    if not jails:
        return "\U0001f511 <b>Список jail</b>\n\nНет активных jail."

    lines = ["\U0001f511 <b>Список jail</b>", ""]

    for jail in jails:
        status_icon = "\u2705" if jail.enabled else "\u274c"
        lines.append(
            f"{status_icon} <code>{esc(jail.name)}</code>"
            f"  |  Активных блокировок: <b>{jail.current_ban}</b>"
            f"  |  Всего сбоев: <b>{jail.total_failed}</b>"
        )

    return "\n".join(lines)


def format_jail_detail(jail: "JailStatus") -> str:
    """Форматирует сведения об одном jail."""
    lines = [
        f"\U0001f50d <b>Сведения о Jail: {esc(jail.name)}</b>",
        "",
        f"\u2705 <b>Включён:</b> {'Да' if jail.enabled else 'Нет'}",
        f"\U0001f6ab <b>Заблокировано IP:</b> <code>{jail.current_ban}</code>",
        f"\U0001f4ca <b>Всего сбоев:</b> <code>{jail.total_failed}</code>",
        f"\U0001f4c8 <b>Всего блокировок:</b> <code>{jail.total_banned}</code>",
        f"\u23f1 <b>Окно обнаружения:</b> <code>{esc(jail.findtime)}</code>",
        f"\u23f1 <b>Срок блокировки:</b> <code>{esc(jail.bantime)}</code>",
        f"\U0001f501 <b>Максимум попыток:</b> <code>{jail.maxretry}</code>",
    ]

    if jail.banned_ips:
        lines.append("")
        lines.append("\U0001f4cd <b>Заблокированные IP:</b>")
        for ip in jail.banned_ips:
            lines.append(f"  • <code>{esc(ip)}</code>")
    else:
        lines.append("")
        lines.append("\U0001f4cd Заблокированных IP нет")

    return "\n".join(lines)


def format_banned_ips(ips: list[str], countries: dict[str, str] | None = None) -> str:
    """Форматирует список заблокированных IP.

    Args:
        ips: список IP
        countries: словарь IP→страна, например {"1.2.3.4": "США 🇺🇸"}
    """
    if not ips:
        return "\U0001f6ab <b>Список заблокированных IP</b>\n\nСейчас нет заблокированных IP.\nСервер в безопасности 😊"

    lines = [
        f"\U0001f6ab <b>Список заблокированных IP</b>",
        f"Заблокировано IP: <b>{len(ips)}</b>",
        "",
    ]

    for i, ip in enumerate(ips, 1):
        country = (countries or {}).get(ip, "")
        if country:
            lines.append(f"  {i}. <code>{esc(ip)}</code>  {country}")
        else:
            lines.append(f"  {i}. <code>{esc(ip)}</code>")

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Форматирование результатов операций
# ──────────────────────────────────────────────

def format_install_result(
    result: "InstallResult", action: str = "установка"
) -> str:
    """Форматирует результат установки/удаления/обновления."""
    icon = "\u2705" if result.success else "\u274c"
    lines = [
        f"{icon} <b>Fail2ban: {action} {'завершена' if result.success else 'не удалась'}</b>",
        "",
        f"\U0001f4e4 <b>Сообщение:</b> {esc(result.message)}",
    ]

    if result.version:
        lines.append(f"\U0001f4e6 <b>Версия:</b> <code>{esc(result.version)}</code>")
    if result.old_version:
        lines.append(
            f"\U0001f4e4 <b>Предыдущая версия:</b> <code>{esc(result.old_version)}</code>"
        )
    if result.elapsed_seconds > 0:
        lines.append(
            f"\u23f1 <b>Затрачено:</b> <code>{result.elapsed_seconds:.1f} с</code>"
        )

    if result.details:
        lines.append("")
        lines.append("\U0001f4dd <b>Сведения:</b>")
        for detail in result.details:
            lines.append(f"  • {esc(detail)}")

    return "\n".join(lines)


def format_ban_result(ip: str, jail: str, success: bool, action: str = "блокировка") -> str:
    """Форматирует результат блокировки/разблокировки."""
    icon = "\u2705" if success else "\u274c"
    return (
        f"{icon} <b>{action}: {'успешно' if success else 'ошибка'}</b>\n\n"
        f"\U0001f4cd IP: <code>{esc(ip)}</code>\n"
        f"\U0001f3f7 Jail: <code>{esc(jail)}</code>"
    )


# ──────────────────────────────────────────────
# Форматирование статистики и отчётов
# ──────────────────────────────────────────────

def format_ban_event(event: "BanEvent") -> str:
    """Форматирует событие блокировки."""
    action_icon = "\U0001f6a8" if event.action.value == "ban" else "\u2705"
    country_str = f"{esc(event.country)}" if event.country else "Неизвестно"

    lines = [
        f"{action_icon} <b>Событие блокировки</b>",
        "",
        f"\U0001f4cd IP: <code>{esc(event.ip)}</code>",
        f"\U0001f3f7 Jail: <code>{esc(event.jail)}</code>",
        f"\U0001f50d Действие: <b>{esc(event.action.value)}</b>",
        f"\U0001f30d Страна: {country_str}",
        f"\U0001f522 Число ошибок: <b>{event.failures}</b>",
        f"\U0001f552 Время: {esc(event.timestamp.strftime('%Y-%m-%d %H:%M:%S'))}",
    ]

    if event.matches:
        preview = event.matches[:200]
        lines.append(f"\U0001f4dd Совпадения в журнале:\n<pre>{esc(preview)}</pre>")

    return "\n".join(lines)


def format_daily_stats(stats: list["DailyStat"]) -> str:
    """Форматирует ежедневную статистику."""
    if not stats:
        return "\U0001f4ca <b>Ежедневная статистика</b>\n\nДанных пока нет."

    lines = ["\U0001f4ca <b>Ежедневная статистика блокировок</b>", ""]

    for stat in stats:
        country = esc(stat.top_country) if stat.top_country else "-"
        lines.append(
            f"<b>{esc(stat.date)}</b>"
            f"  |  блокировок: <code>{stat.total_bans}</code>"
            f"  |  уникальных IP: <code>{stat.unique_ips}</code>"
            f"  |  Top: {country}"
        )

    return "\n".join(lines)


def format_stats_summary(
    total_bans: int,
    unique_ips: int,
    top_ips: list[tuple[str, int]],
    top_countries: list[tuple[str, int]],
    days: int = 7,
) -> str:
    """Форматирует сводку статистики."""
    lines = [
        f"\U0001f4ca <b>Статистика блокировок за {days} дн.</b>",
        "",
        f"\U0001f6ab <b>Всего блокировок:</b> <code>{total_bans}</code>",
        f"\U0001f310 <b>Уникальных IP:</b> <code>{unique_ips}</code>",
    ]

    if top_ips:
        lines.append("")
        lines.append("\U0001f525 <b>Top атакующих IP:</b>")
        for i, (ip, count) in enumerate(top_ips, 1):
            lines.append(f"  {i}. <code>{esc(ip)}</code> — <b>{count}</b> раз")

    if top_countries:
        lines.append("")
        lines.append("\U0001f30d <b>Top стран-источников:</b>")
        for i, (country, count) in enumerate(top_countries, 1):
            lines.append(f"  {i}. {esc(country)} — <b>{count}</b> раз")

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Системные сообщения
# ──────────────────────────────────────────────

def format_welcome(chat_id: int, level_name: str = "Гость") -> str:
    """Приветствие и chat_id."""
    return (
        "\U0001f44b <b>Добро пожаловать в f2b-manager Bot</b>\n\n"
        "Система управления Fail2ban на VPS через Telegram.\n\n"
        f"\U0001f194 <b>Ваш Chat ID:</b> <code>{chat_id}</code>\n"
        f"\U0001f511 <b>Уровень прав:</b> {esc(level_name)}\n\n"
        "Добавьте этот Chat ID в "
        "<code>admin_chat_ids</code> или <code>operator_chat_ids</code> в конфигурации.\n\n"
        "Введите /help, чтобы увидеть все доступные команды."
    )


def format_help(level_name: str = "Гость") -> str:
    """Справка по командам."""
    lines = [
        "\U0001f4da <b>Справка по командам</b>",
        f"\U0001f511 Ваши права: <b>{esc(level_name)}</b>",
        "",
        "<b>📋 Базовые команды</b>",
        "/start — приветствие и Chat ID",
        "/help — эта справка",
        "/cancel — отменить текущую операцию",
        "",
        "<b>🔍 Запросы состояния (оператор+)</b>",
        "/status — обзор состояния Fail2ban",
        "/jails — список всех jail",
        "/banned — текущие заблокированные IP",
        "/jail &lt;name&gt; — детали jail (например /jail sshd)",
        "/report — сформировать отчёт сейчас",
        "/stats [дней] — статистика за N дней (по умолчанию 7)",
        "/setnotify on|off — вкл./выкл. оповещения в реальном времени",
        "",
        "<b>🔧 Управление (администратор)</b>",
        "/ban &lt;ip&gt; — заблокировать IP вручную (например /ban 1.2.3.4)",
        "/unban &lt;ip&gt; — разблокировать IP",
        "/install — установить Fail2ban",
        "/uninstall — удалить Fail2ban (с подтверждением)",
        "/update — обновить Fail2ban",
        "/reload — перезагрузить конфигурацию Fail2ban",
        "/whitelist — просмотр и управление белым списком",
        "/setschedule — расписание отчётов",
    ]
    return "\n".join(lines)


def format_error(message: str) -> str:
    """Сообщение об ошибке."""
    return f"\u274c <b>Ошибка</b>\n\n{esc(message)}"


def format_success(message: str) -> str:
    """Сообщение об успехе."""
    return f"\u2705 <b>Успех</b>\n\n{esc(message)}"


def format_progress(message: str) -> str:
    """Сообщение о прогрессе."""
    return f"\u23f3 {esc(message)}"


def format_cancelled() -> str:
    """Операция отменена."""
    return "\u274c Операция отменена."


def format_not_ready() -> str:
    """Функция ещё не готова."""
    return (
        "\u26a0\ufe0f <b>Функция ещё не готова</b>\n\n"
        "Модуль управления Fail2ban не загружен.\n"
        "Установите и запустите f2b-manager на сервере, затем повторите попытку."
    )
