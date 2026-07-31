"""
f2b_manager.telegram_bot.handlers.status
=========================================

Обработчик команд просмотра состояния.

Команды:
    /status       — обзор состояния Fail2ban
    /jails        — список всех jail
    /banned       — список заблокированных IP
    /jail <name>  — детали указанного jail

Права: оператор (OPERATOR) и выше
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from ..auth import require_operator
from ..deps import get_deps
from ..formatters import format_banned_ips, format_error, format_jail_detail, \
    format_jails, format_not_ready, format_status

logger = logging.getLogger(__name__)


@require_operator
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/status — сводка состояния Fail2ban."""
    deps = get_deps(context)

    if deps.f2b_manager is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    try:
        status = deps.f2b_manager.get_status()
        await update.message.reply_text(
            format_status(status), parse_mode="HTML"
        )
    except Exception as e:
        logger.exception("Не удалось получить состояние")
        await update.message.reply_text(
            format_error(f"Не удалось получить состояние: {e}"), parse_mode="HTML"
        )


@require_operator
async def cmd_jails(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/jails — выводит все jail."""
    deps = get_deps(context)

    if deps.f2b_manager is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    try:
        jails = deps.f2b_manager.get_jails()
        await update.message.reply_text(
            format_jails(jails), parse_mode="HTML"
        )
    except Exception as e:
        logger.exception("Не удалось получить список jail")
        await update.message.reply_text(
            format_error(f"Не удалось получить список jail: {e}"), parse_mode="HTML"
        )


@require_operator
async def cmd_banned(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/banned — выводит все заблокированные IP с указанием страны."""
    deps = get_deps(context)

    if deps.f2b_manager is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    try:
        ips = deps.f2b_manager.get_banned_ips()

        # Определяем страны IP-адресов.
        countries: dict[str, str] = {}
        if ips and deps.config.notify.geoip_enabled:
            try:
                from ...notify.geoip import GeoIPLookup
                geo = GeoIPLookup(
                    db_path=deps.config.notify.geoip_db_path,
                    method=deps.config.notify.geoip_method,
                )
                for ip in ips:
                    info = await geo.lookup(ip)
                    if info.country:
                        flag = f" {info.flag}" if info.flag else ""
                        countries[ip] = f"{info.country}{flag}"
                geo.close()
            except Exception:
                pass  # Ошибка поиска не должна мешать выводу списка.

        await update.message.reply_text(
            format_banned_ips(ips, countries), parse_mode="HTML"
        )
    except Exception as e:
        logger.exception("Не удалось получить список заблокированных IP")
        await update.message.reply_text(
            format_error(f"Не удалось получить список блокировок: {e}"), parse_mode="HTML"
        )


@require_operator
async def cmd_jail(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/jail <name> — показывает сведения о выбранном jail."""
    deps = get_deps(context)

    if deps.f2b_manager is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    # Проверка параметров.
    args = context.args
    if not args:
        await update.message.reply_text(
            format_error("Использование: /jail <jail_name>\nНапример: /jail sshd"),
            parse_mode="HTML",
        )
        return

    jail_name = args[0].strip()

    try:
        jail_status = deps.f2b_manager.get_jail_status(jail_name)
        await update.message.reply_text(
            format_jail_detail(jail_status), parse_mode="HTML"
        )
    except Exception as e:
        logger.exception(f"Не удалось получить сведения о jail '{jail_name}'")
        await update.message.reply_text(
            format_error(f"Не удалось получить сведения о jail '{jail_name}': {e}"),
            parse_mode="HTML",
        )
