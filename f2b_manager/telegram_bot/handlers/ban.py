"""
f2b_manager.telegram_bot.handlers.ban
======================================

Обработчик команд управления блокировками.

Команды:
    /ban <ip> [jail]    — ручная блокировка IP (jail по умолчанию: sshd)
    /unban <ip>         — разблокировка IP

Права: администратор (ADMIN)
"""

from __future__ import annotations

import ipaddress
import logging

from telegram import Update
from telegram.ext import ContextTypes

from ..auth import require_admin
from ..deps import get_deps
from ..formatters import esc, format_ban_result, format_error, format_not_ready

logger = logging.getLogger(__name__)


def validate_ip(ip_str: str) -> bool:
    """Проверяет формат IP-адреса (IPv4 / IPv6)."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _usage_ban() -> str:
    return (
        "Использование:\n"
        "  <code>/ban &lt;ip&gt; [jail]</code>\n\n"
        "Примеры:\n"
        "  /ban 1.2.3.4\n"
        "  /ban 1.2.3.4 sshd"
    )


def _usage_unban() -> str:
    return (
        "Использование:\n"
        "  <code>/unban &lt;ip&gt;</code>\n\n"
        "Примеры:\n"
        "  /unban 1.2.3.4"
    )


@require_admin
async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/ban <ip> [jail] — вручную блокирует IP."""
    deps = get_deps(context)

    if deps.f2b_manager is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    args = context.args
    if not args:
        await update.message.reply_text(
            f"\u274c <b>Не указаны параметры</b>\n\n{_usage_ban()}", parse_mode="HTML"
        )
        return

    ip = args[0].strip()

    # Проверка формата IP.
    if not validate_ip(ip):
        await update.message.reply_text(
            format_error(f"Недопустимый IP-адрес: {ip}\n\n{_usage_ban()}"),
            parse_mode="HTML",
        )
        return

    # Необязательный параметр jail.
    jail = "sshd"
    if len(args) > 1:
        jail = args[1].strip()

    try:
        # Сначала проверяем, не заблокирован ли IP.
        already_banned = False
        try:
            for j in deps.f2b_manager.get_jails():
                js = deps.f2b_manager.get_jail_status(j.name)
                if ip in js.banned_ips:
                    already_banned = True
                    await update.message.reply_text(
                        f"\u26a0\ufe0f <b>IP уже заблокирован</b>\n\n"
                        f"<code>{esc(ip)}</code> уже находится в списке блокировок "
                        f"jail <b>{esc(j.name)}</b>.",
                        parse_mode="HTML",
                    )
                    return
        except Exception:
            pass

        success = deps.f2b_manager.ban_ip(ip, jail)
        await update.message.reply_text(
            format_ban_result(ip, jail, success, "Блокировка"),
            parse_mode="HTML",
        )
        logger.info(f"Ручная блокировка IP={ip} jail={jail} success={success}")
    except Exception as e:
        logger.exception(f"Не удалось заблокировать IP {ip}")
        await update.message.reply_text(
            format_error(f"Не удалось заблокировать IP {ip}: {e}"), parse_mode="HTML"
        )


@require_admin
async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/unban <ip> — разблокирует IP."""
    deps = get_deps(context)

    if deps.f2b_manager is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    args = context.args
    if not args:
        await update.message.reply_text(
            f"\u274c <b>Не указаны параметры</b>\n\n{_usage_unban()}", parse_mode="HTML"
        )
        return

    ip = args[0].strip()

    # Проверка формата IP.
    if not validate_ip(ip):
        await update.message.reply_text(
            format_error(f"Недопустимый IP-адрес: {ip}\n\n{_usage_unban()}"),
            parse_mode="HTML",
        )
        return

    try:
        # Сначала определяем, заблокирован ли IP и в каком jail.
        jail = None
        try:
            for j in deps.f2b_manager.get_jails():
                js = deps.f2b_manager.get_jail_status(j.name)
                if ip in js.banned_ips:
                    jail = j.name
                    break
        except Exception:
            pass

        if jail is None:
            await update.message.reply_text(
                f"\u26a0\ufe0f <b>IP не заблокирован</b>\n\n"
                f"<code>{esc(ip)}</code> не находится в списке блокировок ни одного jail; "
                f"разблокировка не требуется.",
                parse_mode="HTML",
            )
            return

        success = deps.f2b_manager.unban_ip(ip)
        await update.message.reply_text(
            format_ban_result(ip, jail, success, "Разблокировка"),
            parse_mode="HTML",
        )
        logger.info(f"Ручная разблокировка IP={ip} jail={jail} success={success}")
    except Exception as e:
        logger.exception(f"Не удалось разблокировать IP {ip}")
        await update.message.reply_text(
            format_error(f"Не удалось разблокировать IP {ip}: {e}"), parse_mode="HTML"
        )
