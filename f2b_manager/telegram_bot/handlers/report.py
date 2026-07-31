"""
f2b_manager.telegram_bot.handlers.report
==========================================

Обработчик команд отчётов и статистики.

Команды:
    /report       — сформировать отчёт сейчас
    /stats [days] — статистика блокировок за N дней (по умолчанию 7)

Права: оператор (OPERATOR) и выше
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from ..auth import require_operator
from ..deps import get_deps
from ..formatters import format_daily_stats, format_error, \
    format_stats_summary, format_status

logger = logging.getLogger(__name__)


@require_operator
async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/report — формирует отчёт в реальном времени."""
    deps = get_deps(context)

    lines = ["\U0001f4cb <b>Отчёт Fail2ban в реальном времени</b>", ""]

    # 1. Состояние службы.
    if deps.f2b_manager is not None:
        try:
            status = deps.f2b_manager.get_status()
            lines.append(format_status(status))
        except Exception as e:
            logger.exception("Не удалось получить состояние")
            lines.append(f"\u26a0\ufe0f Не удалось получить состояние: {e}")
    else:
        lines.append("\u26a0\ufe0f Модуль управления Fail2ban не загружен")

    lines.append("")

    # 2. Статистика блокировок.
    if deps.db is not None:
        try:
            bans_today = deps.db.count_bans_today()
            lines.append(f"\U0001f6ab <b>Блокировок сегодня:</b> <code>{bans_today}</code>")

            current_bans = deps.db.get_current_bans()
            lines.append(
                f"\U0001f310 <b>Активных блокировок:</b> <code>{len(current_bans)}</code> IP"
            )

            # Топ-5 атакующих IP за последние 7 дней.
            top_ips = deps.db.top_banned_ips(days=7, limit=5)
            if top_ips:
                lines.append("")
                lines.append("\U0001f525 <b>Топ атакующих IP за 7 дней:</b>")
                for i, (ip, count) in enumerate(top_ips, 1):
                    lines.append(f"  {i}. <code>{ip}</code> — <b>{count}</b> раз")

            # Топ-5 стран-источников.
            top_countries = deps.db.top_banned_countries(days=7, limit=5)
            if top_countries:
                lines.append("")
                lines.append("\U0001f30d <b>Топ стран-источников за 7 дней:</b>")
                for i, (country, count) in enumerate(top_countries, 1):
                    name = country or "Неизвестно"
                    lines.append(f"  {i}. {name} — <b>{count}</b> раз")
        except Exception as e:
            logger.exception("Не удалось получить статистику")
            lines.append(f"\u26a0\ufe0f Не удалось получить статистику: {e}")
    else:
        lines.append("\u26a0\ufe0f База состояния не загружена")

    lines.append("")
    lines.append(
        f"\U0001f552 <b>Время отчёта:</b> "
        f"{__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


@require_operator
async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/stats [days] — показывает статистику блокировок за N дней."""
    deps = get_deps(context)

    if deps.db is None:
        await update.message.reply_text(
            format_error("База состояния не загружена, получить статистику невозможно"), parse_mode="HTML"
        )
        return

    # Разбираем параметр количества дней.
    days = 7
    if context.args:
        try:
            days = int(context.args[0])
            if days < 1 or days > 365:
                await update.message.reply_text(
                    format_error("Допустимый диапазон дней: 1–365"), parse_mode="HTML"
                )
                return
        except ValueError:
            await update.message.reply_text(
                format_error(f"Недопустимое количество дней: {context.args[0]}"), parse_mode="HTML"
            )
            return

    try:
        # Получаем статистику по дням.
        daily_stats = deps.db.get_daily_stats(days=days)

        # Рассчитываем сводные показатели.
        total_bans = sum(s.total_bans for s in daily_stats)
        unique_ips = sum(s.unique_ips for s in daily_stats)

        # Топ IP и стран.
        top_ips = deps.db.top_banned_ips(days=days, limit=10)
        top_countries = deps.db.top_banned_countries(days=days, limit=10)

        # Отправляем сводку статистики.
        await update.message.reply_text(
            format_stats_summary(
                total_bans=total_bans,
                unique_ips=unique_ips,
                top_ips=top_ips,
                top_countries=top_countries,
                days=days,
            ),
            parse_mode="HTML",
        )

        # При наличии отправляем статистику по дням.
        if daily_stats:
            await update.message.reply_text(
                format_daily_stats(daily_stats), parse_mode="HTML"
            )

    except Exception as e:
        logger.exception("Не удалось получить статистику")
        await update.message.reply_text(
            format_error(f"Не удалось получить статистику: {e}"), parse_mode="HTML"
        )
