"""
f2b_manager.telegram_bot.handlers.manage
==========================================

Обработчик команд управления установкой.

Команды:
    /install    — установка Fail2ban (асинхронно + прогресс)
    /uninstall  — удаление Fail2ban (ConversationHandler с подтверждением)
    /update     — обновление Fail2ban (асинхронно + прогресс)
    /reload     — перезагрузка конфигурации Fail2ban

Права: администратор (ADMIN)

Машина состояний ConversationHandler (/uninstall):
    /uninstall → CONFIRM → [подтвердить] → выполнить удаление → END
                        → [отмена]      → END
                        → /cancel       → END
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable

from telegram import Update
from telegram.ext import CallbackQueryHandler, CommandHandler, \
    ContextTypes, ConversationHandler

from ...storage.models import AuthLevel
from ..auth import ensure_authorized, require_admin
from ..deps import get_deps
from ..formatters import esc, format_cancelled, format_error, \
    format_install_result, format_not_ready, format_progress, format_success
from ..keyboards import CALLBACK_CANCEL, CALLBACK_CONFIRM, \
    confirm_uninstall_keyboard

logger = logging.getLogger(__name__)

# Состояние ConversationHandler.
CONFIRM = 1


# ──────────────────────────────────────────────
# Вспомогательные функции для длительных операций.
# ──────────────────────────────────────────────

async def _run_with_progress(
    message: Any,
    operation: Callable,
    initial_text: str,
    steps: list[str],
    action_label: str,
) -> str:
    """Выполняет синхронную операцию в executor и отправляет ход выполнения.

    Args:
        message: объект сообщения с методом edit_text (Message)
        operation: синхронный вызываемый объект
        initial_text: исходное сообщение о ходе выполнения
        steps: список сообщений о шагах
        action_label: метка операции (для журналирования)

    Returns:
        Форматированный итоговый текст или текст ошибки при исключении.
    """
    loop = asyncio.get_running_loop()

    # Отправляем исходный прогресс; игнорируем одинаковый текст.
    try:
        await message.edit_text(
            format_progress(initial_text), parse_mode="HTML"
        )
    except Exception:
        pass  # Telegram возвращает 400, если содержимое не изменилось.

    # Передаём операцию в пул потоков.
    task = loop.run_in_executor(None, operation)

    # Опрос хода выполнения.
    step_idx = 0
    while not task.done():
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=4.0)
        except asyncio.TimeoutError:
            # Операция продолжается, отправляем следующий шаг.
            if step_idx < len(steps):
                try:
                    await message.edit_text(
                        format_progress(steps[step_idx]), parse_mode="HTML"
                    )
                except Exception:
                    pass  # Ошибка редактирования (например, лимит) не влияет на выполнение.
                step_idx += 1
            else:
                # Шаги закончились — показываем общий прогресс.
                elapsed = step_idx * 4
                try:
                    await message.edit_text(
                        format_progress(
                            f"Выполняется: {action_label}... Прошло: {elapsed} с"
                        ),
                        parse_mode="HTML",
                    )
                except Exception:
                    pass
                step_idx += 1

    # Получаем результат.
    try:
        result = task.result()
        return format_install_result(result, action_label)
    except Exception as e:
        logger.exception(f"Ошибка операции «{action_label}»")
        return format_error(f"Ошибка операции «{action_label}»: {e}")


# ──────────────────────────────────────────────
# /install
# ──────────────────────────────────────────────

@require_admin
async def cmd_install(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/install — устанавливает Fail2ban."""
    deps = get_deps(context)
    installer = deps.get_installer()

    if installer is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    # Создаём сообщение прогресса (reply_text), далее обновляем через edit_text
    progress_msg = await update.message.reply_text(
        format_progress("Устанавливается Fail2ban, подождите..."), parse_mode="HTML"
    )

    steps = [
        "Определяется дистрибутив системы...",
        "Обновляется индекс пакетов...",
        "Устанавливаются зависимости...",
        "Устанавливается Fail2ban...",
        "Создаётся конфигурация jail.local...",
        "Развёртывается действие уведомлений Telegram...",
        "Развёртывается скрипт notify.sh...",
        "Запускается и включается служба fail2ban...",
        "Проверяется установка...",
    ]

    result_text = await _run_with_progress(
        message=progress_msg,
        operation=installer.install,
        initial_text="Устанавливается Fail2ban, подождите...",
        steps=steps,
        action_label="установка",
    )

    await progress_msg.edit_text(result_text, parse_mode="HTML")
    logger.info(
        f"Установка завершена (chat_id={update.effective_chat.id})"
    )


# ──────────────────────────────────────────────
# /update
# ──────────────────────────────────────────────

@require_admin
async def cmd_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/update — обновляет Fail2ban."""
    deps = get_deps(context)
    installer = deps.get_installer()

    if installer is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    progress_msg = await update.message.reply_text(
        format_progress("Обновляется Fail2ban, подождите..."), parse_mode="HTML"
    )

    steps = [
        "Определяется текущая версия...",
        "Обновляется индекс пакетов...",
        "Обновляется Fail2ban...",
        "Перезапускается служба fail2ban...",
        "Проверяется результат обновления...",
    ]

    result_text = await _run_with_progress(
        message=progress_msg,
        operation=installer.update,
        initial_text="Обновляется Fail2ban, подождите...",
        steps=steps,
        action_label="обновление",
    )

    await progress_msg.edit_text(result_text, parse_mode="HTML")
    logger.info(
        f"Обновление завершено (chat_id={update.effective_chat.id})"
    )


# ──────────────────────────────────────────────
# /reload
# ──────────────────────────────────────────────

@require_admin
async def cmd_reload(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/reload — перезагружает конфигурацию Fail2ban."""
    deps = get_deps(context)

    if deps.f2b_manager is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return

    try:
        success = deps.f2b_manager.reload()
        if success:
            await update.message.reply_text(
                format_success("Конфигурация Fail2ban перезагружена"), parse_mode="HTML"
            )
        else:
            await update.message.reply_text(
                format_error("Перезагрузка не удалась: fail2ban-client reload вернул ненулевой код"),
                parse_mode="HTML",
            )
    except Exception as e:
        logger.exception("Не удалось перезагрузить конфигурацию")
        await update.message.reply_text(
            format_error(f"Не удалось перезагрузить конфигурацию: {e}"), parse_mode="HTML"
        )


# ──────────────────────────────────────────────
# /uninstall — ConversationHandler
# ──────────────────────────────────────────────

@require_admin
async def cmd_uninstall_entry(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    """/uninstall — точка входа, показывает клавиатуру подтверждения."""
    deps = get_deps(context)
    installer = deps.get_installer()

    if installer is None:
        await update.message.reply_text(format_not_ready(), parse_mode="HTML")
        return ConversationHandler.END

    # Сохраняем chat_id для callback
    context.user_data["uninstall_chat_id"] = update.effective_chat.id

    await update.message.reply_text(
        "\u26a0\ufe0f <b>Подтвердите удаление Fail2ban</b>\n\n"
        "Будут выполнены шаги:\n"
        "  • остановка службы fail2ban\n"
        "  • отключение автозапуска\n"
        "  • удаление пакета fail2ban\n"
        "  • резервная копия конфигурации в /etc/fail2ban.backup\n"
        "  • очистка скриптов уведомлений\n\n"
        "<b>Действие необратимо! Продолжить?</b>",
        reply_markup=confirm_uninstall_keyboard(),
        parse_mode="HTML",
    )
    return CONFIRM


async def uninstall_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    """Callback подтверждения удаления — обрабатывает кнопки подтверждения и отмены."""
    if not await ensure_authorized(update, context, AuthLevel.ADMIN):
        return ConversationHandler.END

    query = update.callback_query
    await query.answer()

    deps = get_deps(context)

    # ── Отмена ──
    if query.data == CALLBACK_CANCEL:
        await query.edit_message_text(
            format_cancelled(), parse_mode="HTML"
        )
        return ConversationHandler.END

    # ── Подтверждение ──
    if query.data == CALLBACK_CONFIRM:
        installer = deps.get_installer()
        if installer is None:
            await query.edit_message_text(
                format_not_ready(), parse_mode="HTML"
            )
            return ConversationHandler.END

        # Сообщение о прогрессе
        await query.edit_message_text(
            format_progress("Удаляется Fail2ban, подождите..."),
            parse_mode="HTML",
        )

        loop = asyncio.get_running_loop()

        # Удаление в executor (конфигурация сохраняется в backup)
        uninstall_op = functools.partial(
            installer.uninstall, keep_config=True
        )

        try:
            result = await loop.run_in_executor(None, uninstall_op)
            await query.edit_message_text(
                format_install_result(result, "удаление"),
                parse_mode="HTML",
            )
        except Exception as e:
            logger.exception("Ошибка операции удаления")
            await query.edit_message_text(
                format_error(f"Удаление не удалось: {e}"), parse_mode="HTML"
            )

        logger.info(
            "Удаление завершено (chat_id=%s)",
            update.effective_chat.id,
        )
        return ConversationHandler.END

    # Неизвестный callback
    return ConversationHandler.END


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """/cancel — отмена текущей операции (fallback ConversationHandler)."""
    await update.message.reply_text(
        format_cancelled(), parse_mode="HTML"
    )
    return ConversationHandler.END


# ──────────────────────────────────────────────
# Определение ConversationHandler (для bot.py)
# ──────────────────────────────────────────────

def get_uninstall_handler() -> ConversationHandler:
    """Создаёт ConversationHandler для /uninstall."""
    return ConversationHandler(
        entry_points=[CommandHandler("uninstall", cmd_uninstall_entry)],
        states={
            CONFIRM: [
                CallbackQueryHandler(uninstall_callback),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", cmd_cancel),
        ],
        # per_message=False (по умолчанию):
        # вход — CommandHandler, в states — CallbackQueryHandler.
        # PTB может выдать информационное предупреждение — это нормально.
        per_user=True,
        per_chat=True,
    )
