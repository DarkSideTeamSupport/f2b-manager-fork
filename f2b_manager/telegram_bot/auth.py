"""
f2b_manager.telegram_bot.auth
=============================

Трёхуровневая авторизация.

Модель прав:
    ADMIN (3)    — все действия: установка/удаление/обновление/блокировка/настройка
    OPERATOR (2) — просмотр состояния, отчёты и переключение уведомлений
    VIEWER (1)   — только /start и /help

Права определяются по config.telegram.admin_chat_ids и operator_chat_ids.
Для обработчиков доступны декораторы require_admin / require_operator.
"""

from __future__ import annotations

import functools
import logging
from typing import TYPE_CHECKING, Callable, Optional

from ..storage.models import AuthLevel

if TYPE_CHECKING:
    from telegram import Update
    from telegram.ext import ContextTypes

    from ..config import TelegramConfig

logger = logging.getLogger(__name__)


class AuthManager:
    """Менеджер трёхуровневых прав.

    Определяет уровень прав по chat_id.
    admin_chat_ids → ADMIN, operator_chat_ids → OPERATOR, остальные → VIEWER.
    """

    def __init__(self, tg_config: Optional["TelegramConfig"] = None):
        self._admin_ids: set[int] = set()
        self._operator_ids: set[int] = set()

        if tg_config is not None:
            self._admin_ids = set(tg_config.admin_chat_ids)
            self._operator_ids = set(tg_config.operator_chat_ids)

    def get_level(self, chat_id: int) -> AuthLevel:
        """Возвращает уровень прав для chat_id."""
        if chat_id in self._admin_ids:
            return AuthLevel.ADMIN
        if chat_id in self._operator_ids:
            return AuthLevel.OPERATOR
        return AuthLevel.VIEWER

    def authorize(self, chat_id: int, required: AuthLevel) -> bool:
        """Проверяет, обладает ли chat_id достаточными правами."""
        return self.get_level(chat_id) >= required

    def is_admin(self, chat_id: int) -> bool:
        return self.get_level(chat_id) >= AuthLevel.ADMIN

    def is_operator(self, chat_id: int) -> bool:
        return self.get_level(chat_id) >= AuthLevel.OPERATOR

    def level_name(self, chat_id: int) -> str:
        """Возвращает русское название уровня прав."""
        level = self.get_level(chat_id)
        names = {
            AuthLevel.ADMIN: "Администратор",
            AuthLevel.OPERATOR: "Оператор",
            AuthLevel.VIEWER: "Гость",
        }
        return names.get(level, "Неизвестно")


# ──────────────────────────────────────────────
# Декораторы
# ──────────────────────────────────────────────

# Отложенный импорт, чтобы избежать циклической зависимости.
def _get_auth(context: "ContextTypes.DEFAULT_TYPE") -> Optional[AuthManager]:
    """Получает AuthManager из context.bot_data."""
    deps = context.bot_data.get("deps")
    if deps is not None:
        return deps.auth
    return context.bot_data.get("auth")


def _deny_message(required: AuthLevel) -> str:
    """Формирует сообщение об отказе в доступе."""
    level_name = {AuthLevel.ADMIN: "Администратор", AuthLevel.OPERATOR: "Оператор"}
    name = level_name.get(required, "Авторизация")
    return f"⛔️ <b>Недостаточно прав</b>\n\nДля этой команды требуются права: <b>{name}</b>.\nВашего уровня доступа недостаточно."


async def notify_denied(update: "Update", required: AuthLevel) -> None:
    """Уведомляет пользователя об отказе в доступе."""
    query = update.callback_query
    if query is not None:
        try:
            await query.answer("Недостаточно прав.", show_alert=True)
        except Exception:
            logger.debug("Не удалось показать уведомление об отказе", exc_info=True)
        try:
            await query.delete_message()
        except Exception:
            logger.debug("Не удалось удалить сообщение с callback", exc_info=True)
        return

    message = update.effective_message
    if message is not None:
        await message.reply_text(_deny_message(required), parse_mode="HTML")


async def ensure_authorized(
    update: "Update",
    context: "ContextTypes.DEFAULT_TYPE",
    required: AuthLevel,
) -> bool:
    """Проверяет доступ и уведомляет пользователя при его отсутствии."""
    # В личке chat.id == user.id; в группах права смотрим по user.id.
    user = update.effective_user
    chat = update.effective_chat
    auth = _get_auth(context)
    auth_id = user.id if user is not None else (chat.id if chat is not None else None)
    if auth_id is not None and auth is not None and auth.authorize(auth_id, required):
        return True

    logger.warning(
        "Несанкционированный доступ: user_id=%s chat_id=%s, требуемый уровень=%s",
        getattr(user, "id", None),
        getattr(chat, "id", None),
        required.name,
    )
    await notify_denied(update, required)
    return False


def require_admin(func: Callable) -> Callable:
    """Декоратор: разрешает выполнение только ADMIN.

    При отказе в доступе отправляет уведомление и возвращает None
    (не продолжает выполнение и не входит в состояние диалога).
    """

    @functools.wraps(func)
    async def wrapper(
        update: "Update", context: "ContextTypes.DEFAULT_TYPE"
    ):
        if not await ensure_authorized(update, context, AuthLevel.ADMIN):
            return None

        return await func(update, context)

    return wrapper


def require_operator(func: Callable) -> Callable:
    """Декоратор: разрешает выполнение OPERATOR и выше."""

    @functools.wraps(func)
    async def wrapper(
        update: "Update", context: "ContextTypes.DEFAULT_TYPE"
    ):
        if not await ensure_authorized(update, context, AuthLevel.OPERATOR):
            return None

        return await func(update, context)

    return wrapper
