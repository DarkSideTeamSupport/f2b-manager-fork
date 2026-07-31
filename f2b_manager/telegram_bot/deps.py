"""
f2b_manager.telegram_bot.deps
=============================

Контейнер общих зависимостей.

При инициализации Bot упаковывает config / f2b_manager / installer / db / auth
в BotDeps и сохраняет его в Application.bot_data["deps"]. Все обработчики получают
зависимости через get_deps(), что предотвращает циклические импорты.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from telegram import Update
    from telegram.ext import ContextTypes

    from ..config import AppConfig
    from ..storage.database import StateDB
    from ..storage.models import IFail2banInstaller, IFail2banManager
    from .auth import AuthManager


@dataclass
class BotDeps:
    """Общие зависимости Bot во время работы (внедряются в Application.bot_data)."""

    config: "AppConfig"
    f2b_manager: Optional["IFail2banManager"] = None
    installer: Optional["IFail2banInstaller"] = None
    db: Optional["StateDB"] = None
    auth: Optional["AuthManager"] = None

    # ── Удобные свойства ──────────────────────

    @property
    def tg(self) -> "Any":
        """Быстрый доступ к TelegramConfig."""
        return self.config.telegram

    @property
    def f2b(self) -> Optional["IFail2banManager"]:
        return self.f2b_manager

    def get_installer(self) -> Optional["IFail2banInstaller"]:
        """Возвращает установщик: сначала явно внедрённый installer,
        затем проверяет, реализует ли f2b_manager метод установки (утиная типизация)."""
        if self.installer is not None:
            return self.installer
        if self.f2b_manager is not None and hasattr(self.f2b_manager, "install"):
            return self.f2b_manager  # type: ignore[return-value]
        return None


def get_deps(context: "ContextTypes.DEFAULT_TYPE") -> BotDeps:
    """Получает BotDeps из context.bot_data."""
    return context.bot_data["deps"]


def f2b_not_ready() -> str:
    """Стандартное уведомление, если f2b_manager не готов."""
    return (
        "⚠️ <b>Функция ещё не готова</b>\n\n"
        "Модуль управления Fail2ban (M1) ещё не загружен.\n"
        "Установите и запустите f2b-manager на сервере, затем повторите попытку."
    )
