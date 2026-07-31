"""
tests/test_cli.py
=================
CLI notify проверка команды.

крышка:
- Если bot_token существует, _cmd_notify создает _CliBotSender и правильно вызывает send_alert.
- Когда bot_token не существует, _cmd_notify не сообщает об ошибке, AlertSender получает bot=None
- _CliBotSender.send_alert фактически вызывает telegram.Bot.send_message
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from f2b_manager.config import AppConfig, TelegramConfig


# ── helpers ────────────────────────────────────

def _make_args(**kwargs):
    """Создает объект mock args, аналогичный argparse.Namespace."""
    args = MagicMock()
    args.event = kwargs.get("event", "ban")
    args.ip = kwargs.get("ip", "203.0.113.1")
    args.jail = kwargs.get("jail", "sshd")
    args.failures = kwargs.get("failures", "5")
    args.matches = kwargs.get("matches", "test log line")
    return args


def _make_config(*, bot_token: str = "", notify_chat_id: int = 0):
    """Создайте AppConfig для тестирования."""
    return AppConfig(
        telegram=TelegramConfig(
            bot_token=bot_token,
            admin_chat_ids=[123456789],
            notify_chat_id=notify_chat_id,
        ),
    )


# ── Test: _CliBotSender ────────────────────────

class TestCliBotSender:
    """Модульный тест _CliBotSender.

    _CliBotSender.__init__ внутри import telegram.Bot, поэтому
    Требуется patch telegram.Bot вместо f2b_manager.cli.Bot.
    """

    @pytest.mark.asyncio
    async def test_send_alert_calls_bot_send_message(self):
        """send_alert должен вызвать telegram.Bot.send_message."""
        from f2b_manager.cli import _CliBotSender

        with patch("telegram.Bot") as MockBot:
            mock_bot_instance = MockBot.return_value
            mock_bot_instance.send_message = AsyncMock(return_value=None)

            sender = _CliBotSender(token="test:token123")
            result = await sender.send_alert(
                chat_id=12345,
                message="<b>Test Alert</b>",
                parse_mode="HTML",
            )

            assert result is True
            mock_bot_instance.send_message.assert_called_once_with(
                chat_id=12345,
                text="<b>Test Alert</b>",
                parse_mode="HTML",
                disable_web_page_preview=True,
            )

    @pytest.mark.asyncio
    async def test_send_alert_handles_forbidden(self):
        """Исключения Forbidden должны возвращать False и не создаваться."""
        from f2b_manager.cli import _CliBotSender
        from telegram.error import Forbidden

        with patch("telegram.Bot") as MockBot:
            mock_bot_instance = MockBot.return_value
            mock_bot_instance.send_message = AsyncMock(
                side_effect=Forbidden("blocked")
            )

            sender = _CliBotSender(token="test:token123")
            result = await sender.send_alert(chat_id=12345, message="test")

            assert result is False

    @pytest.mark.asyncio
    async def test_send_alert_handles_network_error(self):
        """Исключения NetworkError должны возвращать False."""
        from f2b_manager.cli import _CliBotSender
        from telegram.error import NetworkError

        with patch("telegram.Bot") as MockBot:
            mock_bot_instance = MockBot.return_value
            mock_bot_instance.send_message = AsyncMock(
                side_effect=NetworkError("timeout")
            )

            sender = _CliBotSender(token="test:token123")
            result = await sender.send_alert(chat_id=12345, message="test")

            assert result is False

    @pytest.mark.asyncio
    async def test_send_alert_handles_generic_telegram_error(self):
        """Общее исключение TelegramError должно возвращать False."""
        from f2b_manager.cli import _CliBotSender
        from telegram.error import TelegramError

        with patch("telegram.Bot") as MockBot:
            mock_bot_instance = MockBot.return_value
            mock_bot_instance.send_message = AsyncMock(
                side_effect=TelegramError("unknown error")
            )

            sender = _CliBotSender(token="test:token123")
            result = await sender.send_alert(chat_id=12345, message="test")

            assert result is False

    @pytest.mark.asyncio
    async def test_send_report_returns_false(self):
        """send_report в режиме CLI должен возвращать False (не поддерживается)."""
        from f2b_manager.cli import _CliBotSender

        with patch("telegram.Bot") as MockBot:
            sender = _CliBotSender(token="test:token123")
            result = await sender.send_report(chat_id=12345, message="report")
            assert result is False


# ── Test: _cmd_notify integration ──────────────

class TestCmdNotifyWithToken:
    """Тест интеграции _cmd_notify при наличии bot_token.

    Внутренний _cmd_notify import StateDB, AlertSender и т. д. требует наличия patch в целевом модуле.
    """

    def test_creates_cli_bot_sender_when_token_present(self):
        """AlertSender должен получить bot, который не является None, когда есть bot_token."""
        from f2b_manager.cli import _cmd_notify

        config = _make_config(bot_token="real:token123", notify_chat_id=12345)
        args = _make_args()

        with patch("f2b_manager.storage.database.StateDB") as MockStateDB, \
             patch("f2b_manager.notify.sender.AlertSender") as MockAlertSender, \
             patch("f2b_manager.cli._CliBotSender") as MockCliBotSender:

            mock_db = MockStateDB.return_value
            mock_db.close = MagicMock()

            mock_sender = MockAlertSender.return_value
            mock_sender.send_ban_alert = AsyncMock(return_value=True)
            mock_sender.close = MagicMock()

            mock_bot = MockCliBotSender.return_value

            result = _cmd_notify(config, args)

            # Убедитесь, что _CliBotSender создан.
            MockCliBotSender.assert_called_once_with("real:token123")

            # Убедитесь, что AlertSender был создан, когда параметр bot не был None.
            _, call_kwargs = MockAlertSender.call_args
            assert call_kwargs["bot"] is mock_bot

            # Убедитесь, что send_ban_alert вызывается
            mock_sender.send_ban_alert.assert_called_once()

            # Код возврата проверки – 0 (успех).
            assert result == 0


class TestCmdNotifyWithoutToken:
    """Тест интеграции _cmd_notify, когда bot_token не существует"""

    def test_alert_sender_receives_bot_none(self):
        """Если bot_token отсутствует, AlertSender должен получить bot=None, не сообщая об ошибке."""
        from f2b_manager.cli import _cmd_notify

        config = _make_config(bot_token="")
        args = _make_args()

        with patch("f2b_manager.storage.database.StateDB") as MockStateDB, \
             patch("f2b_manager.notify.sender.AlertSender") as MockAlertSender:

            mock_db = MockStateDB.return_value
            mock_db.close = MagicMock()

            mock_sender = MockAlertSender.return_value
            mock_sender.send_ban_alert = AsyncMock(return_value=True)
            mock_sender.close = MagicMock()

            result = _cmd_notify(config, args)

            # Убедитесь, что AlertSender создается, когда bot=None.
            _, call_kwargs = MockAlertSender.call_args
            assert call_kwargs["bot"] is None

            # Проверка не сообщает об ошибке и возвращается нормально.
            assert result == 0

    def test_no_token_no_crash(self):
        """Ошибки быть не должно, если bot_token отсутствует и инициализация базы данных не удалась."""
        from f2b_manager.cli import _cmd_notify

        config = _make_config(bot_token="")
        args = _make_args()

        # Инициализация моделирования StateDB не удалась.
        with patch("f2b_manager.storage.database.StateDB",
                   side_effect=Exception("disk full")), \
             patch("f2b_manager.notify.sender.AlertSender") as MockAlertSender:

            mock_sender = MockAlertSender.return_value
            mock_sender.send_ban_alert = AsyncMock(return_value=True)
            mock_sender.close = MagicMock()

            result = _cmd_notify(config, args)

            # Даже если db завершится неудачно, он должен вернуться нормально.
            assert result == 0


class TestCmdNotifyUnbanEvent:
    """_cmd_notify тест на событие разблокировки"""

    def test_unban_event_with_token(self):
        """Событие UNBAN обрабатывается нормально при наличии token."""
        from f2b_manager.cli import _cmd_notify

        config = _make_config(bot_token="test:token", notify_chat_id=12345)
        args = _make_args(event="unban")

        with patch("f2b_manager.storage.database.StateDB") as MockStateDB, \
             patch("f2b_manager.notify.sender.AlertSender") as MockAlertSender, \
             patch("f2b_manager.cli._CliBotSender"):

            mock_db = MockStateDB.return_value
            mock_db.close = MagicMock()

            mock_sender = MockAlertSender.return_value
            mock_sender.send_ban_alert = AsyncMock(return_value=True)
            mock_sender.close = MagicMock()

            result = _cmd_notify(config, args)
            assert result == 0
            mock_sender.send_ban_alert.assert_called_once()
