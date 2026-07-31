"""
tests/conftest.py
==================
pytest общедоступный fixtures.

поставлять:
- tmp_db: временный экземпляр SQLite StateDB.
- sample_config: экземпляр AppConfig для тестирования.
- sample_config_yaml: полная строка конфигурации YAML.
- mock_bot: Mock, реализующий IMessageSender, регистрирующий все вызовы.
"""
from __future__ import annotations

import os
import sys
import tempfile
from unittest.mock import MagicMock

import pytest

# Убедитесь, что корень проекта находится в sys.path.
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from f2b_manager.config import (
    AppConfig,
    DatabaseConfig,
    Fail2banConfig,
    LoggingConfig,
    NotifyConfig,
    ScheduleConfig,
    TelegramConfig,
)
from f2b_manager.storage.database import StateDB
from f2b_manager.storage.models import BanEvent, BanAction


# ── Database fixtures ──────────────────────────

@pytest.fixture
def tmp_db():
    """Создайте временную базу данных SQLite и автоматически очистите ее после тестирования."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = StateDB(db_path)
    yield db
    db.close()
    os.unlink(db_path)


# ── Config fixtures ────────────────────────────

@pytest.fixture
def sample_config():
    """Возвращает экземпляр AppConfig, который можно использовать для тестирования."""
    return AppConfig(
        telegram=TelegramConfig(
            bot_token="test:token_for_unit_test",
            admin_chat_ids=[123456789],
            operator_chat_ids=[987654321],
            notify_chat_id=123456789,
            mode="polling",
        ),
        fail2ban=Fail2banConfig(
            default_bantime="1h",
            default_findtime="10m",
            default_maxretry=5,
            incremental=True,
            max_bantime="1w",
            ignoreip=["127.0.0.1/8", "::1"],
            enabled_jails=["sshd", "recidive"],
        ),
        notify=NotifyConfig(
            enable_ban_alert=True,
            enable_unban_alert=False,
            enable_service_alert=True,
            enable_health_alert=True,
            geoip_enabled=False,
            geoip_method="local",
            geoip_db_path="/tmp/nonexistent.mmdb",
            dedup_window_seconds=300,
        ),
        schedule=ScheduleConfig(
            daily_report_enabled=True,
            daily_report_time="08:00",
            weekly_report_enabled=True,
            weekly_report_day="monday",
            weekly_report_time="08:00",
            poll_interval_minutes=5,
            health_check_minutes=10,
        ),
        logging=LoggingConfig(
            level="INFO",
            file="/tmp/f2b-test.log",
            max_size_mb=1,
            backup_count=1,
        ),
        database=DatabaseConfig(
            path="/tmp/f2b-test.db",
        ),
    )


@pytest.fixture
def sample_config_yaml():
    """Возвращает полную строку конфигурации YAML для тестирования загрузки конфигурации."""
    return """
telegram:
  bot_token: "123456:abc_test_token"
  admin_chat_ids: [111, 222]
  operator_chat_ids: [333]
  notify_chat_id: 444
  mode: polling

fail2ban:
  default_bantime: "2h"
  default_findtime: "15m"
  default_maxretry: 3
  incremental: false
  ignoreip: ["127.0.0.1/8", "10.0.0.0/8"]
  enabled_jails: ["sshd", "nginx-http-auth"]

schedule:
  daily_report:
    enabled: true
    time: "09:00"
  weekly_report:
    enabled: false
  poll_interval_minutes: 10
  health_check_minutes: 15

notify:
  enable_ban_alert: true
  enable_unban_alert: true
  enable_service_alert: false
  geoip:
    enabled: false
  dedup_window_seconds: 600

logging:
  level: "DEBUG"
  file: "/tmp/test.log"
  max_size_mb: 5
  backup_count: 3

database:
  path: "/tmp/test.db"
"""


# ── Bot mock fixture ───────────────────────────

class MockBot:
    """Класс Mock реализует протокол IMessageSender, регистрирующий все вызовы.

    Может использоваться для проверки правильности составления и отправки сообщения.
    """

    def __init__(self):
        self.alerts: list[dict] = []
        self.reports: list[dict] = []
        self.should_fail: bool = False  # Установите значение True для имитации сбоя отправки.

    async def send_alert(self, chat_id: int, message: str,
                         parse_mode: str = "HTML") -> bool:
        if self.should_fail:
            return False
        self.alerts.append({
            "chat_id": chat_id,
            "message": message,
            "parse_mode": parse_mode,
        })
        return True

    async def send_report(self, chat_id: int, message: str) -> bool:
        if self.should_fail:
            return False
        self.reports.append({
            "chat_id": chat_id,
            "message": message,
        })
        return True

    def reset(self) -> None:
        """Очистите запись, чтобы облегчить несколько утверждений."""
        self.alerts.clear()
        self.reports.clear()


@pytest.fixture
def mock_bot():
    """Возвращает экземпляр MockBot, регистрирующий все вызовы send_alert/send_report."""
    return MockBot()


# ── Ban event fixtures ─────────────────────────

@pytest.fixture
def sample_ban_event():
    """Стандартное событие бана fixture."""
    from datetime import datetime
    return BanEvent(
        ip="203.0.113.1",
        jail="sshd",
        action=BanAction.BAN,
        failures=5,
        matches="_SYSTEMD_UNIT=sshd.service + _COMM=sshd",
        timestamp=datetime(2026, 7, 11, 14, 30, 0),
    )


@pytest.fixture
def sample_unban_event():
    """Стандартное событие разблокировки fixture."""
    from datetime import datetime
    return BanEvent(
        ip="203.0.113.1",
        jail="sshd",
        action=BanAction.UNBAN,
        timestamp=datetime(2026, 7, 11, 15, 0, 0),
    )
