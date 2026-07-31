"""
tests/test_config.py
====================
Загрузка конфигурации и проверочное тестирование.

Переопределения: AppConfig.from_dict / validate / load_config / По умолчанию / Правильность типа.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from f2b_manager.config import (
    AppConfig,
    TelegramConfig,
    Fail2banConfig,
    NotifyConfig,
    ScheduleConfig,
    LoggingConfig,
    DatabaseConfig,
    load_config,
)


class TestAppConfigDefaults:
    """Тест конфигурации по умолчанию"""

    def test_default_config(self):
        """AppConfig Значение по умолчанию правильное."""
        cfg = AppConfig()
        assert cfg.telegram.bot_token == ""
        assert cfg.telegram.mode == "polling"
        assert cfg.fail2ban.default_bantime == "1h"
        assert cfg.fail2ban.default_findtime == "10m"
        assert cfg.fail2ban.default_maxretry == 5
        assert cfg.fail2ban.incremental is True
        assert cfg.fail2ban.max_bantime == "1w"
        assert cfg.fail2ban.ignoreip == ["127.0.0.1/8", "::1"]
        assert cfg.fail2ban.enabled_jails == ["sshd"]
        assert cfg.notify.enable_ban_alert is True
        assert cfg.notify.enable_unban_alert is False
        assert cfg.notify.geoip_enabled is True
        assert cfg.notify.dedup_window_seconds == 300
        assert cfg.schedule.daily_report_enabled is True
        assert cfg.schedule.daily_report_time == "08:00"
        assert cfg.schedule.poll_interval_minutes == 5
        assert cfg.logging.level == "INFO"

    def test_default_from_dict_empty(self):
        """В конструкции пустого словаря используются значения по умолчанию."""
        cfg = AppConfig.from_dict({})
        assert cfg.telegram.bot_token == ""


class TestAppConfigFromDict:
    """Создание тестов конфигурации из словаря"""

    def test_from_dict_full(self):
        """Полный словарь построен правильно со всеми полями."""
        data = {
            "telegram": {
                "bot_token": "abc:123",
                "admin_chat_ids": [111],
                "operator_chat_ids": [222],
                "notify_chat_id": 333,
                "mode": "webhook",
                "webhook": {
                    "url": "https://example.com/webhook",
                    "port": 8443,
                },
                "rate_limit": {
                    "max_messages_per_minute": 10,
                    "cooldown_on_burst": 30,
                },
            },
            "fail2ban": {
                "default_bantime": "2h",
                "default_findtime": "15m",
                "default_maxretry": 3,
                "incremental": False,
                "max_bantime": "2w",
                "ignoreip": ["127.0.0.1/8"],
                "enabled_jails": ["sshd", "recidive"],
            },
            "schedule": {
                "daily_report": {"enabled": False, "time": "09:00"},
                "weekly_report": {"enabled": True, "day": "friday", "time": "18:00"},
                "poll_interval_minutes": 10,
                "health_check_minutes": 20,
            },
            "notify": {
                "enable_ban_alert": False,
                "enable_unban_alert": True,
                "enable_service_alert": False,
                "enable_health_alert": False,
                "geoip": {
                    "enabled": False,
                    "method": "api",
                    "db_path": "/custom/path.mmdb",
                },
                "dedup_window_seconds": 600,
            },
            "logging": {
                "level": "DEBUG",
                "file": "/custom/log.log",
                "max_size_mb": 20,
                "backup_count": 10,
            },
            "database": {
                "path": "/custom/db.db",
            },
        }

        cfg = AppConfig.from_dict(data)

        # Telegram
        assert cfg.telegram.bot_token == "abc:123"
        assert cfg.telegram.admin_chat_ids == [111]
        assert cfg.telegram.operator_chat_ids == [222]
        assert cfg.telegram.notify_chat_id == 333
        assert cfg.telegram.mode == "webhook"
        assert cfg.telegram.webhook_url == "https://example.com/webhook"
        assert cfg.telegram.webhook_port == 8443
        assert cfg.telegram.max_messages_per_minute == 10
        assert cfg.telegram.cooldown_on_burst == 30

        # Fail2ban
        assert cfg.fail2ban.default_bantime == "2h"
        assert cfg.fail2ban.default_findtime == "15m"
        assert cfg.fail2ban.default_maxretry == 3
        assert cfg.fail2ban.incremental is False
        assert cfg.fail2ban.max_bantime == "2w"
        assert cfg.fail2ban.ignoreip == ["127.0.0.1/8"]
        assert cfg.fail2ban.enabled_jails == ["sshd", "recidive"]

        # Schedule
        assert cfg.schedule.daily_report_enabled is False
        assert cfg.schedule.daily_report_time == "09:00"
        assert cfg.schedule.weekly_report_enabled is True
        assert cfg.schedule.weekly_report_day == "friday"
        assert cfg.schedule.weekly_report_time == "18:00"
        assert cfg.schedule.poll_interval_minutes == 10
        assert cfg.schedule.health_check_minutes == 20

        # Notify
        assert cfg.notify.enable_ban_alert is False
        assert cfg.notify.enable_unban_alert is True
        assert cfg.notify.enable_service_alert is False
        assert cfg.notify.geoip_enabled is False
        assert cfg.notify.geoip_method == "api"
        assert cfg.notify.geoip_db_path == "/custom/path.mmdb"
        assert cfg.notify.dedup_window_seconds == 600

        # Logging
        assert cfg.logging.level == "DEBUG"
        assert cfg.logging.file == "/custom/log.log"
        assert cfg.logging.max_size_mb == 20
        assert cfg.logging.backup_count == 10

        # Database
        assert cfg.database.path == "/custom/db.db"

    def test_from_dict_partial(self):
        """Значения по умолчанию следует использовать, когда некоторые поля словаря отсутствуют."""
        cfg = AppConfig.from_dict({
            "telegram": {"bot_token": "token123", "admin_chat_ids": [1]},
        })
        assert cfg.telegram.bot_token == "token123"
        assert cfg.telegram.mode == "polling"  # значение по умолчанию
        assert cfg.fail2ban.default_bantime == "1h"  # значение по умолчанию

    def test_env_token_override(self):
        """Переопределение переменной среды тестирования F2B_BOT_TOKEN."""
        # Использовать значение словаря, если нет переменной среды
        cfg = AppConfig.from_dict({
            "telegram": {"bot_token": "dict_token"},
        })
        assert cfg.telegram.bot_token == "dict_token"


class TestAppConfigValidate:
    """Тест проверки конфигурации"""

    def test_valid_config(self, sample_config):
        """Полная и действительная конфигурация должна быть правильной."""
        errors = sample_config.validate()
        # sample_config имеет bot_token, admin_chat_ids, notify_chat_id
        assert len(errors) == 0

    def test_missing_bot_token(self):
        """Отсутствие bot_token должно сообщить об ошибке."""
        cfg = AppConfig()
        errors = cfg.validate()
        assert any("bot_token" in e.lower() for e in errors)

    def test_missing_admin_chat_ids(self):
        """Отсутствие admin_chat_ids должно сообщить об ошибке."""
        cfg = AppConfig()
        cfg.telegram.bot_token = "test"
        cfg.telegram.notify_chat_id = 123
        # admin_chat_ids пуст.
        errors = cfg.validate()
        assert any("admin" in e.lower() for e in errors)

    def test_missing_notify_chat_id(self):
        """Если notify_chat_id равен 0, следует сообщить об ошибке."""
        cfg = AppConfig()
        cfg.telegram.bot_token = "test"
        cfg.telegram.admin_chat_ids = [1]
        errors = cfg.validate()
        assert any("notify_chat_id" in e.lower() for e in errors)

    def test_invalid_mode(self):
        """Неверный telegram.mode должен сообщить об ошибке."""
        cfg = AppConfig()
        cfg.telegram.bot_token = "test"
        cfg.telegram.admin_chat_ids = [1]
        cfg.telegram.notify_chat_id = 1
        cfg.telegram.mode = "invalid_mode"
        errors = cfg.validate()
        assert any("mode" in e.lower() for e in errors)

    def test_webhook_missing_url(self):
        """url не установлен в режиме webhook, и следует сообщить об ошибке."""
        cfg = AppConfig()
        cfg.telegram.bot_token = "test"
        cfg.telegram.admin_chat_ids = [1]
        cfg.telegram.notify_chat_id = 1
        cfg.telegram.mode = "webhook"
        errors = cfg.validate()
        assert any("webhook" in e.lower() for e in errors)

    def test_invalid_poll_interval(self):
        """poll_interval < 1 должен сообщить об ошибке."""
        cfg = AppConfig()
        cfg.telegram.bot_token = "test"
        cfg.telegram.admin_chat_ids = [1]
        cfg.telegram.notify_chat_id = 1
        cfg.schedule.poll_interval_minutes = 0
        errors = cfg.validate()
        assert any("poll_interval" in e.lower() for e in errors)

    def test_invalid_health_check(self):
        """health_check_minutes < 1 должен сообщить об ошибке."""
        cfg = AppConfig()
        cfg.telegram.bot_token = "test"
        cfg.telegram.admin_chat_ids = [1]
        cfg.telegram.notify_chat_id = 1
        cfg.schedule.health_check_minutes = 0
        errors = cfg.validate()
        assert any("health_check" in e.lower() for e in errors)


class TestLoadConfig:
    """Тест загрузки файла конфигурации"""

    def test_load_from_yaml_file(self, sample_config_yaml):
        """Загрузите конфигурацию из файла YAML."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8",
        ) as f:
            f.write(sample_config_yaml)
            config_path = f.name

        try:
            cfg = load_config(config_path)
            assert cfg.telegram.bot_token == "123456:abc_test_token"
            assert cfg.telegram.admin_chat_ids == [111, 222]
            assert cfg.fail2ban.default_bantime == "2h"
            assert cfg.fail2ban.enabled_jails == ["sshd", "nginx-http-auth"]
            assert cfg.schedule.daily_report_time == "09:00"
            assert cfg.notify.enable_ban_alert is True
            assert cfg.notify.dedup_window_seconds == 600
            assert cfg.logging.level == "DEBUG"
            assert cfg.database.path == "/tmp/test.db"
            assert cfg.config_path == config_path
        finally:
            os.unlink(config_path)

    def test_load_nonexistent_file(self):
        """Загрузка несуществующего файла возвращает конфигурацию по умолчанию."""
        cfg = load_config("/nonexistent/path/config.yaml")
        assert isinstance(cfg, AppConfig)
        assert cfg.telegram.bot_token == ""
        assert cfg.fail2ban.default_bantime == "1h"

    def test_load_empty_yaml(self):
        """Пустой файл YAML возвращает конфигурацию по умолчанию."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8",
        ) as f:
            f.write("")
            config_path = f.name

        try:
            cfg = load_config(config_path)
            assert isinstance(cfg, AppConfig)
            assert cfg.telegram.bot_token == ""
        finally:
            os.unlink(config_path)


class TestConfigDataclassTypes:
    """Проверка правильности типа"""

    def test_telegram_config_types(self):
        cfg = TelegramConfig(
            bot_token="tok",
            admin_chat_ids=[1, 2],
            notify_chat_id=3,
        )
        assert isinstance(cfg.admin_chat_ids, list)
        assert isinstance(cfg.notify_chat_id, int)
        assert isinstance(cfg.webhook_port, int)
        assert isinstance(cfg.max_messages_per_minute, int)

    def test_fail2ban_config_types(self):
        cfg = Fail2banConfig(ignoreip=["127.0.0.1"])
        assert isinstance(cfg.ignoreip, list)
        assert isinstance(cfg.enabled_jails, list)
        assert isinstance(cfg.default_maxretry, int)
        assert cfg.default_maxretry == 5

    def test_config_from_dict_preserves_int_types(self, sample_config_yaml):
        """Целочисленный тип должен быть сохранен после анализа YAML."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8",
        ) as f:
            f.write(sample_config_yaml)
            config_path = f.name

        try:
            cfg = load_config(config_path)
            assert isinstance(cfg.telegram.notify_chat_id, int)
            assert isinstance(cfg.telegram.admin_chat_ids[0], int)
            assert isinstance(cfg.fail2ban.default_maxretry, int)
            assert isinstance(cfg.schedule.poll_interval_minutes, int)
            assert isinstance(cfg.notify.dedup_window_seconds, int)
        finally:
            os.unlink(config_path)
