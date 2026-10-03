"""
tests/test_config_builder.py
=============================
Скрипты jail.local/action/notify генерируют тесты.

Покрытие: поколение сегмента DEFAULT / поколение сегмента jail / telegram-notify action /
       Скрипт notify/инкрементный бан/белый список/по умолчанию jail/пользовательский jail.
"""
from __future__ import annotations

import pytest

from f2b_manager.config import Fail2banConfig
from f2b_manager.fail2ban.config_builder import JailConfigBuilder


@pytest.fixture
def builder():
    """Стандартный тест использует builder (включить инкрементный бан, 2 jail)."""
    config = Fail2banConfig(
        default_bantime="1h",
        default_findtime="10m",
        default_maxretry=5,
        incremental=True,
        max_bantime="1w",
        ignoreip=["127.0.0.1/8", "::1"],
        enabled_jails=["sshd", "recidive"],
    )
    return JailConfigBuilder(config)


@pytest.fixture
def builder_no_incremental():
    """Отключите дополнительный бан builder."""
    config = Fail2banConfig(
        default_bantime="30m",
        default_findtime="5m",
        default_maxretry=3,
        incremental=False,
        max_bantime="1w",
        ignoreip=["127.0.0.1/8"],
        enabled_jails=["sshd"],
    )
    return JailConfigBuilder(config)


class TestDefaultSection:
    """Тест сегмента [DEFAULT]"""

    def test_contains_config_values(self, builder):
        """Раздел DEFAULT содержит все значения конфигурации."""
        output = builder.generate_jail_local()
        assert "[DEFAULT]" in output
        assert "bantime = 1h" in output
        assert "findtime = 10m" in output
        assert "maxretry = 5" in output

    def test_contains_ignoreip(self, builder):
        """Сегмент DEFAULT содержит белый список ignoreip."""
        output = builder.generate_jail_local()
        assert "ignoreip = 127.0.0.1/8 ::1" in output

    def test_no_recursive_banaction_or_action(self, builder):
        """В DEFAULT нельзя писать banaction/action = %(banaction/action_)s — recursion."""
        output = builder.generate_jail_local()
        default = output.split("[sshd]")[0]
        assert "banaction = %(banaction)s" not in default
        assert "action = %(action_)s" not in default

    def test_incremental_bantime_config(self, builder):
        """Настройте, когда включен дополнительный бан."""
        output = builder.generate_jail_local()
        assert "bantime.increment = true" in output
        assert "bantime.rndtime = 10m" in output
        assert "bantime.factor = 2" in output
        assert "bantime.maxtime = 1w" in output
        assert "Нарастающий бан" in output

    def test_no_incremental_config(self, builder_no_incremental):
        """При отключении добавочного запрета соответствующая конфигурация не включается."""
        output = builder_no_incremental.generate_jail_local()
        assert "bantime.increment" not in output
        assert "bantime.rndtime" not in output


class TestJailSection:
    """Тест сегмента Jail"""

    def test_sshd_jail_present(self, builder):
        """sshd jail должен появиться."""
        output = builder.generate_jail_local()
        assert "[sshd]" in output
        assert "enabled = true" in output
        assert "port    = ssh" in output

    def test_sshd_uses_systemd_without_auth_log(self, builder, monkeypatch):
        """Без auth.log/secure — backend=systemd (Ubuntu journald-only)."""
        monkeypatch.setattr(
            "f2b_manager.fail2ban.config_builder._sshd_uses_systemd_journal",
            lambda: True,
        )
        output = builder.generate_jail_local()
        sshd = output.split("[sshd]", 1)[1].split("[", 1)[0]
        assert "backend = systemd" in sshd
        assert "logpath" not in sshd

    def test_sshd_uses_logpath_when_auth_log_exists(self, builder, monkeypatch):
        """При наличии auth.log — классический logpath/backend."""
        monkeypatch.setattr(
            "f2b_manager.fail2ban.config_builder._sshd_uses_systemd_journal",
            lambda: False,
        )
        output = builder.generate_jail_local()
        sshd = output.split("[sshd]", 1)[1].split("[", 1)[0]
        assert "logpath = %(sshd_log)s" in sshd
        assert "backend = %(sshd_backend)s" in sshd

    def test_recidive_jail_present(self, builder):
        """recidive jail должен появиться."""
        output = builder.generate_jail_local()
        assert "[recidive]" in output
        assert "bantime  = 1w" in output
        assert "maxretry = 5" in output


class TestTelegramAction:
    """Telegram action Дополнительное тестирование"""

    def test_action_appended_to_jails(self, builder):
        """К каждому jail следует добавить telegram-notify action."""
        output = builder.generate_jail_local()
        # Отметьте sshd, а затем telegram-notify.
        assert "telegram-notify" in output
        # Встречается как минимум 2 раза (строки action в DEFAULT не учитываются, см. jail section)
        count = output.count("telegram-notify")
        assert count >= 2  # sshd + recidive

    def test_action_format(self, builder):
        """Строка action имеет правильный формат."""
        output = builder.generate_jail_local()
        assert "action = %(action_)s" in output
        assert "telegram-notify[name=%(__name__)s]" in output


class TestCustomJail:
    """Нестандартный тест jail"""

    def test_generic_jail_generated(self):
        """Не по умолчанию jail генерирует конфигурацию по умолчанию."""
        config = Fail2banConfig(
            enabled_jails=["custom-service"],
        )
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()

        assert "[custom-service]" in output
        assert "enabled = true" in output
        assert "filter  = custom-service" in output
        assert "logpath = /var/log/custom-service.log" in output
        assert "telegram-notify" in output


class TestMultipleJails:
    """Множественное тестирование конфигурации jail"""

    def test_enabled_jails_order(self, builder):
        """Последовательность jail должна соответствовать конфигурации."""
        output = builder.generate_jail_local()
        sshd_idx = output.index("[sshd]")
        recidive_idx = output.index("[recidive]")
        assert sshd_idx < recidive_idx

    def test_only_enabled_jails_included(self):
        """Включен только jail в enabled_jails."""
        config = Fail2banConfig(
            enabled_jails=["proftpd"],
        )
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()

        assert "[proftpd]" in output
        assert "[sshd]" not in output  # Не включено
        assert "[recidive]" not in output  # Не включено

    def test_all_preset_jails(self):
        """Все пресеты jail могут быть сгенерированы."""
        config = Fail2banConfig(
            enabled_jails=[
                "sshd", "nginx-http-auth", "nginx-botsearch",
                "dovecot", "postfix", "proftpd",
            ],
        )
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()

        assert "[sshd]" in output
        assert "[nginx-http-auth]" in output
        assert "[nginx-botsearch]" in output
        assert "[dovecot]" in output
        assert "[postfix]" in output
        assert "[proftpd]" in output

    def test_empty_jails(self):
        """Пустой список jail не содержит сегментов jail."""
        config = Fail2banConfig(enabled_jails=[])
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()

        assert "[DEFAULT]" in output
        # Других jail section быть не должно.
        # Статистика [Количество
        assert output.count("[") == 1  # Только [DEFAULT]


class TestActionConfig:
    """Тест файла конфигурации Action"""

    def test_generate_telegram_action(self, builder):
        """Создайте telegram-notify.conf."""
        action = builder.generate_telegram_action()
        assert "[Definition]" in action
        assert "actionstart" in action
        assert "actionstop" in action
        assert "actionban" in action
        assert "actionunban" in action
        assert "f2b-notify.sh" in action
        assert 'ban"' in action or "\"ban\"" in action
        assert "unban" in action

    def test_action_config_has_init_section(self, builder):
        """Конфигурация action содержит раздел [Init]."""
        action = builder.generate_telegram_action()
        assert "[Init]" in action
        assert "name = default" in action


class TestNotifyScript:
    """Тест скрипта уведомлений"""

    def test_generate_notify_script(self, builder):
        """Создайте f2b-notify.sh."""
        script = builder.generate_notify_script()
        assert "#!/bin/bash" in script
        assert "f2b-manager notify" in script
        assert "case" in script
        assert "ban" in script
        assert "unban" in script
        assert "start" in script
        assert "stop" in script
        assert "exit 0" in script  # всегда возвращает 0

    def test_notify_script_has_ban_block(self, builder):
        """Скрипт содержит обработку событий ban."""
        script = builder.generate_notify_script()
        assert "--event" in script
        assert "--ip" in script
        assert "--jail" in script
        assert "--failures" in script
        assert "--matches" in script


class TestConfigParams:
    """Комбинированное тестирование различных параметров"""

    def test_different_bantime(self):
        config = Fail2banConfig(default_bantime="24h", enabled_jails=["sshd"])
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()
        assert "bantime = 24h" in output

    def test_different_findtime(self):
        config = Fail2banConfig(default_findtime="30m", enabled_jails=["sshd"])
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()
        assert "findtime = 30m" in output

    def test_different_maxretry(self):
        config = Fail2banConfig(default_maxretry=10, enabled_jails=["sshd"])
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()
        assert "maxretry = 10" in output

    def test_multiple_ignoreip(self):
        config = Fail2banConfig(
            ignoreip=["127.0.0.1/8", "10.0.0.0/8", "192.168.0.0/16"],
            enabled_jails=["sshd"],
        )
        builder = JailConfigBuilder(config)
        output = builder.generate_jail_local()
        assert "127.0.0.1/8" in output
        assert "10.0.0.0/8" in output
        assert "192.168.0.0/16" in output
