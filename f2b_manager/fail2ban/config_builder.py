"""
f2b_manager.fail2ban.config_builder
====================================

Генерация конфигурации fail2ban jail.local.

По Fail2banConfig собирает jail.local по спецификации fail2ban;
в action каждого jail добавляется telegram-notify.
"""

from __future__ import annotations

import textwrap
from typing import Optional

from ..config import Fail2banConfig
from ..utils.logger import get_logger

_logger = get_logger(__name__)

# Предустановки jail (базовая конфигурация часто используемых jail)
_PRESET_JAILS: dict[str, str] = {
    "sshd": textwrap.dedent("""\
        [sshd]
        enabled = true
        port    = ssh
        logpath = %(sshd_log)s
        backend = %(sshd_backend)s
    """),
    "nginx-http-auth": textwrap.dedent("""\
        [nginx-http-auth]
        enabled  = true
        port     = http,https
        logpath  = %(nginx_error_log)s
    """),
    "nginx-botsearch": textwrap.dedent("""\
        [nginx-botsearch]
        enabled  = true
        port     = http,https
        logpath  = %(nginx_error_log)s
    """),
    "nginx-noscript": textwrap.dedent("""\
        [nginx-noscript]
        enabled  = true
        port     = http,https
        logpath  = %(nginx_error_log)s
    """),
    "recidive": textwrap.dedent("""\
        [recidive]
        enabled  = true
        logpath  = /var/log/fail2ban.log
        bantime  = 1w
        findtime = 1d
        maxretry = 5
    """),
    "proftpd": textwrap.dedent("""\
        [proftpd]
        enabled  = true
        port     = ftp,ftp-data,ftps,ftps-data
        logpath  = %(proftpd_log)s
        backend  = %(proftpd_backend)s
    """),
    "dovecot": textwrap.dedent("""\
        [dovecot]
        enabled  = true
        port     = pop3,pop3s,imap,imaps,submission,465,sieve
        logpath  = %(dovecot_log)s
        backend  = %(dovecot_backend)s
    """),
    "postfix": textwrap.dedent("""\
        [postfix]
        enabled  = true
        mode     = more
        port     = smtp,465,submission
        logpath  = %(postfix_log)s
        backend  = %(postfix_backend)s
    """),
}


class JailConfigBuilder:
    """Генератор конфигурации fail2ban.

    По Fail2banConfig и шаблонам собирает полный jail.local.
    Особенности:
    - секция DEFAULT — глобальные параметры;
    - в action каждого jail автоматически добавляется telegram-notify;
    - поддержка нарастающего бана (incremental banning);
    - белый список IP в ignoreip.
    """

    def __init__(self, config: Fail2banConfig):
        self._config = config

    def generate_jail_local(self) -> str:
        """Собрать полное содержимое jail.local.

        Включает [DEFAULT] и все включённые jail.

        Returns:
            Текст файла jail.local.
        """
        sections: list[str] = []

        sections.append(self._build_default_section())

        for jail_name in self._config.enabled_jails:
            jail_section = self._build_jail_section(jail_name)
            if jail_section:
                sections.append(jail_section)
            else:
                _logger.warning(
                    "Предустановка jail «%s» не найдена — будет использована конфигурация по умолчанию",
                    jail_name,
                )
                sections.append(self._build_generic_jail(jail_name))

        result = "\n\n".join(sections) + "\n"
        _logger.debug("Generated jail.local with %d sections", len(sections))
        return result

    def _build_default_section(self) -> str:
        """Собрать секцию [DEFAULT]."""
        cfg = self._config
        lines: list[str] = ["[DEFAULT]"]

        lines.append(f"bantime = {cfg.default_bantime}")
        lines.append(f"findtime = {cfg.default_findtime}")
        lines.append(f"maxretry = {cfg.default_maxretry}")

        ignoreip = " ".join(cfg.ignoreip)
        lines.append(f"ignoreip = {ignoreip}")

        lines.append("banaction = %(banaction)s")
        # Базовый action; telegram-notify добавляется в секциях jail
        lines.append("action = %(action_)s")

        if cfg.incremental:
            lines.append("")
            lines.append("# Нарастающий бан: длительность удваивается при каждом нарушении")
            lines.append("bantime.increment = true")
            lines.append("bantime.rndtime = 10m")
            lines.append("bantime.factor = 2")
            lines.append(f"bantime.maxtime = {cfg.max_bantime}")

        return "\n".join(lines)

    def _build_jail_section(self, jail_name: str) -> Optional[str]:
        """Собрать секцию jail по предустановке."""
        preset = _PRESET_JAILS.get(jail_name)
        if preset is None:
            return None

        action_line = (
            "action = %(action_)s\n"
            "         telegram-notify"
        )
        return preset.rstrip() + "\n" + action_line

    def _build_generic_jail(self, jail_name: str) -> str:
        """Конфигурация по умолчанию для jail без предустановки."""
        return textwrap.dedent(f"""\
            [{jail_name}]
            enabled = true
            filter  = {jail_name}
            logpath = /var/log/{jail_name}.log
            action  = %(action_)s
                      telegram-notify
        """)

    def generate_telegram_action(self) -> str:
        """Сгенерировать /etc/fail2ban/action.d/telegram-notify.conf.

        Returns:
            Текст telegram-notify.conf.
        """
        return textwrap.dedent("""\
            # Fail2ban Telegram — action уведомлений
            # При ban/unban вызывается скрипт уведомления
            #
            # Автогенерация: f2b-manager config_builder
            # Путь: /etc/fail2ban/action.d/telegram-notify.conf

            [Definition]

            # Уведомление при старте службы
            actionstart = /usr/local/bin/f2b-notify.sh "start" "<name>"

            # Уведомление при остановке службы
            actionstop = /usr/local/bin/f2b-notify.sh "stop" "<name>"

            # Команда проверки (пусто)
            actioncheck =

            # Уведомление при блокировке IP
            actionban = /usr/local/bin/f2b-notify.sh "ban" "<ip>" "<name>" "<failures>" "<matches>"

            # Уведомление при разблокировке IP
            actionunban = /usr/local/bin/f2b-notify.sh "unban" "<ip>" "<name>"

            # Зависимости action
            actionstart_on_demand = false

            [Init]

            # Имя (в Definition зашито явно; здесь только объявление)
            name = default
        """)

    def generate_notify_script(self) -> str:
        """Сгенерировать мост /usr/local/bin/f2b-notify.sh.

        Returns:
            Текст notify.sh.
        """
        return textwrap.dedent("""\
            #!/bin/bash
            # Fail2ban -> f2b-manager: мост уведомлений
            # Вызывается fail2ban action, событие передаётся в f2b-manager
            #
            # Автогенерация: f2b-manager config_builder
            # Путь: /usr/local/bin/f2b-notify.sh

            # Аргументы: $1=тип события $2=IP/jail $3=jail $4=failures $5=matches
            EVENT="${1:-unknown}"

            case "$EVENT" in
                ban)
                    # Пересылка события бана
                    f2b-manager notify \\
                        --event "ban" \\
                        --ip "${2:-}" \\
                        --jail "${3:-}" \\
                        --failures "${4:-0}" \\
                        --matches "${5:-}" \\
                        >/dev/null 2>&1 &
                    ;;
                unban)
                    # Пересылка события разбана
                    f2b-manager notify \\
                        --event "unban" \\
                        --ip "${2:-}" \\
                        --jail "${3:-}" \\
                        >/dev/null 2>&1 &
                    ;;
                start|stop)
                    # Уведомление о старте/остановке службы
                    f2b-manager notify \\
                        --event "$EVENT" \\
                        --jail "${2:-}" \\
                        >/dev/null 2>&1 &
                    ;;
                *)
                    ;;
            esac

            exit 0  # всегда 0 — не мешать работе fail2ban
        """)


# ──────────────────────────────────────────────
# Самопроверка
# ──────────────────────────────────────────────

if __name__ == "__main__":
    from ..config import Fail2banConfig

    config = Fail2banConfig(
        default_bantime="1h",
        default_findtime="10m",
        default_maxretry=5,
        incremental=True,
        max_bantime="1w",
        ignoreip=["127.0.0.1/8", "::1"],
        enabled_jails=["sshd", "recidive"],
    )

    builder = JailConfigBuilder(config)

    print("=== Сгенерированный jail.local ===")
    print(builder.generate_jail_local())

    print("\n=== Сгенерированный telegram-notify.conf ===")
    print(builder.generate_telegram_action())

    print("\n=== Сгенерированный f2b-notify.sh ===")
    print(builder.generate_notify_script())
