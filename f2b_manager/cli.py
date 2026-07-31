"""
f2b_manager.cli
===============

Точка входа CLI.

Поддерживаемые подкоманды:
  f2b-manager run                 запуск демона (Bot + Scheduler)
  f2b-manager fail2ban install    установка fail2ban
  f2b-manager fail2ban uninstall  удаление fail2ban
  f2b-manager fail2ban update     обновление fail2ban
  f2b-manager notify              отправка уведомления (вызов из notify.sh)
  f2b-manager status              статус fail2ban
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional

from .config import AppConfig, load_config


class _CliBotSender:
    """Лёгкий отправитель Telegram-сообщений только для CLI-команды notify.

    Вызывает Bot API через telegram.Bot(token=...), без
    ApplicationBuilder / polling / job_queue и лишних накладных расходов.
    Реализует метод send_alert из протокола IMessageSender, нужный для CLI.
    """

    def __init__(self, token: str):
        from telegram import Bot
        from telegram.error import Forbidden, NetworkError, TelegramError
        self._bot = Bot(token=token)
        self._logger = logging.getLogger("cli.bot_sender")
        # Ссылки на классы исключений — удобно для mock в тестах
        self._Forbidden = Forbidden
        self._NetworkError = NetworkError
        self._TelegramError = TelegramError

    async def send_alert(self, chat_id: int, message: str,
                         parse_mode: str = "HTML") -> bool:
        """Отправить предупреждение в указанный chat_id.

        Поведение как у F2BTelegramBot.send_alert(): Forbidden — только warning,
        сетевые/API ошибки — error; всегда возвращает bool.
        """
        try:
            await self._bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode=parse_mode,
                disable_web_page_preview=True,
            )
            return True
        except self._Forbidden:
            self._logger.warning(
                "Пользователь %d заблокировал бота, оповещение не отправлено",
                chat_id,
            )
            return False
        except self._NetworkError as e:
            self._logger.error("Сетевая ошибка при отправке оповещения: %s", e)
            return False
        except self._TelegramError as e:
            self._logger.error("Не удалось отправить оповещение: %s", e)
            return False

    async def send_report(self, chat_id: int, message: str) -> bool:
        """В CLI send_report не нужен — только для соответствия IMessageSender."""
        self._logger.debug("send_report в режиме CLI не поддерживается")
        return False


def build_parser() -> argparse.ArgumentParser:
    """Собрать парсер аргументов командной строки."""
    parser = argparse.ArgumentParser(
        prog="f2b-manager",
        description="Система управления Fail2ban на VPS — Telegram-бот + оповещения",
    )
    parser.add_argument(
        "-c", "--config",
        default=None,
        help="Путь к конфигу (по умолчанию: /etc/f2b-manager/config.yaml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод (DEBUG-логи)",
    )

    subparsers = parser.add_subparsers(dest="command", help="подкоманда")

    # run: запуск демона
    run_parser = subparsers.add_parser("run", help="Запустить демон")
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Только проверить конфиг, не запускать",
    )

    # fail2ban: управление fail2ban
    f2b_parser = subparsers.add_parser("fail2ban", help="Управление fail2ban")
    f2b_sub = f2b_parser.add_subparsers(dest="fail2ban_action")
    f2b_sub.add_parser("install", help="Установить fail2ban")
    uninstall_parser = f2b_sub.add_parser("uninstall", help="Удалить fail2ban")
    uninstall_parser.add_argument(
        "--purge-config",
        action="store_true",
        help="Также удалить файлы конфигурации",
    )
    f2b_sub.add_parser("update", help="Обновить fail2ban")

    # notify: отправка уведомления (вызов из notify.sh)
    notify_parser = subparsers.add_parser("notify", help="Отправить уведомление")
    notify_parser.add_argument(
        "--event", required=True, help="Тип события: ban/unban/start/stop",
    )
    notify_parser.add_argument("--ip", default="", help="IP-адрес")
    notify_parser.add_argument("--jail", default="", help="Имя jail")
    notify_parser.add_argument("--failures", default="0", help="Число неудач")
    notify_parser.add_argument("--matches", default="", help="Совпавшие строки лога")

    # status: статус
    subparsers.add_parser("status", help="Статус fail2ban")

    # menu: интерактивное меню
    subparsers.add_parser("menu", help="Интерактивное меню управления")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Главная точка входа CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Загрузка конфигурации
    config = load_config(args.config)

    # Уровень логирования
    log_level = "DEBUG" if args.verbose else config.logging.level
    from .utils.logger import setup_logging
    setup_logging(
        level=log_level,
        log_file=config.logging.file,
        max_size_mb=config.logging.max_size_mb,
        backup_count=config.logging.backup_count,
    )

    logger = __import__("logging").getLogger("cli")

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "run":
        return _cmd_run(config, args)

    if args.command == "fail2ban":
        return _cmd_fail2ban(config, args)

    if args.command == "notify":
        return _cmd_notify(config, args)

    if args.command == "status":
        return _cmd_status(config, args)

    if args.command == "menu":
        return _cmd_menu(config, args)

    parser.print_help()
    return 0


def _cmd_run(config, args) -> int:
    """Запустить демон."""
    logger = __import__("logging").getLogger("run")

    # Проверка конфигурации
    errors = config.validate()
    if errors:
        for e in errors:
            logger.error("Ошибка конфигурации: %s", e)
        logger.error("Исправьте файл конфигурации и повторите попытку")
        return 1

    logger.info("Проверка конфигурации пройдена")

    if args.dry_run:
        logger.info("Режим --dry-run: запуск не выполняется")
        return 0

    # Запуск приложения
    logger.info("Запуск демона f2b-manager...")
    try:
        from .app import Application
        app = Application(config)
        app.run()
    except ImportError:
        logger.warning("Главный класс приложения ещё не реализован (Wave 2+)")
        logger.info("Инфраструктура M0 готова — продолжайте разработку Wave 2")
        return 0
    except KeyboardInterrupt:
        logger.info("Получен сигнал прерывания, выход")
        return 0

    return 0


def _cmd_fail2ban(config, args) -> int:
    """Управление fail2ban."""
    logger = __import__("logging").getLogger("fail2ban")

    action = args.fail2ban_action
    if not action:
        logger.error("Укажите действие: install / uninstall / update")
        return 1

    try:
        from .fail2ban.installer import Fail2banInstaller
        installer = Fail2banInstaller(config)
    except ImportError:
        logger.warning("Модуль управления Fail2ban ещё не реализован (Wave 2 M1)")
        return 0

    if action == "install":
        result = installer.install()
    elif action == "uninstall":
        result = installer.uninstall(keep_config=not args.purge_config)
    elif action == "update":
        result = installer.update()
    else:
        logger.error("Неизвестное действие: %s", action)
        return 1

    if result.success:
        logger.info("Операция успешна: %s", result.message)
    else:
        logger.error("Операция не удалась: %s", result.message)
        for d in result.details:
            logger.error("  %s", d)

    return 0 if result.success else 1


def _cmd_notify(config, args) -> int:
    """Отправить уведомление (вызывается из notify.sh).

    Action fail2ban передаёт событие через CLI-подкоманду модулю оповещений.
    Здесь автономный CLI-режим (не демон): создаётся AlertSender,
    событие обрабатывается, процесс завершается.
    """
    logger = __import__("logging").getLogger("notify")

    import asyncio

    from .notify.sender import AlertSender
    from .storage.database import StateDB
    from .storage.models import BanAction, BanEvent

    try:
        action = BanAction(args.event)
    except ValueError:
        logger.error("Неизвестный тип события: %s", args.event)
        return 1

    event = BanEvent(
        ip=args.ip,
        jail=args.jail,
        action=action,
        failures=int(args.failures) if args.failures else 0,
        matches=args.matches,
    )

    logger.info(
        "Получено событие: %s ip=%s jail=%s failures=%s",
        action.value, args.ip, args.jail, args.failures,
    )

    # Инициализация БД состояния (для записи событий)
    db = None
    try:
        db = StateDB(db_path=config.database.path)
    except Exception as e:
        logger.warning("Не удалось инициализировать БД состояния: %s — событие не будет записано", e)

    # Отправитель: лёгкий _CliBotSender при наличии bot_token,
    # иначе None (только запись в БД + warning в лог)
    if config.telegram.bot_token:
        bot = _CliBotSender(config.telegram.bot_token)
        logger.info("Отправитель Telegram создан — оповещения пойдут через Bot API")
    else:
        bot = None
        logger.warning(
            "telegram.bot_token не задан: оповещение будет только в БД, "
            "в Telegram не отправится. Укажите bot_token в конфиге для realtime-оповещений."
        )

    sender = AlertSender(config=config, bot=bot, db=db)

    try:
        if action in (BanAction.BAN, BanAction.UNBAN):
            result = asyncio.run(sender.send_ban_alert(event))
        elif action in (BanAction.START, BanAction.STOP):
            result = asyncio.run(
                sender.send_service_alert(action, jail=args.jail)
            )
        else:
            logger.error("Неподдерживаемый тип события: %s", action)
            result = False
    except Exception as e:
        logger.error("Ошибка обработки события уведомления: %s", e, exc_info=True)
        result = False
    finally:
        sender.close()
        if db is not None:
            db.close()

    return 0 if result else 1


def _cmd_status(config, args) -> int:
    """Показать статус fail2ban."""
    logger = __import__("logging").getLogger("status")

    try:
        from .fail2ban.manager import Fail2banManager
        manager = Fail2banManager()
        status = manager.get_status()
        print(f"Версия: {status.version}")
        print(f"Состояние: {status.state.value}")
        print(f"Число jail: {status.jail_count}")
        print(f"Всего блокировок: {status.total_bans}")
    except ImportError:
        logger.warning("Модуль управления Fail2ban ещё не реализован (Wave 2 M1)")
        # Запасной вариант: прямой вызов системной команды
        from .utils.shell import run_command
        result = run_command("fail2ban-client status", timeout=10)
        if result.success:
            print(result.stdout)
        else:
            print(f"fail2ban-client недоступен: {result.stderr}")
            return 1

    return 0


def _cmd_menu(config, args) -> int:
    """Запустить интерактивное меню управления."""
    try:
        from .menu import InteractiveMenu
        menu = InteractiveMenu(
            config_path=config.config_path or "/etc/f2b-manager/config.yaml",
        )
        menu.run()
        return 0
    except ImportError:
        logger = __import__("logging").getLogger("menu")
        logger.error("Не удалось загрузить модуль интерактивного меню")
        return 1
    except KeyboardInterrupt:
        print()
        return 0
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0


if __name__ == "__main__":
    sys.exit(main())
