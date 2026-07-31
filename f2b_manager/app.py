"""
f2b_manager.app
===============

Главный класс приложения: собирает модули и управляет жизненным циклом.

Wave 1 (M0) — скелетная реализация; подмодули подключаются постепенно в Wave 2+.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .config import AppConfig
from .storage.database import StateDB
from .storage.models import (
    IFail2banInstaller, IFail2banManager,
    IAlertSender, IMessageSender, IReporter,
)
from .utils.logger import get_logger


class Application:
    """Главный класс приложения f2b-manager.

    Собирает модули и управляет жизненным циклом:
    - загрузка конфигурации
    - инициализация БД состояния
    - запуск Telegram Bot (M2, Wave 2)
    - запуск Scheduler (M4, Wave 3)
    - приём событий уведомлений (M3, Wave 2)

    Жизненный цикл:
        app = Application(config)
        app.setup()     # инициализация модулей
        app.run()       # главный цикл
        app.shutdown()  # освобождение ресурсов
    """

    def __init__(self, config: AppConfig):
        self.config = config
        self.logger = get_logger("app")

        # Ядро (инициализируется сразу в M0)
        self.db: Optional[StateDB] = None

        # Подмодули (подключаются в Wave 2+)
        self._f2b_manager: Optional[IFail2banManager] = None
        self._f2b_installer: Optional[IFail2banInstaller] = None
        self._bot: Optional[IMessageSender] = None
        self._alert_sender: Optional[IAlertSender] = None
        self._reporter: Optional[IReporter] = None
        self._scheduler = None  # экземпляр APScheduler

        self._running = False

    def setup(self) -> None:
        """Инициализировать модули."""
        self.logger.info("Инициализация f2b-manager...")

        # 1. БД состояния
        self.db = StateDB(self.config.database.path)
        self.logger.info("БД состояния подключена: %s", self.config.database.path)

        # 2. Управление Fail2ban (M1, Wave 2)
        try:
            from .fail2ban.manager import Fail2banManager
            from .fail2ban.installer import Fail2banInstaller
            self._f2b_manager = Fail2banManager()
            self._f2b_installer = Fail2banInstaller(self.config)
            self.logger.info("Модуль управления Fail2ban загружен")
        except ImportError:
            self.logger.debug("Модуль управления Fail2ban ещё не реализован (M1)")

        # 3. Telegram Bot (M2, Wave 2)
        try:
            from .telegram_bot.bot import F2BTelegramBot
            self._bot = F2BTelegramBot(
                config=self.config,
                f2b_manager=self._f2b_manager,
                db=self.db,
                installer=self._f2b_installer,
            )
            self.logger.info("Модуль Telegram Bot загружен")
        except ImportError:
            self.logger.debug("Модуль Telegram Bot ещё не реализован (M2)")

        # 4. Оповещения в реальном времени (M3, Wave 2)
        try:
            from .notify.sender import AlertSender
            self._alert_sender = AlertSender(
                config=self.config,
                bot=self._bot,
                db=self.db,
            )
            self.logger.info("Модуль оповещений загружен")
        except ImportError:
            self.logger.debug("Модуль оповещений ещё не реализован (M3)")

        # 5. Планировщик задач (M4, Wave 3)
        try:
            from .monitor.scheduler import F2BScheduler
            self._scheduler = F2BScheduler(
                config=self.config,
                f2b_manager=self._f2b_manager,
                bot=self._bot,
                alert_sender=self._alert_sender,
                db=self.db,
            )
            self.logger.info("Модуль планировщика загружен")
        except ImportError:
            self.logger.debug("Модуль планировщика ещё не реализован (M4)")

        self.logger.info("Инициализация завершена")

    def run(self) -> None:
        """Запустить главный цикл.

        На этапе M4 Scheduler и Bot работают в одном event loop.
        AsyncIOScheduler и Application из python-telegram-bot делят цикл,
        чтобы таймеры и обработка сообщений не конфликтовали.
        """
        self.setup()
        self._running = True

        self.logger.info("Демон f2b-manager запущен")
        self.logger.info("Файл конфигурации: %s", self.config.config_path)

        try:
            if self._bot is not None and hasattr(self._bot, "run"):
                # M4: общий event loop для Scheduler + Bot
                asyncio.run(self._main_loop())
            else:
                # M0: заглушка
                self.logger.info("Инфраструктура M0 готова, ожидаются модули Wave 2")
                self.logger.info("Доступные CLI-команды:")
                self.logger.info("  f2b-manager status            — статус fail2ban")
                self.logger.info("  f2b-manager fail2ban install  — установка fail2ban")
                self.logger.info("  f2b-manager --help            — список команд")
                while self._running:
                    asyncio.sleep(60)
        except KeyboardInterrupt:
            self.logger.info("Получен сигнал прерывания")
        finally:
            self.shutdown()

    async def _main_loop(self) -> None:
        """Корутина главного цикла: Scheduler и Bot в одном event loop.

        Важно:
        - после asyncio.run() сюда попадаем уже с созданным циклом;
        - scheduler.start() вызывается здесь, чтобы делить цикл с Bot;
        - Bot.run() блокирует до сигнала остановки (SIGINT/SIGTERM).
        """
        # Планировщик — до старта Bot, после запуска цикла
        if self._scheduler:
            try:
                self._scheduler.setup_jobs()
                self._scheduler.start()
                self.logger.info("Планировщик запущен в главном event loop")
            except Exception as e:
                self.logger.error("Не удалось запустить планировщик: %s", e)

        # Telegram Bot (блокирует до сигнала остановки)
        if self._bot is not None and hasattr(self._bot, "run"):
            await self._bot.run()

    def shutdown(self) -> None:
        """Освободить ресурсы."""
        self.logger.info("Остановка f2b-manager...")
        self._running = False

        if self._scheduler:
            try:
                self._scheduler.shutdown()
            except Exception as e:
                self.logger.error("Ошибка остановки Scheduler: %s", e)

        if self._bot and hasattr(self._bot, "shutdown"):
            try:
                asyncio.run(self._bot.shutdown())
            except Exception as e:
                self.logger.error("Ошибка остановки Bot: %s", e)

        if self.db:
            self.db.close()
            self.logger.info("БД состояния закрыта")

        self.logger.info("f2b-manager остановлен")
