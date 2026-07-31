"""
f2b_manager.telegram_bot.bot
=============================

Основной класс Telegram Bot.

Реализует протокол IMessageSender (send_alert / send_report),
регистрирует обработчики всех 17 команд и управляет жизненным циклом Bot.

Конструктор принимает config, f2b_manager, db, installer — любой из них
может быть None (mock на этапе разработки).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

from telegram import Update
from telegram.error import Forbidden, NetworkError, TelegramError
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from ..config import AppConfig
from ..storage.database import StateDB
from ..storage.models import (
    AuthLevel,
    IFail2banInstaller,
    IFail2banManager,
    IMessageSender,
)
from ..utils.logger import get_logger
from .auth import AuthManager
from .deps import BotDeps
from .formatters import format_error, format_help, format_welcome
from .handlers.ban import cmd_ban, cmd_unban
from .handlers.config import (
    cmd_setnotify,
    cmd_setschedule,
    cmd_whitelist,
    handle_schedule_callback,
    cmd_f2bconfig,
    handle_f2bconfig_callback,
)
from .handlers.manage import (
    cmd_cancel,
    cmd_install,
    cmd_reload,
    cmd_update,
    get_uninstall_handler,
)
from .handlers.report import cmd_report, cmd_stats
from .handlers.status import cmd_banned, cmd_jail, cmd_jails, cmd_status

if TYPE_CHECKING:
    pass

logger = get_logger("telegram_bot")


class F2BTelegramBot(IMessageSender):
    """Telegram Bot f2b-manager.

    Возможности:
        - регистрация обработчиков всех 17 команд;
        - трёхуровневая авторизация (admin / operator / viewer);
        - /uninstall с повторным подтверждением (ConversationHandler);
        - /install и /update асинхронно с прогрессом;
        - реализация протокола IMessageSender (send_alert / send_report).

    Жизненный цикл:
        bot = F2BTelegramBot(config, f2b_manager, db, installer)
        await bot.run()       # запуск polling/webhook
        await bot.shutdown()  # остановка
    """

    def __init__(
        self,
        config: AppConfig,
        f2b_manager: Optional[IFail2banManager] = None,
        db: Optional[StateDB] = None,
        installer: Optional[IFail2banInstaller] = None,
    ) -> None:
        self.config = config
        self.f2b_manager = f2b_manager
        self.db = db
        self.installer = installer

        # Менеджер авторизации
        self.auth = AuthManager(config.telegram)

        # Общие зависимости
        self.deps = BotDeps(
            config=config,
            f2b_manager=f2b_manager,
            installer=installer,
            db=db,
            auth=self.auth,
        )

        # Application (отложенная сборка: на этапе разработки token может отсутствовать)
        self._application: Optional[Application] = None
        self._initialized = False

        # Сборка Application, если token задан
        token = config.telegram.bot_token
        if token:
            self._application = (
                ApplicationBuilder()
                .token(token)
                .build()
            )
            self._register_handlers()
            self._register_deps()
            logger.info("Telegram Bot Application собран")
        else:
            logger.warning(
                "telegram.bot_token не задан, Bot работает в mock-режиме "
                "(polling недоступен, но send_alert/send_report можно использовать в тестах)"
            )

    # ──────────────────────────────────────────
    # Регистрация обработчиков
    # ──────────────────────────────────────────

    def _register_handlers(self) -> None:
        """Регистрирует обработчики всех команд."""
        app = self._application
        if app is None:
            return

        # ── Базовые команды (все пользователи) ──
        app.add_handler(CommandHandler("start", self._cmd_start))
        app.add_handler(CommandHandler("help", self._cmd_help))
        app.add_handler(CommandHandler("cancel", cmd_cancel))

        # ── Запрос состояния (оператор+) ──
        app.add_handler(CommandHandler("status", cmd_status))
        app.add_handler(CommandHandler("jails", cmd_jails))
        app.add_handler(CommandHandler("banned", cmd_banned))
        app.add_handler(CommandHandler("jail", cmd_jail))

        # ── Управление блокировками (администратор) ──
        app.add_handler(CommandHandler("ban", cmd_ban))
        app.add_handler(CommandHandler("unban", cmd_unban))

        # ── Управление установкой (администратор) ──
        app.add_handler(CommandHandler("install", cmd_install))
        app.add_handler(CommandHandler("update", cmd_update))
        app.add_handler(CommandHandler("reload", cmd_reload))

        # /uninstall — ConversationHandler (повторное подтверждение)
        app.add_handler(get_uninstall_handler())

        # ── Отчёты и статистика (оператор+) ──
        app.add_handler(CommandHandler("report", cmd_report))
        app.add_handler(CommandHandler("stats", cmd_stats))

        # ── Управление конфигурацией ──
        app.add_handler(CommandHandler("whitelist", cmd_whitelist))
        app.add_handler(CommandHandler("setnotify", cmd_setnotify))
        app.add_handler(CommandHandler("setschedule", cmd_setschedule))
        app.add_handler(CommandHandler("f2bconfig", cmd_f2bconfig))

        # Callback-обработчики
        app.add_handler(CallbackQueryHandler(handle_schedule_callback, pattern=r"^sch_"))
        app.add_handler(CallbackQueryHandler(handle_f2bconfig_callback, pattern=r"^f2bcfg_"))

        # ── Глобальная обработка ошибок ──
        app.add_error_handler(self.error_handler)

        logger.info("Зарегистрировано 18 обработчиков команд")

    def _register_deps(self) -> None:
        """Внедряет BotDeps в Application.bot_data."""
        if self._application is not None:
            self._application.bot_data["deps"] = self.deps
            self._application.bot_data["auth"] = self.auth

    # ──────────────────────────────────────────
    # /start и /help (встроенные, без отдельного файла)
    # ──────────────────────────────────────────

    async def _cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """/start — приветствие и отображение chat_id."""
        chat = update.effective_chat
        if chat is None:
            return

        chat_id = chat.id
        level_name = self.auth.level_name(chat_id)

        await update.message.reply_text(
            format_welcome(chat_id, level_name),
            parse_mode="HTML",
        )

    async def _cmd_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """/help — справка по командам."""
        chat = update.effective_chat
        level_name = self.auth.level_name(chat.id) if chat else "Гость"

        await update.message.reply_text(
            format_help(level_name),
            parse_mode="HTML",
        )

    # ──────────────────────────────────────────
    # Реализация протокола IMessageSender
    # ──────────────────────────────────────────

    async def send_alert(
        self,
        chat_id: int,
        message: str,
        parse_mode: str = "HTML",
        message_thread_id: Optional[int] = None,
    ) -> bool:
        """Отправляет оповещение (вызывается модулем notify).

        Реализация IMessageSender.send_alert.
        Для notify_chat_id автоматически подставляет notify_message_thread_id.
        """
        if self._application is None:
            logger.warning("Bot не собран (нет token), оповещение отправить нельзя")
            return False

        thread_id = self._resolve_thread_id(chat_id, message_thread_id)

        try:
            bot = self._application.bot
            kwargs: dict = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            }
            if thread_id:
                kwargs["message_thread_id"] = thread_id
            await bot.send_message(**kwargs)
            return True
        except Forbidden:
            logger.warning("Пользователь %s заблокировал Bot, оповещение не отправлено", chat_id)
            return False
        except NetworkError as e:
            logger.error("Сетевая ошибка при отправке оповещения: %s", e)
            return False
        except TelegramError as e:
            logger.error("Не удалось отправить оповещение: %s", e)
            return False

    async def send_report(
        self,
        chat_id: int,
        message: str,
        message_thread_id: Optional[int] = None,
    ) -> bool:
        """Отправляет отчёт (вызывается модулем scheduler).

        Реализация IMessageSender.send_report.
        Для notify_chat_id автоматически подставляет notify_message_thread_id.
        """
        if self._application is None:
            logger.warning("Bot не собран (нет token), отчёт отправить нельзя")
            return False

        thread_id = self._resolve_thread_id(chat_id, message_thread_id)

        try:
            bot = self._application.bot
            kwargs: dict = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
            if thread_id:
                kwargs["message_thread_id"] = thread_id
            await bot.send_message(**kwargs)
            return True
        except Forbidden:
            logger.warning("Пользователь %s заблокировал Bot, отчёт не отправлен", chat_id)
            return False
        except NetworkError as e:
            logger.error("Сетевая ошибка при отправке отчёта: %s", e)
            return False
        except TelegramError as e:
            logger.error("Не удалось отправить отчёт: %s", e)
            return False

    def _resolve_thread_id(
        self,
        chat_id: int,
        message_thread_id: Optional[int],
    ) -> Optional[int]:
        """Выбрать message_thread_id: явный аргумент или из конфига для notify."""
        if message_thread_id:
            return message_thread_id
        if chat_id == self.config.telegram.notify_chat_id:
            tid = self.config.telegram.notify_message_thread_id
            return tid if tid else None
        return None

    # ──────────────────────────────────────────
    # Жизненный цикл
    # ──────────────────────────────────────────

    async def run(self) -> None:
        """Запускает Bot (polling или webhook).

        Способ запуска выбирается по config.telegram.mode:
        - polling: длинный опрос (удобно для VPS без публичного входа);
        - webhook: режим webhook (удобно при наличии домена и reverse proxy).
        """
        if self._application is None:
            logger.error(
                "Bot не собран (нет bot_token), запуск невозможен. "
                "Укажите telegram.bot_token в конфигурации."
            )
            return

        app = self._application
        mode = self.config.telegram.mode

        logger.info("Запуск Telegram Bot (режим: %s)...", mode)

        # Инициализация
        await app.initialize()
        self._initialized = True
        logger.info("Bot инициализирован")

        # Сведения о Bot
        me = await app.bot.get_me()
        logger.info("Bot подключён: @%s (%s)", me.username, me.first_name)

        # Меню команд (список по кнопке / слева от поля ввода)
        from telegram import BotCommand
        commands = [
            BotCommand("status", "Состояние работы"),
            BotCommand("jails", "Список jail"),
            BotCommand("banned", "Заблокированные IP"),
            BotCommand("jail", "Детали выбранного jail"),
            BotCommand("ban", "Заблокировать IP вручную"),
            BotCommand("unban", "Разблокировать IP"),
            BotCommand("report", "Сформировать отчёт"),
            BotCommand("stats", "Статистика"),
            BotCommand("whitelist", "Белый список"),
            BotCommand("setnotify", "Вкл./выкл. уведомления"),
            BotCommand("setschedule", "Расписание отчётов"),
            BotCommand("f2bconfig", "Параметры Fail2ban"),
            BotCommand("install", "Установить Fail2ban"),
            BotCommand("uninstall", "Удалить Fail2ban"),
            BotCommand("update", "Обновить Fail2ban"),
            BotCommand("reload", "Перезагрузить конфигурацию"),
            BotCommand("help", "Справка"),
        ]
        await app.bot.set_my_commands(commands)
        logger.info("Зарегистрировано пунктов меню команд: %s", len(commands))

        # Уведомить администраторов о запуске
        await self._notify_admins_online()

        try:
            await app.start()

            if mode == "webhook":
                await self._start_webhook(app)
            else:
                await self._start_polling(app)

            logger.info("Bot запущен, ожидание сообщений...")

            # Держим процесс до сигнала остановки
            stop_event = asyncio.Event()
            # Регистрация сигналов в цикле asyncio
            try:
                import signal

                loop = asyncio.get_running_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(sig, stop_event.set)
            except (NotImplementedError, RuntimeError):
                # Windows не поддерживает add_signal_handler
                pass

            await stop_event.wait()

        except KeyboardInterrupt:
            logger.info("Получен сигнал прерывания, остановка...")
        finally:
            await self.shutdown()

    async def _start_polling(self, app: Application) -> None:
        """Запускает режим polling."""
        await app.updater.start_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
        logger.info("Polling запущен")

    async def _start_webhook(self, app: Application) -> None:
        """Запускает режим webhook."""
        tg = self.config.telegram
        await app.updater.start_webhook(
            listen="0.0.0.0",
            port=tg.webhook_port,
            url_path=tg.bot_token.split(":")[0] if tg.bot_token else "",
            webhook_url=tg.webhook_url,
            allowed_updates=Update.ALL_TYPES,
        )
        logger.info("Webhook запущен (port=%s)", tg.webhook_port)

    async def _notify_admins_online(self) -> None:
        """Уведомляет администраторов, что Bot онлайн."""
        if not self.config.telegram.admin_chat_ids:
            return

        message = (
            "\U0001f7e2 <b>f2b-manager Bot онлайн</b>\n\n"
            "Bot успешно запущен и готов к работе.\n"
            "Введите /help, чтобы увидеть доступные команды."
        )

        for admin_id in self.config.telegram.admin_chat_ids:
            try:
                await self.send_alert(admin_id, message)
            except Exception as e:
                logger.debug("Не удалось уведомить администратора %s: %s", admin_id, e)

    async def shutdown(self) -> None:
        """Останавливает Bot и освобождает ресурсы."""
        if self._application is None:
            return

        app = self._application

        logger.info("Остановка Telegram Bot...")

        try:
            if app.updater and app.updater.running:
                await app.updater.stop()
                logger.info("Updater остановлен")

            if app.running:
                await app.stop()
                logger.info("Application остановлен")

            if self._initialized:
                await app.shutdown()
                logger.info("Application закрыт")
        except Exception as e:
            logger.error("Ошибка при остановке Bot: %s", e)

        self._initialized = False
        logger.info("Telegram Bot остановлен")

    # ──────────────────────────────────────────
    # Глобальная обработка ошибок
    # ──────────────────────────────────────────

    async def error_handler(
        self, update: object, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Глобальный обработчик ошибок."""
        error = context.error
        if error is None:
            return

        logger.error(
            "Ошибка при обработке обновления: %s",
            error,
            exc_info=context.error,
        )

        # Попытаться уведомить пользователя
        if isinstance(update, Update) and update.effective_chat:
            try:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=format_error(
                        "При обработке команды произошла внутренняя ошибка. "
                        "Повторите попытку позже.\n"
                        "Если проблема сохраняется — попросите администратора проверить журнал."
                    ),
                    parse_mode="HTML",
                )
            except Exception:
                pass  # не допускаем ошибку в самом обработчике ошибок

    # ──────────────────────────────────────────
    # Вспомогательные свойства для разработки/тестов
    # ──────────────────────────────────────────

    @property
    def application(self) -> Optional[Application]:
        """Отдаёт Application для внешних тестов."""
        return self._application

    @property
    def is_ready(self) -> bool:
        """Готов ли Bot (есть token и Application собран)."""
        return self._application is not None
