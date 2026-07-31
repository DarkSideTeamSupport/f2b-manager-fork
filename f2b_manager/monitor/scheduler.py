"""
f2b_manager.monitor.scheduler
==============================

Планировщик задач по расписанию.

На базе APScheduler AsyncIOScheduler управляет 4 задачами:
1. Ежедневный отчёт (cron)          — формирует и отправляет ежедневный отчёт о банах в заданное время
2. Еженедельный отчёт (cron)        — формирует и отправляет еженедельный статистический отчёт в заданное время
3. Опрос-страховка (interval)      — сравнивает изменения банов и досылает пропущенные уведомления
4. Health-check (interval)           — проверяет состояние fail2ban и автоматически восстанавливает при сбоях

Ключевая идея:
    AsyncIOScheduler должен использовать тот же цикл событий, что и Application
    из python-telegram-bot. Метод start() нужно вызывать после запуска цикла
    событий (то есть внутри asyncio-цикла, который создаёт Bot.run()).

Подключение (в app.py):
    async def _main_loop(self):
        self._scheduler.setup_jobs()
        self._scheduler.start()       # ← к этому моменту цикл событий уже работает
        await self._bot.run()

    def run(self):
        asyncio.run(self._main_loop())
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from ..config import AppConfig
from ..storage.database import StateDB
from ..storage.models import (
    BanAction,
    BanEvent,
    IAlertSender,
    IFail2banManager,
    IMessageSender,
)
from ..utils.logger import get_logger
from .health import HealthChecker
from .reporter import BanReporter

logger = get_logger("monitor.scheduler")

# Сопоставление дней недели: значение конфигурации → сокращение day_of_week в APScheduler cron
_WEEKDAY_MAP: dict[str, str] = {
    "monday": "mon", "tuesday": "tue", "wednesday": "wed",
    "thursday": "thu", "friday": "fri", "saturday": "sat",
    "sunday": "sun",
    "mon": "mon", "tue": "tue", "wed": "wed",
    "thu": "thu", "fri": "fri", "sat": "sat", "sun": "sun",
}


class F2BScheduler:
    """Планировщик задач на базе APScheduler AsyncIOScheduler.

    Управляет 4 задачами; расписание всех задач читается из AppConfig.schedule
    и может динамически меняться через переопределения конфигурации (StateDB config_overrides).

    Конструктор принимает:
        config:        глобальная конфигурация приложения
        f2b_manager:   интерфейс управления Fail2ban (может быть None — опрос пропускается)
        bot:           интерфейс отправки сообщений (может быть None — только логирование)
        alert_sender:  интерфейс отправки алертов (может быть None — досылка уведомлений пропускается)
        db:            интерфейс хранилища состояния (статистика и сравнение снимков)

    Жизненный цикл:
        scheduler = F2BScheduler(config, f2b, bot, alert, db)
        scheduler.setup_jobs()   # регистрация задач (после создания цикла событий)
        scheduler.start()        # запуск планировщика (после старта цикла событий)
        scheduler.shutdown()     # корректное завершение
    """

    def __init__(
        self,
        config: AppConfig,
        f2b_manager: Optional[IFail2banManager] = None,
        bot: Optional[IMessageSender] = None,
        alert_sender: Optional[IAlertSender] = None,
        db: Optional[StateDB] = None,
    ):
        self._config = config
        self._f2b = f2b_manager
        self._bot = bot
        self._alert_sender = alert_sender
        self._db = db

        # Подкомпоненты (создаются только при наличии зависимостей)
        if f2b_manager is not None and db is not None:
            self._reporter: Optional[BanReporter] = BanReporter(
                config, f2b_manager, db
            )
        else:
            self._reporter = None

        self._health_checker = HealthChecker(config, bot)

        # Экземпляр APScheduler — создаётся в setup_jobs() для использования правильного цикла событий
        self._scheduler: Optional[AsyncIOScheduler] = None
        self._started = False

    # ── Публичные методы ──────────────────────────────

    def setup_jobs(self) -> None:
        """Регистрация всех задач по расписанию.

        Вызывается после создания цикла событий, но до start().
        Создаёт экземпляр AsyncIOScheduler и регистрирует 4 задачи.
        Все параметры времени читаются из self._config.schedule.
        """
        self._scheduler = AsyncIOScheduler()
        sc = self._config.schedule

        # ── Задача 1: ежедневный отчёт о банах (cron) ──
        if sc.daily_report_enabled:
            hour, minute = self._parse_time(sc.daily_report_time)
            self._scheduler.add_job(
                self._daily_report_job,
                trigger="cron",
                hour=hour,
                minute=minute,
                id="daily_report",
                name="Ежедневный отчёт о банах",
                replace_existing=True,
            )
            logger.info(
                "Зарегистрирована задача ежедневного отчёта: %02d:%02d",
                hour, minute,
            )
        else:
            logger.info("Ежедневный отчёт отключён")

        # ── Задача 2: еженедельный статистический отчёт (cron) ──
        if sc.weekly_report_enabled:
            weekday = _WEEKDAY_MAP.get(
                sc.weekly_report_day.lower(), "mon"
            )
            hour, minute = self._parse_time(sc.weekly_report_time)
            self._scheduler.add_job(
                self._weekly_report_job,
                trigger="cron",
                day_of_week=weekday,
                hour=hour,
                minute=minute,
                id="weekly_report",
                name="Еженедельная статистика банов",
                replace_existing=True,
            )
            logger.info(
                "Зарегистрирована задача еженедельного отчёта: %s %02d:%02d",
                sc.weekly_report_day, hour, minute,
            )
        else:
            logger.info("Еженедельный отчёт отключён")

        # ── Задача 3: опрос-страховка (interval) ──
        self._scheduler.add_job(
            self._poll_ban_changes_job,
            trigger="interval",
            minutes=sc.poll_interval_minutes,
            id="poll_changes",
            name="Опрос изменений банов (страховка)",
            replace_existing=True,
        )
        logger.info(
            "Зарегистрирована задача опроса-страховки: каждые %d мин",
            sc.poll_interval_minutes,
        )

        # ── Задача 4: health-check (interval) ──
        self._scheduler.add_job(
            self._health_check_job,
            trigger="interval",
            minutes=sc.health_check_minutes,
            id="health_check",
            name="Health-check Fail2ban",
            replace_existing=True,
        )
        logger.info(
            "Зарегистрирована задача health-check: каждые %d мин",
            sc.health_check_minutes,
        )

    def start(self) -> None:
        """Запуск планировщика.

        **Важно**: вызывать после запуска asyncio-цикла событий python-telegram-bot,
        чтобы APScheduler использовал тот же цикл событий, что и Bot.

        Типичный порядок вызова (в корутине _main_loop в app.py):
            self._scheduler.setup_jobs()
            self._scheduler.start()
            await self._bot.run()
        """
        if self._scheduler is None:
            logger.error("Планировщик не инициализирован, сначала вызовите setup_jobs()")
            return

        try:
            self._scheduler.start()
            self._started = True
            logger.info("APScheduler запущен, все задачи активированы")
        except Exception as e:
            logger.error("Не удалось запустить планировщик: %s", e)
            raise

    def shutdown(self, wait: bool = True) -> None:
        """Корректное завершение работы планировщика.

        Перед закрытием дождаться завершения текущих задач (wait=True)
        или остановить немедленно (wait=False).

        Args:
            wait: ждать ли завершения текущих задач.
        """
        if not self._started or self._scheduler is None:
            return

        logger.info("Завершение работы планировщика...")
        try:
            self._scheduler.shutdown(wait=wait)
            self._started = False
            logger.info("Планировщик остановлен")
        except Exception as e:
            logger.error("Не удалось остановить планировщик: %s", e)

    # ── Задача 1: ежедневный отчёт ────────────────────────

    async def _daily_report_job(self) -> None:
        """Формирует ежедневный отчёт и отправляет его через Bot в notify_chat_id."""
        logger.info("Выполнение задачи ежедневного отчёта...")

        if self._reporter is None:
            logger.warning("Reporter не инициализирован, пропуск ежедневного отчёта")
            return

        try:
            report = self._reporter.daily_report()
            await self._send_report(report)
        except Exception as e:
            logger.error("Ошибка задачи ежедневного отчёта: %s", e, exc_info=True)

    # ── Задача 2: еженедельный отчёт ────────────────────────

    async def _weekly_report_job(self) -> None:
        """Формирует еженедельный отчёт и отправляет его через Bot в notify_chat_id."""
        logger.info("Выполнение задачи еженедельного отчёта...")

        if self._reporter is None:
            logger.warning("Reporter не инициализирован, пропуск еженедельного отчёта")
            return

        try:
            report = self._reporter.weekly_report()
            await self._send_report(report)
        except Exception as e:
            logger.error("Ошибка задачи еженедельного отчёта: %s", e, exc_info=True)

    # ── Задача 3: опрос-страховка ────────────────────────

    async def _poll_ban_changes_job(self) -> None:
        """Опрос для обнаружения изменений банов и досылки уведомлений, пропущенных Hook.

        Алгоритм diff:
        1. Обойти все jail и через get_jail_status() получить списки заблокированных IP
        2. Построить current_bans: set[(ip, jail)]
        3. Прочитать из StateDB последний снимок saved_bans: set[(ip, jail)]
        4. Вычислить diff:
           - added   = current_bans - saved_bans     (новые баны)
           - removed = saved_bans - current_bans     (разблокировки)
        5. Для каждого added IP → создать BanEvent → вызвать alert_sender.send_ban_alert()
        6. Для каждого removed IP → создать BanEvent(UNBAN) → вызвать alert_sender.send_ban_alert()
        7. Обновить снимок StateDB: db.set_current_bans(current_bans)

        Безопасность: каждый шаг в отдельном try/except; сбой одного jail не влияет на остальные.
        """
        if self._f2b is None:
            logger.debug("f2b_manager не настроен, пропуск опроса")
            return

        if self._db is None:
            logger.debug("db не настроен, пропуск опроса")
            return

        logger.debug("Выполнение опроса-страховки...")

        try:
            # Шаг 1: получить все текущие баны (ip, jail)
            current_bans: list[tuple[str, str]] = []
            try:
                jails = self._f2b.get_jails()
                for jail_info in jails:
                    try:
                        jail_status = self._f2b.get_jail_status(jail_info.name)
                        for ip in jail_status.banned_ips:
                            current_bans.append((ip, jail_info.name))
                    except Exception as e:
                        logger.debug(
                            "Не удалось получить статус jail '%s': %s",
                            jail_info.name, e,
                        )
            except Exception as e:
                logger.warning("Не удалось получить список банов: %s", e)
                return

            # Шаг 2: прочитать снимок из БД
            saved_bans = self._db.get_current_bans()

            # Шаг 3: вычислить diff
            current_set: set[tuple[str, str]] = set(current_bans)
            saved_set: set[tuple[str, str]] = set(saved_bans)

            added = current_set - saved_set
            removed = saved_set - current_set

            if not added and not removed:
                logger.debug("Опрос-страховка: изменений нет")
                return

            logger.info(
                "Опрос-страховка: обнаружены изменения: +%d -%d",
                len(added), len(removed),
            )

            # Шаг 4: дослать уведомления о новых банах
            if added and self._alert_sender is not None:
                for ip, jail in added:
                    try:
                        event = BanEvent(
                            ip=ip,
                            jail=jail,
                            action=BanAction.BAN,
                            timestamp=datetime.now(),
                        )
                        await self._alert_sender.send_ban_alert(event)
                        logger.info(
                            "Опрос-страховка: досылка уведомления о бане: ip=%s jail=%s",
                            ip, jail,
                        )
                    except Exception as e:
                        logger.error(
                            "Не удалось дослать уведомление о бане ip=%s: %s",
                            ip, e,
                        )

            # Шаг 5: дослать уведомления о разблокировках
            if removed and self._alert_sender is not None:
                for ip, jail in removed:
                    try:
                        event = BanEvent(
                            ip=ip,
                            jail=jail,
                            action=BanAction.UNBAN,
                            timestamp=datetime.now(),
                        )
                        await self._alert_sender.send_ban_alert(event)
                        logger.info(
                            "Опрос-страховка: досылка уведомления о разблокировке: ip=%s jail=%s",
                            ip, jail,
                        )
                    except Exception as e:
                        logger.error(
                            "Не удалось дослать уведомление о разблокировке ip=%s: %s",
                            ip, e,
                        )

            # Шаг 6: обновить снимок в БД
            self._db.set_current_bans(current_bans)
            logger.debug(
                "Обновлён снимок БД: %d записей",
                len(current_bans),
            )

        except Exception as e:
            logger.error("Ошибка опроса-страховки: %s", e, exc_info=True)

    # ── Задача 4: health-check ────────────────────────

    async def _health_check_job(self) -> None:
        """Выполняет health-check fail2ban."""
        logger.debug("Выполнение health-check...")
        try:
            await self._health_checker.check()
        except Exception as e:
            logger.error("Ошибка health-check: %s", e, exc_info=True)

    # ── Внутренние вспомогательные методы ──────────────────────────

    async def _send_report(self, message: str) -> None:
        """Отправляет отчёт через Bot в настроенный notify_chat_id.

        Если bot равен None или notify_chat_id не задан, ошибка не выбрасывается — только лог.
        """
        if self._bot is None:
            logger.warning("bot не настроен, отправка отчёта невозможна")
            return

        chat_id = self._config.telegram.notify_chat_id
        if chat_id == 0:
            logger.warning("notify_chat_id не задан, отправка отчёта невозможна")
            return

        try:
            await self._bot.send_report(chat_id=chat_id, message=message)
            logger.info("Отчёт отправлен в chat_id=%d", chat_id)
        except Exception as e:
            logger.error("Не удалось отправить отчёт: %s", e)

    @staticmethod
    def _parse_time(time_str: str) -> tuple[int, int]:
        """Разбирает строку времени в формате «HH:MM».

        Args:
            time_str: например «08:00», «14:30»

        Returns:
            Кортеж (hour, minute). При ошибке разбора возвращает (8, 0).
        """
        try:
            parts = time_str.strip().split(":")
            hour = int(parts[0])
            minute = int(parts[1]) if len(parts) > 1 else 0
            # Проверка границ
            hour = max(0, min(23, hour))
            minute = max(0, min(59, minute))
            return hour, minute
        except (ValueError, IndexError):
            logger.warning(
                "Неверный формат времени '%s', используется значение по умолчанию 08:00",
                time_str,
            )
            return 8, 0

    # ── Свойства ──────────────────────────────────

    @property
    def is_running(self) -> bool:
        """Запущен ли планировщик."""
        return (
            self._started
            and self._scheduler is not None
            and self._scheduler.running
        )

    @property
    def reporter(self) -> Optional[BanReporter]:
        """Экземпляр BanReporter (может быть None)."""
        return self._reporter

    @property
    def health_checker(self) -> HealthChecker:
        """Экземпляр HealthChecker."""
        return self._health_checker
