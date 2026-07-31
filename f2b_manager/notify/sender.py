"""
f2b_manager.notify.sender
=========================

Формирование и отправка оповещений.

Реализует протокол IAlertSender и отвечает за:
1. Определение геолокации IP (GeoIPLookup)
2. Проверку дедупликации (DedupTracker)
3. Формирование HTML-сообщений об оповещениях
4. Отправку сообщений через Telegram Bot
5. Запись событий бана в базу состояния

Параметр bot может быть None (режим разработки/тестирования) —
в этом случае только пишется лог, без отправки.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from ..config import AppConfig
from ..storage.models import (
    BanAction, BanEvent, GeoInfo, IAlertSender, IMessageSender, IStateDB,
)

logger = logging.getLogger("notify.sender")

# ── Шаблоны сообщений ────────────────────────────────

BAN_TEMPLATE = """\
<b>Оповещение о бане IP</b>
----------------------
Jail: <code>{jail}</code>
IP: <code>{ip}</code>
Страна: {country} {flag}
Неудачных попыток: <b>{failures}</b>
Время: {time}
Совпадения в логе:
<pre>{matches_preview}</pre>
----------------------
Сейчас в бане: {total_banned} IP"""

UNBAN_TEMPLATE = """\
<b>IP разбанен</b>
----------------------
IP: <code>{ip}</code>
Jail: {jail}
Время разбана: {time}
Длительность бана: {ban_duration}"""

SERVICE_START_TEMPLATE = """\
<b>Запуск службы Fail2ban</b>
----------------------
Jail: {jail}
Время: {time}"""

SERVICE_STOP_TEMPLATE = """\
<b>Остановка службы Fail2ban</b>
----------------------
Jail: {jail}
Время: {time}"""


def _format_time(dt: Optional[datetime] = None) -> str:
    """Форматирует время в читаемую строку."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _truncate_matches(matches: str, max_length: int = 200) -> str:
    """Обрезает совпадения в логе, чтобы сообщение не было слишком длинным."""
    if not matches:
        return "(нет)"
    if len(matches) <= max_length:
        return matches
    return matches[:max_length] + "...(обрезано)"


def _estimate_ban_duration(event: BanEvent) -> str:
    """Оценивает длительность бана (по разнице между баном и разбаном).

    Поскольку notify.sh передаёт только текущее событие, точную длительность
    вычислить нельзя. Для событий unban возвращается оценочное значение
    от бана до разбана. Если время бана в event не зафиксировано — «неизвестно».
    """
    # Оценка по event.timestamp (здесь доступно только текущее время;
    # фактическую длительность нужно запрашивать из db)
    return "неизвестно"


class AlertSender:
    """Отправитель оповещений, реализует протокол IAlertSender.

    При создании принимает:
    - config: глобальная конфигурация приложения (переключатели notify,
      окно dedup и т.д.)
    - bot: интерфейс отправки сообщений (Telegram Bot), может быть None
      (режим разработки)
    - db: интерфейс базы состояния (запись событий, запрос статистики)
    """

    def __init__(
        self,
        config: AppConfig,
        bot: Optional[IMessageSender] = None,
        db: Optional[IStateDB] = None,
    ):
        self._config = config
        self._bot = bot
        self._db = db

        # Отложенный импорт во избежание циклических зависимостей
        from .geoip import GeoIPLookup
        from .dedup import DedupTracker

        self._geoip = GeoIPLookup(
            db_path=config.notify.geoip_db_path,
            method=config.notify.geoip_method,
        )
        self._dedup = DedupTracker(
            window_seconds=config.notify.dedup_window_seconds,
        )

    # ── Реализация протокола IAlertSender ─────────────────

    async def send_ban_alert(self, event: BanEvent) -> bool:
        """Отправляет оповещение о бане или разбане.

        Порядок обработки:
        1. Определение геолокации IP (всегда, для записи в базу)
        2. Запись в базу состояния (всегда, для статистики и аудита)
        3. Проверка дедупликации (только для событий ban)
        4. Проверка переключателей оповещений
        5. Формирование HTML-сообщения и отправка (если bot доступен)

        Args:
            event: событие бана или разбана

        Returns:
            True — обработка успешна (в том числе при дедупликации,
            отключённых оповещениях или успешной отправке);
            False — ошибка в процессе обработки.
        """
        ncfg = self._config.notify

        # Шаг 1: геолокация IP (всегда, для записи в базу и статистики)
        geo_info: GeoInfo = GeoInfo()
        if ncfg.geoip_enabled:
            try:
                geo_info = await self._geoip.lookup(event.ip)
            except Exception as e:
                logger.warning("Ошибка GeoIP-запроса ip=%s: %s", event.ip, e)

        # Обновляем поле country в event (для записи в базу)
        event.country = geo_info.country or geo_info.country_code

        # Шаг 2: запись в базу состояния (независимо от отправки оповещения)
        self._record_event(event, geo_info)

        # Шаг 3: дедупликация (только для событий ban)
        if event.action == BanAction.BAN:
            if not self._dedup.should_send(event.ip, event.jail):
                logger.info(
                    "Событие бана пропущено (дедупликация): ip=%s jail=%s (окно=%d с)",
                    event.ip, event.jail,
                    ncfg.dedup_window_seconds,
                )
                return True

        # Шаг 4: проверка переключателей оповещений
        if event.action == BanAction.BAN and not ncfg.enable_ban_alert:
            logger.debug("Оповещение о бане отключено, пропуск отправки ip=%s", event.ip)
            return True

        if event.action == BanAction.UNBAN and not ncfg.enable_unban_alert:
            logger.debug("Оповещение о разбане отключено, пропуск отправки ip=%s", event.ip)
            return True

        # Шаг 5: формирование сообщения и отправка
        message = self._build_message(event, geo_info)
        sent = await self._send_message(message)

        if sent:
            logger.info(
                "Оповещение отправлено: action=%s ip=%s jail=%s",
                event.action.value, event.ip, event.jail,
            )
        else:
            logger.warning(
                "Оповещение не отправлено (bot недоступен): action=%s ip=%s jail=%s",
                event.action.value, event.ip, event.jail,
            )

        return True

    async def send_service_alert(self, action: BanAction,
                                 jail: str = "") -> bool:
        """Отправляет оповещение о запуске или остановке службы.

        Args:
            action: BanAction.START или BanAction.STOP
            jail: имя jail

        Returns:
            True — сообщение обработано.
        """
        ncfg = self._config.notify

        if not ncfg.enable_service_alert:
            logger.debug("Оповещение о службе отключено, пропуск action=%s", action.value)
            return True

        now = _format_time()

        if action == BanAction.START:
            message = SERVICE_START_TEMPLATE.format(
                jail=jail or "all",
                time=now,
            )
        elif action == BanAction.STOP:
            message = SERVICE_STOP_TEMPLATE.format(
                jail=jail or "all",
                time=now,
            )
        else:
            logger.warning("Неподдерживаемый тип оповещения о службе: %s", action.value)
            return False

        await self._send_message(message)
        logger.info("Оповещение о службе отправлено: action=%s jail=%s",
                     action.value, jail)
        return True

    # ── Внутренние методы ──────────────────────────────

    def _build_message(self, event: BanEvent, geo_info: GeoInfo) -> str:
        """Формирует HTML-текст сообщения в зависимости от типа события."""
        now = _format_time(event.timestamp)

        country_display = geo_info.country or "неизвестно"
        flag_display = geo_info.flag or ""

        if event.action == BanAction.BAN:
            # Текущее общее число банов
            total_banned = self._count_current_bans()

            return BAN_TEMPLATE.format(
                jail=event.jail,
                ip=event.ip,
                country=country_display,
                flag=flag_display,
                failures=event.failures,
                time=now,
                matches_preview=_truncate_matches(event.matches),
                total_banned=total_banned,
            )
        else:
            # UNBAN
            return UNBAN_TEMPLATE.format(
                ip=event.ip,
                jail=event.jail,
                time=now,
                ban_duration=_estimate_ban_duration(event),
            )

    async def _send_message(self, message: str) -> bool:
        """Отправляет сообщение через bot.

        Если bot равен None, не падает — только пишет в лог.
        """
        if self._bot is None:
            logger.debug("bot не настроен, пропуск отправки сообщения")
            return False

        try:
            chat_id = self._config.telegram.notify_chat_id
            if chat_id == 0:
                logger.warning("notify_chat_id не задан, отправка невозможна")
                return False

            return await self._bot.send_alert(
                chat_id=chat_id,
                message=message,
                parse_mode="HTML",
            )
        except Exception as e:
            logger.error("Не удалось отправить сообщение: %s", e)
            return False

    def _record_event(self, event: BanEvent, geo_info: GeoInfo) -> None:
        """Записывает событие в базу состояния."""
        if self._db is None:
            logger.debug("db не настроена, пропуск записи события")
            return

        try:
            # Обновляем поле country
            if geo_info.country:
                event.country = geo_info.country
            elif geo_info.country_code:
                event.country = geo_info.country_code

            self._db.record_ban(event)
            logger.debug("Событие записано в базу состояния: ip=%s action=%s",
                         event.ip, event.action.value)
        except Exception as e:
            logger.error("Не удалось записать событие в базу состояния: %s", e)

    def _count_current_bans(self) -> int:
        """Возвращает текущее общее число банов."""
        if self._db is None:
            return 0

        try:
            bans = self._db.get_current_bans()
            return len(bans)
        except Exception as e:
            logger.debug("Не удалось получить число текущих банов: %s", e)
            return 0

    def close(self) -> None:
        """Освобождает ресурсы."""
        if self._geoip is not None:
            self._geoip.close()
