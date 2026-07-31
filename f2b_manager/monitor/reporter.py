"""
f2b_manager.monitor.reporter
=============================

Генератор отчётов.

Реализует протокол IReporter: формирует ежедневные, еженедельные и мгновенные
отчёты о блокировках.
Источники данных: статистика StateDB и статус Fail2banManager.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from ..config import AppConfig
from ..storage.database import StateDB
from ..storage.models import (
    IFail2banManager,
    ServiceState,
)

logger = logging.getLogger("monitor.reporter")


def _fmt_time(dt: Optional[datetime] = None) -> str:
    """Форматирует время в читаемую строку."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_date(dt: Optional[datetime] = None) -> str:
    """Форматирует дату в YYYY-MM-DD."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d")


def _state_emoji(state: ServiceState) -> str:
    """Статус сервиса → emoji цветного индикатора."""
    if state == ServiceState.RUNNING:
        return "\U0001f7e2"  # 🟢
    elif state == ServiceState.STOPPED:
        return "\U0001f534"  # 🔴
    return "\U0001f7e1"  # 🟡


def _bar_chart(count: int, max_width: int = 20) -> str:
    """Формирует простую строку-гистограмму."""
    return "\u2588" * min(count, max_width)


class BanReporter:
    """Генератор отчётов о блокировках, реализующий протокол IReporter.

    Аргументы конструктора:
        config: глобальная конфигурация приложения (сводка настроек fail2ban)
        f2b_manager: интерфейс управления Fail2ban в runtime
        db: хранилище состояния (статистические запросы)

    Usage:
        reporter = BanReporter(config, f2b_manager, db)
        daily = reporter.daily_report()     # текст ежедневного отчёта
        weekly = reporter.weekly_report()   # текст еженедельного отчёта
        instant = reporter.instant_report() # мгновенный снимок
    """

    def __init__(
        self,
        config: AppConfig,
        f2b_manager: IFail2banManager,
        db: StateDB,
    ):
        self._config = config
        self._f2b = f2b_manager
        self._db = db

    # ── Реализация протокола IReporter ─────────────────────

    def daily_report(self) -> str:
        """Формирует текст ежедневного HTML-отчёта.

        Содержание:
        - статус сервиса (версия, состояние, количество jail)
        - статистика банов за сегодня (число банов, IP в бане сейчас)
        - топ-5 IP источников атак
        - топ-5 стран-источников атак
        - статус каждого jail (текущие баны, неудачные попытки)
        - сводка конфигурации Fail2ban

        Returns:
            Отформатированный HTML-текст отчёта (для отправки в Telegram).
        """
        # ── Получение данных ──
        try:
            status = self._f2b.get_status()
        except Exception as e:
            logger.warning("Не удалось получить статус fail2ban: %s", e)
            status = None

        bans_today = self._db.count_bans_today()
        current_bans = self._db.get_current_bans()
        top_ips = self._db.top_banned_ips(days=1, limit=5)
        top_countries = self._db.top_banned_countries(days=1, limit=5)

        try:
            jails = self._f2b.get_jails()
        except Exception as e:
            logger.warning("Не удалось получить список jail: %s", e)
            jails = []

        today = _fmt_date()

        # ── Формирование отчёта ──
        lines: list[str] = []
        lines.append("<b>\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501</b>")
        lines.append(f"<b>\U0001f4ca Ежедневный отчёт Fail2ban {today}</b>")
        lines.append("<b>\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501</b>")
        lines.append("")

        # Статус сервиса
        if status is not None:
            emoji = _state_emoji(status.state)
            lines.append(f"{emoji} <b>Статус сервиса:</b> {status.state.value}")
            if status.version:
                lines.append(f"\U0001f4e6 <b>Версия:</b> {status.version}")
            if status.jail_count:
                lines.append(f"\U0001f512 <b>Количество jail:</b> {status.jail_count}")
        else:
            lines.append("\U0001f534 <b>Статус сервиса:</b> недоступен")

        lines.append("")

        # Статистика банов за сегодня
        lines.append("<b>\U0001f6ab Баны за сегодня:</b>")
        lines.append(f"  \u2022 Всего банов: <b>{bans_today}</b>")
        lines.append(f"  \u2022 Сейчас в бане: <b>{len(current_bans)}</b> IP")

        # Топ IP источников атак
        if top_ips:
            lines.append("")
            lines.append("<b>\U0001f3af Топ источников атак (сегодня):</b>")
            for i, (ip, count) in enumerate(top_ips, 1):
                country = self._get_ip_country(ip)
                country_display = f" ({country})" if country else ""
                lines.append(
                    f"  {i}. <code>{ip}</code>{country_display} - "
                    f"<b>{count}</b> раз"
                )

        # Топ стран-источников атак
        if top_countries:
            lines.append("")
            lines.append("<b>\U0001f310 Топ стран-источников:</b>")
            for i, (country, count) in enumerate(top_countries, 1):
                country_display = country if country else "неизвестно"
                lines.append(f"  {i}. {country_display} - <b>{count}</b> раз")

        # Статус jail
        if jails:
            lines.append("")
            lines.append("<b>\U0001f512 Статус jail:</b>")
            for jail in jails:
                lines.append(
                    f"  \u2022 <code>{jail.name}</code>: "
                    f"бан {jail.current_ban} / "
                    f"неудач {jail.total_failed}"
                )

        # Сводка конфигурации
        lines.append("")
        lines.append("<b>\u2699\ufe0f Конфигурация:</b>")
        f2b_cfg = self._config.fail2ban
        lines.append(f"  \u2022 bantime: {f2b_cfg.default_bantime}")
        lines.append(f"  \u2022 maxretry: {f2b_cfg.default_maxretry}")
        lines.append(f"  \u2022 findtime: {f2b_cfg.default_findtime}")

        lines.append("")
        lines.append("<b>\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501</b>")
        lines.append(f"<i>Сформировано: {_fmt_time()}</i>")

        return "\n".join(lines)

    def weekly_report(self) -> str:
        """Формирует текст еженедельного HTML-отчёта.

        Содержание:
        - статус сервиса
        - итоги за неделю (всего банов, уникальных IP атакующих, IP в бане сейчас)
        - динамика банов по дням (гистограмма)
        - топ-10 IP источников атак
        - топ-5 стран-источников атак

        Returns:
            Отформатированный HTML-текст отчёта.
        """
        today = _fmt_date()
        week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        # ── Получение данных ──
        try:
            status = self._f2b.get_status()
        except Exception as e:
            logger.warning("Не удалось получить статус fail2ban: %s", e)
            status = None

        daily_stats = self._db.get_daily_stats(days=7)
        top_ips = self._db.top_banned_ips(days=7, limit=10)
        top_countries = self._db.top_banned_countries(days=7, limit=5)

        # Итоги за неделю
        total_weekly_bans = sum(s.total_bans for s in daily_stats)
        total_weekly_ips = sum(s.unique_ips for s in daily_stats)
        current_bans = self._db.get_current_bans()

        # ── Формирование отчёта ──
        lines: list[str] = []
        lines.append("<b>\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501</b>")
        lines.append("<b>\U0001f4ca Еженедельный отчёт Fail2ban</b>")
        lines.append(f"<b>{week_ago} ~ {today}</b>")
        lines.append("<b>\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501</b>")
        lines.append("")

        # Статус сервиса
        if status is not None:
            emoji = _state_emoji(status.state)
            lines.append(f"{emoji} <b>Статус сервиса:</b> {status.state.value}")
            lines.append(f"\U0001f4e6 <b>Версия:</b> {status.version}")
        else:
            lines.append("\U0001f534 <b>Статус сервиса:</b> недоступен")

        lines.append("")

        # Итоги за неделю
        lines.append("<b>\U0001f4ca Итоги за неделю:</b>")
        lines.append(f"  \u2022 Всего банов: <b>{total_weekly_bans}</b>")
        lines.append(f"  \u2022 Уникальных IP атакующих: <b>{total_weekly_ips}</b>")
        lines.append(f"  \u2022 Сейчас в бане: <b>{len(current_bans)}</b> IP")

        # Динамика по дням (гистограмма)
        if daily_stats:
            lines.append("")
            lines.append("<b>\U0001f4c8 Динамика банов по дням:</b>")
            max_bans = max((s.total_bans for s in daily_stats), default=1)
            for stat in daily_stats:
                bar_width = int(stat.total_bans / max_bans * 20) if max_bans > 0 else 0
                bar = _bar_chart(bar_width)
                lines.append(
                    f"  <code>{stat.date}</code> {bar} "
                    f"<b>{stat.total_bans}</b> раз "
                    f"({stat.unique_ips} IP)"
                )

        # Топ IP источников атак
        if top_ips:
            lines.append("")
            lines.append("<b>\U0001f3af Топ источников атак (неделя):</b>")
            for i, (ip, count) in enumerate(top_ips, 1):
                country = self._get_ip_country(ip)
                country_display = f" ({country})" if country else ""
                lines.append(
                    f"  {i}. <code>{ip}</code>{country_display} - "
                    f"<b>{count}</b> раз"
                )

        # Топ стран-источников атак
        if top_countries:
            lines.append("")
            lines.append("<b>\U0001f310 Топ стран-источников:</b>")
            for i, (country, count) in enumerate(top_countries, 1):
                country_display = country if country else "неизвестно"
                lines.append(f"  {i}. {country_display} - <b>{count}</b> раз")

        lines.append("")
        lines.append("<b>\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                      "\u2501\u2501\u2501\u2501\u2501\u2501</b>")
        lines.append(f"<i>Сформировано: {_fmt_time()}</i>")

        return "\n".join(lines)

    def instant_report(self) -> str:
        """Формирует мгновенный отчёт для команды /report.

        Краткий снимок для быстрого просмотра. Содержит:
        - статус сервиса
        - число банов за сегодня и IP в бане сейчас
        - топ-3 IP с наибольшим числом атак

        Returns:
            Отформатированный HTML-текст отчёта.
        """
        # ── Получение данных ──
        try:
            status = self._f2b.get_status()
        except Exception as e:
            logger.warning("Не удалось получить статус fail2ban: %s", e)
            status = None

        bans_today = self._db.count_bans_today()
        current_bans = self._db.get_current_bans()
        top_ips = self._db.top_banned_ips(days=1, limit=3)

        # ── Формирование отчёта ──
        lines: list[str] = []
        lines.append("<b>\U0001f4ca Мгновенный отчёт Fail2ban</b>")
        lines.append("")

        if status is not None:
            emoji = _state_emoji(status.state)
            parts = [f"{emoji} Статус: {status.state.value}"]
            if status.version:
                parts.append(f"Версия: {status.version}")
            if status.jail_count:
                parts.append(f"Jail: {status.jail_count} шт.")
            lines.append(" | ".join(parts))
        else:
            lines.append("\U0001f534 Статус: недоступен")

        lines.append(
            f"\U0001f6ab Баны за сегодня: <b>{bans_today}</b> раз | "
            f"Сейчас в бане: <b>{len(current_bans)}</b> IP"
        )

        if top_ips:
            ips_parts = []
            for ip, cnt in top_ips:
                ips_parts.append(f"<code>{ip}</code>({cnt})")
            lines.append(f"\U0001f3af Частые атаки: {', '.join(ips_parts)}")

        lines.append(f"\n<i>Сформировано: {_fmt_time()}</i>")

        return "\n".join(lines)

    # ── Внутренние методы ──────────────────────────────

    def _get_ip_country(self, ip: str) -> str:
        """Определяет страну IP по истории банов.

        Args:
            ip: IP-адрес

        Returns:
            Название страны; пустая строка, если не найдено.
        """
        try:
            history = self._db.get_ban_history(days=30)
            for event in history:
                if event.ip == ip and event.country:
                    return event.country
        except Exception as e:
            logger.debug("Не удалось определить страну IP ip=%s: %s", ip, e)
        return ""
