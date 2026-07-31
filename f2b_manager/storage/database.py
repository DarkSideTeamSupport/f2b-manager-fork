"""
f2b_manager.storage.database
============================

Работа с SQLite-хранилищем состояния.

Отвечает за сохранение истории банов, снимка текущих банов,
ежедневной статистики и переопределений конфигурации.
Структура таблиц создаётся автоматически в init(); вызов идемпотентен.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .models import BanAction, BanEvent, DailyStat


# SQL-схема (CREATE TABLE)
_SCHEMA = """
CREATE TABLE IF NOT EXISTS ban_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    jail        TEXT NOT NULL,
    action      TEXT NOT NULL,
    failures    INTEGER DEFAULT 0,
    country     TEXT DEFAULT '',
    matches     TEXT DEFAULT '',
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    notified    INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ban_history_ip
    ON ban_history(ip);
CREATE INDEX IF NOT EXISTS idx_ban_history_timestamp
    ON ban_history(timestamp);

CREATE TABLE IF NOT EXISTS current_bans (
    ip          TEXT NOT NULL,
    jail        TEXT NOT NULL,
    banned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip, jail)
);

CREATE TABLE IF NOT EXISTS daily_stats (
    date        TEXT PRIMARY KEY,
    total_bans  INTEGER DEFAULT 0,
    unique_ips  INTEGER DEFAULT 0,
    top_country TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS config_overrides (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class StateDB:
    """SQLite-хранилище состояния (потокобезопасное)"""

    def __init__(self, db_path: str = "/var/lib/f2b-manager/state.db"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()
        self.init()

    def _connect(self) -> None:
        """Установить соединение с базой данных"""
        path = Path(self._db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        # Режим WAL для лучшей конкурентности чтения/записи
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def init(self) -> None:
        """Инициализировать схему таблиц (идемпотентно)"""
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        """Закрыть соединение с базой данных"""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    # ── История банов ──────────────────────────────

    def record_ban(self, event: BanEvent) -> None:
        """Записать событие бана/разбана в историю и синхронно обновить снимок current_bans.

        Синхронизация current_bans нужна, чтобы события, уже обработанные через CLI,
        не обрабатывались повторно опросом-страховкой (_poll_ban_changes_job)
        и не удваивали статистику.

        - BAN: после записи в ban_history — INSERT OR REPLACE в current_bans
        - UNBAN: после записи в ban_history — DELETE из current_bans
        """
        ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            self._conn.execute(
                """INSERT INTO ban_history
                   (ip, jail, action, failures, country, matches, timestamp, notified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
                (
                    event.ip,
                    event.jail,
                    event.action.value,
                    event.failures,
                    event.country,
                    event.matches[:500],  # Ограничение длины, чтобы не сохранять огромные логи
                    ts,
                ),
            )

            # Синхронизация снимка current_bans, чтобы опрос-страховка не обрабатывал событие повторно
            if event.action == BanAction.BAN:
                self._conn.execute(
                    """INSERT OR REPLACE INTO current_bans (ip, jail, banned_at)
                       VALUES (?, ?, ?)""",
                    (event.ip, event.jail, ts),
                )
            elif event.action == BanAction.UNBAN:
                self._conn.execute(
                    "DELETE FROM current_bans WHERE ip = ? AND jail = ?",
                    (event.ip, event.jail),
                )

            self._conn.commit()

    def mark_notified(self, event_id: int) -> None:
        """Отметить запись как уведомлённую"""
        with self._lock:
            self._conn.execute(
                "UPDATE ban_history SET notified = 1 WHERE id = ?",
                (event_id,),
            )
            self._conn.commit()

    def get_ban_history(self, days: int = 7) -> list[BanEvent]:
        """Получить историю банов за последние N дней"""
        cutoff = (datetime.now() - timedelta(days=days)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM ban_history
                   WHERE timestamp >= ?
                   ORDER BY timestamp DESC""",
                (cutoff,),
            ).fetchall()

        return [
            BanEvent(
                ip=row["ip"],
                jail=row["jail"],
                action=BanAction(row["action"]),
                failures=row["failures"],
                country=row["country"],
                matches=row["matches"],
                timestamp=datetime.strptime(
                    row["timestamp"], "%Y-%m-%d %H:%M:%S"
                ),
            )
            for row in rows
        ]

    def get_unnotified_bans(self) -> list[tuple[int, BanEvent]]:
        """Получить неуведомлённые записи о банах (для опроса-страховки)"""
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM ban_history
                   WHERE notified = 0 AND action = 'ban'
                   ORDER BY timestamp ASC"""
            ).fetchall()

        return [
            (
                row["id"],
                BanEvent(
                    ip=row["ip"],
                    jail=row["jail"],
                    action=BanAction(row["action"]),
                    failures=row["failures"],
                    country=row["country"],
                    matches=row["matches"],
                    timestamp=datetime.strptime(
                        row["timestamp"], "%Y-%m-%d %H:%M:%S"
                    ),
                ),
            )
            for row in rows
        ]

    # ── Снимок текущих банов ──────────────────────────

    def get_current_bans(self) -> list[tuple[str, str]]:
        """Получить снимок текущих банов [(ip, jail), ...]"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, jail FROM current_bans"
            ).fetchall()
        return [(row["ip"], row["jail"]) for row in rows]

    def set_current_bans(self, bans: list[tuple[str, str]]) -> None:
        """Полностью обновить снимок текущих банов"""
        with self._lock:
            self._conn.execute("DELETE FROM current_bans")
            self._conn.executemany(
                "INSERT INTO current_bans (ip, jail) VALUES (?, ?)",
                bans,
            )
            self._conn.commit()

    # ── Ежедневная статистика ──────────────────────────────

    def get_daily_stats(self, days: int = 7) -> list[DailyStat]:
        """Получить ежедневную статистику"""
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM daily_stats
                   WHERE date >= ?
                   ORDER BY date DESC""",
                (cutoff,),
            ).fetchall()
        return [
            DailyStat(
                date=row["date"],
                total_bans=row["total_bans"],
                unique_ips=row["unique_ips"],
                top_country=row["top_country"],
            )
            for row in rows
        ]

    def update_daily_stats(self, date: str, total_bans: int,
                           unique_ips: int, top_country: str = "") -> None:
        """Обновить статистику за день (upsert)"""
        with self._lock:
            self._conn.execute(
                """INSERT INTO daily_stats (date, total_bans, unique_ips, top_country)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(date) DO UPDATE SET
                       total_bans = excluded.total_bans,
                       unique_ips = excluded.unique_ips,
                       top_country = excluded.top_country""",
                (date, total_bans, unique_ips, top_country),
            )
            self._conn.commit()

    # ── Переопределения конфигурации ──────────────────────────────

    def set_config_override(self, key: str, value: str) -> None:
        """Задать переопределение конфигурации (upsert)"""
        with self._lock:
            self._conn.execute(
                """INSERT INTO config_overrides (key, value)
                   VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                (key, value),
            )
            self._conn.commit()

    def get_config_override(self, key: str, default: str = "") -> str:
        """Получить значение переопределения конфигурации"""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM config_overrides WHERE key = ?",
                (key,),
            ).fetchone()
        return row["value"] if row else default

    def delete_config_override(self, key: str) -> None:
        """Удалить переопределение конфигурации"""
        with self._lock:
            self._conn.execute(
                "DELETE FROM config_overrides WHERE key = ?", (key,)
            )
            self._conn.commit()

    # ── Статистические запросы ──────────────────────────────

    def count_bans_today(self) -> int:
        """Подсчитать число банов за сегодня"""
        today = datetime.now().strftime("%Y-%m-%d")
        with self._lock:
            row = self._conn.execute(
                """SELECT COUNT(*) as cnt FROM ban_history
                   WHERE action = 'ban' AND timestamp LIKE ?""",
                (f"{today}%",),
            ).fetchone()
        return row["cnt"] if row else 0

    def top_banned_ips(self, days: int = 7, limit: int = 10) -> list[tuple[str, int]]:
        """Получить IP с наибольшим числом банов"""
        cutoff = (datetime.now() - timedelta(days=days)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        with self._lock:
            rows = self._conn.execute(
                """SELECT ip, COUNT(*) as cnt FROM ban_history
                   WHERE action = 'ban' AND timestamp >= ?
                   GROUP BY ip ORDER BY cnt DESC LIMIT ?""",
                (cutoff, limit),
            ).fetchall()
        return [(row["ip"], row["cnt"]) for row in rows]

    def top_banned_countries(self, days: int = 7,
                             limit: int = 10) -> list[tuple[str, int]]:
        """Получить страны с наибольшим числом банов"""
        cutoff = (datetime.now() - timedelta(days=days)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        with self._lock:
            rows = self._conn.execute(
                """SELECT country, COUNT(*) as cnt FROM ban_history
                   WHERE action = 'ban' AND timestamp >= ?
                     AND country != ''
                   GROUP BY country ORDER BY cnt DESC LIMIT ?""",
                (cutoff, limit),
            ).fetchall()
        return [(row["country"], row["cnt"]) for row in rows]
