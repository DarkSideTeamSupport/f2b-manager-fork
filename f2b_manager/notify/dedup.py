"""
f2b_manager.notify.dedup
========================

Дедупликация и ограничение частоты сообщений.

По ключу (ip, jail) в окне dedup_window_seconds секунд
для одной пары IP+jail отправляется только одно оповещение.

Потокобезопасно: общее состояние защищено threading.Lock.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional, Tuple

logger = logging.getLogger("notify.dedup")


class DedupTracker:
    """Трекер дедупликации сообщений.

    В памяти хранит время последней отправки для каждой пары (ip, jail).
    Повторные запросы той же пары внутри окна подавляются.

    Потокобезопасно: чтение и запись под threading.Lock.
    """

    def __init__(self, window_seconds: int = 300):
        """
        Args:
            window_seconds: окно дедупликации в секундах (по умолчанию 300 = 5 мин).
        """
        self._window = window_seconds
        self._lock = threading.Lock()
        # {(ip, jail): last_notify_timestamp}
        self._last_notify: dict[Tuple[str, str], float] = {}

    def should_send(self, ip: str, jail: str) -> bool:
        """Нужно ли отправлять уведомление по этому событию.

        Args:
            ip: IP-адрес
            jail: имя fail2ban jail

        Returns:
            True — отправить (нет в окне или первое появление);
            False — пропустить (внутри окна дедупликации).
        """
        key = (ip, jail)
        now = time.time()

        with self._lock:
            last_time = self._last_notify.get(key)

            if last_time is not None and (now - last_time) < self._window:
                elapsed = now - last_time
                logger.debug(
                    "Дедуп: пропуск ip=%s jail=%s — прошло лишь %.0f с "
                    "(окно=%d с)",
                    ip, jail, elapsed, self._window,
                )
                return False

            self._last_notify[key] = now
            return True

    def reset(self, ip: str, jail: str) -> None:
        """Сбросить дедуп для пары (например, чтобы форсировать уведомление при разбане).

        Args:
            ip: IP-адрес
            jail: имя jail
        """
        key = (ip, jail)
        with self._lock:
            self._last_notify.pop(key, None)

    def reset_all(self) -> None:
        """Очистить всё состояние дедупликации."""
        with self._lock:
            self._last_notify.clear()

    def cleanup(self, max_age_seconds: Optional[int] = None) -> int:
        """Удалить устаревшие записи дедупликации.

        Args:
            max_age_seconds: возраст записи для удаления;
                             по умолчанию window_seconds * 2.

        Returns:
            Число удалённых записей.
        """
        if max_age_seconds is None:
            max_age_seconds = self._window * 2

        now = time.time()
        cutoff = now - max_age_seconds
        removed = 0

        with self._lock:
            stale_keys = [
                k for k, t in self._last_notify.items()
                if t < cutoff
            ]
            for k in stale_keys:
                del self._last_notify[k]
            removed = len(stale_keys)

        if removed:
            logger.debug(
                "Удалено %d устаревших записей дедупа (max_age=%d с)",
                removed, max_age_seconds,
            )

        return removed

    def __len__(self) -> int:
        """Текущее число отслеживаемых пар."""
        with self._lock:
            return len(self._last_notify)
