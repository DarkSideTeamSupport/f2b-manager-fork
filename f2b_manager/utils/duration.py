"""Парсинг длительностей Fail2ban (10m, 1h, 1d, 1w, 1M)."""

from __future__ import annotations

import re

_DURATION_RE = re.compile(r"^(\d+)\s*([smhdwM])$", re.IGNORECASE)

_UNIT_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
    "M": 2592000,  # ~30 дней, как в fail2ban
}


def duration_to_seconds(value: str) -> int | None:
    """Преобразовать строку длительности fail2ban в секунды.

    Поддерживает суффиксы: s, m, h, d, w, M.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.isdigit():
        return int(raw)
    match = _DURATION_RE.match(raw)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2)
    # M (месяц) регистрозависим; остальное — lower
    if unit == "M":
        mult = _UNIT_SECONDS["M"]
    else:
        mult = _UNIT_SECONDS.get(unit.lower())
        if mult is None:
            return None
    return amount * mult


def incremental_bantime_valid(bantime: str, max_bantime: str) -> tuple[bool, str]:
    """Проверить, что bantime.maxtime >= bantime при нарастающем бане.

    Returns:
        (ok, message) — message пустой при ok, иначе текст ошибки для UI.
    """
    ban_sec = duration_to_seconds(bantime)
    max_sec = duration_to_seconds(max_bantime)
    if ban_sec is None:
        return False, f"Некорректная длительность блокировки: {bantime!r}"
    if max_sec is None:
        return False, f"Некорректная макс. длительность: {max_bantime!r}"
    if max_sec < ban_sec:
        return (
            False,
            f"Макс. длительность ({max_bantime}) меньше базовой ({bantime}). "
            f"При нарастающем бане fail2ban отклонит jail.local (reload exit 255). "
            f"Поставьте макс. >= {bantime} (например 1w).",
        )
    return True, ""
