"""
f2b_manager.fail2ban.parser
============================

Разбор вывода команд fail2ban-client.

Совместим с fail2ban 0.11.x (ASCII-дерево) и 1.0.x (Unicode-дерево).
Возвращает Fail2banStatus, JailInfo, JailStatus из models.py.
"""

from __future__ import annotations

import re
from typing import Optional

from ..storage.models import Fail2banStatus, JailInfo, JailStatus, ServiceState
from ..utils.logger import get_logger

_logger = get_logger(__name__)


# ──────────────────────────────────────────────
# Примеры вывода для самопроверки
# ──────────────────────────────────────────────

# Формат fail2ban 0.11.x
STATUS_OUTPUT_0_11 = """
Status
|- Number of jail:\t2
`- Jail list:\tsshd, nginx-http-auth
"""

# Формат fail2ban 1.0.x
STATUS_OUTPUT_1_0 = """
Status
├─ Number of jail:\t3
└─ Jail list:\tsshd, nginx-http-auth, recidive
"""

# Подробный статус одного jail (0.11.x)
JAIL_STATUS_OUTPUT_0_11 = """Status for the jail 'sshd'
|- Filter
|  |- Currently failed:\t3
|  |- Total failed:\t156
|  `- Journal matches:\t_SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned:\t5
   |- Total banned:\t42
   `- Banned IP list:\t1.2.3.4 5.6.7.8 9.10.11.12
"""

# Подробный статус одного jail (1.0.x)
JAIL_STATUS_OUTPUT_1_0 = """Status for the jail 'sshd'
├─ Filter
│  ├─ Currently failed:\t3
│  ├─ Total failed:\t156
│  └─ Journal matches:\t_SYSTEMD_UNIT=sshd.service + _COMM=sshd
└─ Actions
   ├─ Currently banned:\t5
   ├─ Total banned:\t42
   └─ Banned IP list:\t1.2.3.4 5.6.7.8 9.10.11.12
"""

# Пустой бан-лист (1.0.x)
JAIL_STATUS_EMPTY = """Status for the jail 'nginx-http-auth'
├─ Filter
│  ├─ Currently failed:\t0
│  ├─ Total failed:\t3
│  └─ Journal matches:\t_SYSTEMD_UNIT=nginx.service
└─ Actions
   ├─ Currently banned:\t0
   ├─ Total banned:\t0
   └─ Banned IP list:
"""

# Пример вывода fail2ban-client banned
BANNED_OUTPUT = """1.2.3.4
5.6.7.8
9.10.11.12"""

# Пустой список блокировок
BANNED_EMPTY = ""


# ──────────────────────────────────────────────
# Внутренние утилиты
# ──────────────────────────────────────────────

def _extract_int(line: str) -> int:
    """Извлечь целое из строки вида '|- Currently failed:\\t3'."""
    m = re.search(r":\s*(\d+)", line)
    return int(m.group(1)) if m else 0


def _extract_value(line: str) -> str:
    """Извлечь значение после двоеточия из строки вида '`- Jail list:\\tsshd'."""
    parts = re.split(r":\s*", line, maxsplit=1)
    return parts[1].strip() if len(parts) > 1 else ""


def _strip_tree_chars(line: str) -> str:
    """Убрать символы дерева fail2ban (|- `- ├─ └─ │), оставить текст."""
    cleaned = re.sub(r"^[\s]*[|`├└│\-─]+[\s]*", "", line)
    return cleaned.strip()


def _normalize_lines(raw: str) -> list[str]:
    """Разбить вывод на строки, убрать пустые и заголовок 'Status'."""
    lines = [line.rstrip() for line in raw.strip().splitlines()]
    return [l for l in lines if l and l.strip() != "Status"]


# ──────────────────────────────────────────────
# Публичные функции разбора
# ──────────────────────────────────────────────

def parse_version(raw: str) -> str:
    """Разобрать вывод fail2ban-client version.

    Args:
        raw: вывод команды, например «0.11.2» или «Fail2Ban v0.11.2».

    Returns:
        Строка версии.
    """
    raw = raw.strip()
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", raw)
    if m:
        return m.group(1)
    return raw or "unknown"


def parse_status(raw: str) -> Fail2banStatus:
    """Разобрать вывод fail2ban-client status.

    Поддерживает форматы 0.11.x (ASCII) и 1.0.x (Unicode).

    Args:
        raw: stdout команды fail2ban-client status.

    Returns:
        Fail2banStatus.
    """
    status = Fail2banStatus()
    lines = _normalize_lines(raw)

    for line in lines:
        cleaned = _strip_tree_chars(line)
        if not cleaned:
            continue

        if "Number of jail" in cleaned:
            status.jail_count = _extract_int(line)
        elif "Jail list" in cleaned:
            raw_jails = _extract_value(line)
            if raw_jails:
                # Только для отладки; список jail даёт get_jails()
                jail_names = [j.strip() for j in raw_jails.split(",") if j.strip()]
        elif "Currently banned" in cleaned:
            status.total_bans = _extract_int(line)

    _logger.debug(
        "Parsed status: jail_count=%d, total_bans=%d",
        status.jail_count, status.total_bans,
    )
    return status


def parse_jail_status(raw: str) -> JailStatus:
    """Разобрать вывод fail2ban-client status <jail>.

    Поддерживает 0.11.x и 1.0.x.
    Извлекает имя jail, счётчики блокировок/сбоев и список IP.

    Args:
        raw: stdout команды fail2ban-client status <jail>.

    Returns:
        JailStatus.
    """
    jail_name = ""
    m = re.search(r"Status for the jail ['\"]?([^'\"]+)['\"]?", raw)
    if m:
        jail_name = m.group(1)

    jail_status = JailStatus(name=jail_name, enabled=True)
    lines = _normalize_lines(raw)

    for line in lines:
        cleaned = _strip_tree_chars(line)
        if not cleaned:
            continue

        if "Currently failed" in cleaned:
            jail_status.total_failed = _extract_int(line)
        elif "Total failed" in cleaned:
            jail_status.total_failed = _extract_int(line)
        elif "Currently banned" in cleaned:
            jail_status.current_ban = _extract_int(line)
        elif "Total banned" in cleaned:
            jail_status.total_banned = _extract_int(line)
        elif "Banned IP list" in cleaned:
            raw_ips = _extract_value(line)
            if raw_ips:
                jail_status.banned_ips = raw_ips.split()
        elif "File list" in cleaned or "Journal matches" in cleaned:
            pass

    _logger.debug(
        "Parsed jail status: name=%s bans=%d failed=%d ips=%d",
        jail_name, jail_status.current_ban,
        jail_status.total_failed, len(jail_status.banned_ips),
    )
    return jail_status


def parse_banned_ips(raw: str) -> list[str]:
    """Разобрать вывод fail2ban-client banned.

    Форматы:
    - fail2ban 0.x: один IP на строку;
    - fail2ban 1.0+: структура вида [{'sshd': ['1.2.3.4']}, {'nginx': []}].

    Args:
        raw: stdout команды fail2ban-client banned.

    Returns:
        Список IP-адресов.
    """
    if not raw or not raw.strip():
        return []

    raw = raw.strip()

    # Структурированный вывод fail2ban 1.0+
    if raw.startswith("["):
        try:
            import ast
            data = ast.literal_eval(raw)
            ips: list[str] = []
            for item in data:
                if isinstance(item, dict):
                    for jail_ips in item.values():
                        if isinstance(jail_ips, list):
                            ips.extend(jail_ips)
                        elif isinstance(jail_ips, str):
                            ips.append(jail_ips)
            return ips
        except (ValueError, SyntaxError):
            pass

    # fail2ban 0.x: по одному IP в строке
    return [ip.strip() for ip in raw.splitlines() if ip.strip()]


def parse_jail_list(raw: str) -> list[JailInfo]:
    """Извлечь список jail из вывода fail2ban-client status.

    Args:
        raw: stdout команды fail2ban-client status.

    Returns:
        Список JailInfo (заполнены name и enabled).
    """
    jails: list[JailInfo] = []
    lines = _normalize_lines(raw)

    for line in lines:
        if "Jail list" in line:
            raw_jails = _extract_value(line)
            if raw_jails:
                names = [j.strip() for j in raw_jails.split(",") if j.strip()]
                jails = [JailInfo(name=n, enabled=True) for n in names]
            break

    return jails


# ──────────────────────────────────────────────
# Самопроверка (при прямом запуске файла)
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Тест parse_version ===")
    assert parse_version("0.11.2") == "0.11.2"
    assert parse_version("Fail2Ban v1.0.2") == "1.0.2"
    assert parse_version("1.0.2\n") == "1.0.2"
    print("  parse_version: PASS")

    print("\n=== Тест parse_status (0.11.x) ===")
    s = parse_status(STATUS_OUTPUT_0_11)
    assert s.jail_count == 2
    assert s.total_bans == 0  # в status нет total_bans
    print(f"  jail_count={s.jail_count}, total_bans={s.total_bans}: PASS")

    print("\n=== Тест parse_status (1.0.x) ===")
    s = parse_status(STATUS_OUTPUT_1_0)
    assert s.jail_count == 3
    print(f"  jail_count={s.jail_count}: PASS")

    print("\n=== Тест parse_jail_list (0.11.x) ===")
    jails = parse_jail_list(STATUS_OUTPUT_0_11)
    assert len(jails) == 2
    assert jails[0].name == "sshd"
    assert jails[1].name == "nginx-http-auth"
    print(f"  jails={[j.name for j in jails]}: PASS")

    print("\n=== Тест parse_jail_status (0.11.x) ===")
    js = parse_jail_status(JAIL_STATUS_OUTPUT_0_11)
    assert js.name == "sshd"
    assert js.total_failed == 156
    assert js.current_ban == 5
    assert js.total_banned == 42
    assert len(js.banned_ips) == 3
    assert "1.2.3.4" in js.banned_ips
    print(
        f"  name={js.name}, failed={js.total_failed}, "
        f"current_ban={js.current_ban}, total_banned={js.total_banned}, "
        f"ips={js.banned_ips}: PASS"
    )

    print("\n=== Тест parse_jail_status (1.0.x) ===")
    js = parse_jail_status(JAIL_STATUS_OUTPUT_1_0)
    assert js.name == "sshd"
    assert js.total_failed == 156
    assert js.current_ban == 5
    assert len(js.banned_ips) == 3
    print(f"  name={js.name}: PASS")

    print("\n=== Тест parse_jail_status (empty) ===")
    js = parse_jail_status(JAIL_STATUS_EMPTY)
    assert js.name == "nginx-http-auth"
    assert js.current_ban == 0
    assert js.total_banned == 0
    assert js.banned_ips == []
    print(f"  name={js.name}, bans=0, ips=[]: PASS")

    print("\n=== Тест parse_banned_ips ===")
    ips = parse_banned_ips(BANNED_OUTPUT)
    assert len(ips) == 3
    assert "1.2.3.4" in ips
    print(f"  ips={ips}: PASS")

    print("\n=== Тест parse_banned_ips (empty) ===")
    ips = parse_banned_ips(BANNED_EMPTY)
    assert ips == []
    print("  empty: PASS")

    print("\nВсе тесты пройдены")
