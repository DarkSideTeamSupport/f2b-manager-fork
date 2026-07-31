"""
f2b_manager.storage.models
==========================

Глобальные модели данных и контракты интерфейсов.

Этот файл — «контрактный слой» всего проекта: все общие между модулями типы данных
и интерфейсы Protocol определены здесь. При разработке других модулей
(fail2ban/, telegram_bot/, monitor/, notify/) следует строго опираться на
сигнатуры типов отсюда, а не на конкретные реализации.

На этапе разработки незавершённые зависимые модули можно заменять Mock-реализациями.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable


# ──────────────────────────────────────────────
# Перечисления
# ──────────────────────────────────────────────

class Distro(str, Enum):
    """Тип дистрибутива Linux"""
    DEBIAN = "debian"
    UBUNTU = "ubuntu"
    CENTOS = "centos"
    RHEL = "rhel"
    ROCKY = "rocky"
    ALMA = "alma"
    FEDORA = "fedora"
    ALPINE = "alpine"
    ARCH = "arch"
    UNKNOWN = "unknown"


class PackageManager(str, Enum):
    """Тип менеджера пакетов"""
    APT = "apt"
    DNF = "dnf"
    YUM = "yum"
    APK = "apk"
    PACMAN = "pacman"
    UNKNOWN = "unknown"


class BanAction(str, Enum):
    """Тип действия бана"""
    BAN = "ban"
    UNBAN = "unban"
    START = "start"
    STOP = "stop"


class AuthLevel(int, Enum):
    """Уровень прав пользователя Telegram (чем больше значение, тем выше права)"""
    VIEWER = 1     # Только /start /help
    OPERATOR = 2   # Запросы + отчёты + переключение уведомлений
    ADMIN = 3      # Все операции: установка/удаление/обновление/бан


class ServiceState(str, Enum):
    """Состояние работы службы fail2ban"""
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


# ──────────────────────────────────────────────
# Модели данных (dataclass)
# ──────────────────────────────────────────────

@dataclass
class DistroInfo:
    """Информация о дистрибутиве"""
    distro: Distro
    version: str
    package_manager: PackageManager


@dataclass
class Fail2banStatus:
    """Общее состояние fail2ban"""
    version: str = ""
    state: ServiceState = ServiceState.UNKNOWN
    jail_count: int = 0
    total_bans: int = 0
    uptime: str = ""


@dataclass
class JailInfo:
    """Базовая информация об одном jail"""
    name: str
    enabled: bool = True
    current_ban: int = 0
    total_failed: int = 0
    total_banned: int = 0


@dataclass
class JailStatus(JailInfo):
    """Подробное состояние jail (включая список заблокированных IP)"""
    banned_ips: list[str] = field(default_factory=list)
    findtime: str = ""
    bantime: str = ""
    maxretry: int = 0


@dataclass
class BanEvent:
    """Событие бана/разбана (получается из fail2ban action hook)"""
    ip: str
    jail: str
    action: BanAction
    failures: int = 0
    matches: str = ""
    country: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class InstallResult:
    """Результат операции установки/удаления/обновления"""
    success: bool
    message: str = ""
    version: str = ""
    old_version: str = ""
    details: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0


@dataclass
class DailyStat:
    """Ежедневная статистика банов"""
    date: str
    total_bans: int = 0
    unique_ips: int = 0
    top_country: str = ""


@dataclass
class BanChange:
    """Изменения банов, обнаруженные при опросе и сравнении"""
    added: list[tuple[str, str]] = field(default_factory=list)   # [(ip, jail), ...]
    removed: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class GeoInfo:
    """Информация о геолокации IP"""
    country: str = ""
    country_code: str = ""
    flag: str = ""


# ──────────────────────────────────────────────
# Контракты интерфейсов Protocol
# ──────────────────────────────────────────────

@runtime_checkable
class IFail2banManager(Protocol):
    """Интерфейс управления fail2ban в runtime (реализация M1)"""

    def get_status(self) -> Fail2banStatus:
        """Получить общее состояние fail2ban"""
        ...

    def get_jails(self) -> list[JailInfo]:
        """Получить список всех включённых jail"""
        ...

    def get_jail_status(self, jail: str) -> JailStatus:
        """Получить подробное состояние указанного jail"""
        ...

    def get_banned_ips(self) -> list[str]:
        """Получить IP, заблокированные во всех jail"""
        ...

    def ban_ip(self, ip: str, jail: str = "sshd") -> bool:
        """Заблокировать IP вручную"""
        ...

    def unban_ip(self, ip: str) -> bool:
        """Разблокировать IP"""
        ...

    def reload(self) -> bool:
        """Перезагрузить конфигурацию fail2ban"""
        ...


@runtime_checkable
class IFail2banInstaller(Protocol):
    """Интерфейс установки/удаления/обновления fail2ban (реализация M1)"""

    def install(self) -> InstallResult:
        """Установить fail2ban"""
        ...

    def uninstall(self, keep_config: bool = True) -> InstallResult:
        """Удалить fail2ban"""
        ...

    def update(self) -> InstallResult:
        """Обновить fail2ban"""
        ...


@runtime_checkable
class IMessageSender(Protocol):
    """Интерфейс отправки сообщений (реализация M2 Bot, вызов из M3/M4)"""

    async def send_alert(self, chat_id: int, message: str,
                         parse_mode: str = "HTML") -> bool:
        """Отправить предупреждающее сообщение"""
        ...

    async def send_report(self, chat_id: int, message: str) -> bool:
        """Отправить сообщение с отчётом"""
        ...


@runtime_checkable
class IAlertSender(Protocol):
    """Интерфейс отправки оповещений в реальном времени (реализация M3, вызов из M4)"""

    async def send_ban_alert(self, event: BanEvent) -> bool:
        """Отправить оповещение о бане"""
        ...

    async def send_service_alert(self, action: BanAction, jail: str = "") -> bool:
        """Отправить уведомление о запуске/остановке службы"""
        ...


@runtime_checkable
class IStateDB(Protocol):
    """Интерфейс БД состояния (реализация в storage/database.py)"""

    def record_ban(self, event: BanEvent) -> None:
        """Записать событие бана в таблицу истории"""
        ...

    def get_current_bans(self) -> list[tuple[str, str]]:
        """Получить текущий снимок банов [(ip, jail), ...]"""
        ...

    def set_current_bans(self, bans: list[tuple[str, str]]) -> None:
        """Обновить текущий снимок банов"""
        ...

    def get_ban_history(self, days: int = 7) -> list[BanEvent]:
        """Запросить историю банов за последние N дней"""
        ...

    def get_daily_stats(self, days: int = 7) -> list[DailyStat]:
        """Запросить ежедневную статистику"""
        ...

    def set_config_override(self, key: str, value: str) -> None:
        """Установить переопределение конфигурации"""
        ...

    def get_config_override(self, key: str, default: str = "") -> str:
        """Прочитать переопределение конфигурации"""
        ...


@runtime_checkable
class IReporter(Protocol):
    """Интерфейс формирования отчётов (реализация M4)"""

    def daily_report(self) -> str:
        """Сформировать текст ежедневного отчёта"""
        ...

    def weekly_report(self) -> str:
        """Сформировать текст еженедельного отчёта"""
        ...

    def instant_report(self) -> str:
        """Сформировать текст мгновенного отчёта"""
        ...
