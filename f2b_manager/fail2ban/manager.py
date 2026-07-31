"""
f2b_manager.fail2ban.manager
=============================

Менеджер runtime fail2ban.

Реализует интерфейс IFail2banManager: через run_command() вызывает fail2ban-client
для получения и изменения состояния fail2ban. Все методы с полной обработкой ошибок и логированием.

Примечание: модуль не проверяет доступность fail2ban при импорте — только при вызове методов.
Импорт в среде без fail2ban (например, macOS) не падает; при вызове методов выбрасывается исключение.
"""

from __future__ import annotations

import datetime
import subprocess
from typing import Optional

from ..storage.models import (
    Fail2banStatus,
    JailInfo,
    JailStatus,
    ServiceState,
)
from ..utils.shell import run_command, which
from ..utils.logger import get_logger
from .parser import (
    parse_status,
    parse_jail_status,
    parse_banned_ips,
    parse_jail_list,
    parse_version,
)

_logger = get_logger(__name__)

# Путь к исполняемому файлу fail2ban-client
_F2B_CLIENT = "fail2ban-client"


def _get_service_uptime(service: str) -> str:
    """Получить время работы службы systemd.

    Args:
        service: имя службы systemd

    Returns:
        Строка времени работы в удобочитаемом виде (например, «2h 30m»);
        при ошибке — пустая строка
    """
    try:
        r = subprocess.run(
            ["systemctl", "show", service, "--property=ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return ""

        # Формат: ActiveEnterTimestamp=Sun 2026-07-12 01:06:55 CST
        line = r.stdout.strip()
        if "=" not in line:
            return ""
        ts_str = line.split("=", 1)[1].strip()

        # Разбор метки времени
        # Формат вывода systemd: «Day YYYY-MM-DD HH:MM:SS TZ»
        # или «YYYY-MM-DD HH:MM:SS TZ»
        try:
            # Пробуем несколько форматов
            for fmt in ("%a %Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S %Z"):
                try:
                    start = datetime.datetime.strptime(ts_str, fmt)
                    # systemd возвращает локальное время; strptime по умолчанию
                    # создаёт naive datetime — требуется обработка
                    now = datetime.datetime.now()
                    delta = now - start
                    break
                except ValueError:
                    continue
            else:
                return ""

            # Форматирование в удобочитаемый вид
            if delta.days > 0:
                return f"{delta.days}d {delta.seconds // 3600}h"
            hours = delta.seconds // 3600
            mins = (delta.seconds % 3600) // 60
            if hours > 0:
                return f"{hours}h {mins}m"
            return f"{mins}m"
        except Exception:
            return ""
    except Exception:
        return ""


class Fail2banNotAvailableError(RuntimeError):
    """Выбрасывается, когда fail2ban-client недоступен."""

    def __init__(self, msg: str = "fail2ban-client не установлен или недоступен"):
        super().__init__(msg)


class Fail2banManager:
    """Управление runtime fail2ban.

    Все операции выполняются через вызов команды fail2ban-client.

    Usage:
        mgr = Fail2banManager()
        status = mgr.get_status()
        jails = mgr.get_jails()
        detail = mgr.get_jail_status("sshd")
    """

    def __init__(self, client_path: Optional[str] = None):
        """Инициализация менеджера.

        Args:
            client_path: путь к fail2ban-client; по умолчанию определяется автоматически
        """
        self._client = client_path or _F2B_CLIENT

    # ── Внутренние методы ──────────────────────────────

    def _run(self, *args: str, timeout: int = 30) -> str:
        """Выполнить команду fail2ban-client и вернуть stdout.

        Args:
            *args: аргументы команды
            timeout: таймаут в секундах

        Returns:
            stdout команды

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
            subprocess.CalledProcessError: команда завершилась с ошибкой
        """
        cmd = [self._client, *args]
        _logger.debug("Выполнение команды: %s", " ".join(cmd))
        result = run_command(cmd, timeout=timeout, check=False)

        if not result.success:
            # Проверка: fail2ban-client не найден
            if "not found" in result.stderr.lower() or \
               "no such file" in result.stderr.lower():
                raise Fail2banNotAvailableError(
                    f"fail2ban-client не установлен: {result.stderr}"
                )
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        return result.stdout

    def _verify_available(self) -> None:
        """Проверить доступность fail2ban-client.

        Raises:
            Fail2banNotAvailableError: если клиент недоступен
        """
        path = which(self._client)
        if path is None:
            raise Fail2banNotAvailableError(
                f"Не найден {self._client}, убедитесь, что fail2ban установлен"
            )

    # ── Реализация интерфейса IFail2banManager ─────────────

    def get_status(self) -> Fail2banStatus:
        """Получить общий статус fail2ban.

        Выполняет три команды fail2ban-client: version, status и banned;
        результат агрегируется в Fail2banStatus.

        Returns:
            Fail2banStatus: версия, состояние службы, число jail, общее число банов

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
        """
        self._verify_available()
        status = Fail2banStatus()

        try:
            # 1. Получение версии
            version_output = self._run("version")
            status.version = parse_version(version_output)
        except Exception as e:
            _logger.warning("Не удалось получить версию fail2ban: %s", e)
            status.version = "unknown"

        try:
            # 2. Проверка состояния службы (через ping)
            self._run("ping")
            status.state = ServiceState.RUNNING
        except Exception:
            _logger.warning("Служба fail2ban, возможно, не запущена")
            status.state = ServiceState.STOPPED

        # 2a. Время работы
        if status.state == ServiceState.RUNNING:
            status.uptime = _get_service_uptime("fail2ban")

        try:
            # 3. Разбор вывода status: число jail и базовая информация
            raw_status = self._run("status")
            parsed = parse_status(raw_status)
            status.jail_count = parsed.jail_count
            status.total_bans = parsed.total_bans
        except Exception as e:
            _logger.warning("Не удалось получить статус fail2ban: %s", e)

        # 4. Если total_bans не получен из status — пробуем команду banned
        if status.total_bans == 0 and status.state == ServiceState.RUNNING:
            try:
                ips = self.get_banned_ips()
                status.total_bans = len(ips)
            except Exception as e:
                _logger.debug("Не удалось получить список banned IP: %s", e)

        _logger.info("Статус Fail2ban: version=%s state=%s jails=%d bans=%d",
                      status.version, status.state.value,
                      status.jail_count, status.total_bans)
        return status

    def get_jails(self) -> list[JailInfo]:
        """Получить список всех активных jail.

        Выполняет fail2ban-client status и разбирает список jail.

        Returns:
            Список JailInfo (заполнены только поля name и enabled)

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
        """
        self._verify_available()
        try:
            raw = self._run("status")
            jails = parse_jail_list(raw)
            _logger.info("Получен список jail: %s", [j.name for j in jails])

            # Дополняем каждый jail данными о банах и неудачных попытках
            enriched: list[JailInfo] = []
            for jail in jails:
                try:
                    js = self.get_jail_status(jail.name)
                    jail.current_ban = js.current_ban
                    jail.total_failed = js.total_failed
                    jail.total_banned = js.total_banned
                except Exception as e:
                    _logger.warning("Не удалось получить статус jail '%s': %s", jail.name, e)
                enriched.append(jail)
            return enriched

        except Exception as e:
            _logger.error("Не удалось получить список jail: %s", e)
            raise

    def get_jail_status(self, jail: str) -> JailStatus:
        """Получить подробный статус указанного jail.

        Выполняет fail2ban-client status <jail> и разбирает вывод.

        Args:
            jail: имя jail

        Returns:
            JailStatus: список заблокированных IP, число неудачных попыток и прочие детали

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
            ValueError: некорректное имя jail
        """
        self._verify_available()
        if not jail or not jail.strip():
            raise ValueError("Имя jail не может быть пустым")

        try:
            raw = self._run("status", jail)
            status = parse_jail_status(raw)
            _logger.info("Статус jail '%s': bans=%d failed=%d ips=%d",
                          jail, status.current_ban,
                          status.total_failed, len(status.banned_ips))
            return status
        except subprocess.CalledProcessError as e:
            _logger.error("Не удалось получить статус jail '%s' (exit=%d): %s",
                          jail, e.returncode, e.stderr)
            raise
        except Exception as e:
            _logger.error("Неизвестная ошибка при получении статуса jail '%s': %s", jail, e)
            raise

    def get_banned_ips(self) -> list[str]:
        """Получить список IP, заблокированных во всех jail.

        Выполняет fail2ban-client banned.

        Returns:
            Список IP-адресов

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
        """
        self._verify_available()
        try:
            raw = self._run("banned")
            ips = parse_banned_ips(raw)
            _logger.info("Получен список заблокированных IP: %d адресов", len(ips))
            return ips
        except Exception as e:
            _logger.error("Не удалось получить список заблокированных IP: %s", e)
            raise

    def ban_ip(self, ip: str, jail: str = "sshd") -> bool:
        """Заблокировать IP вручную.

        Выполняет fail2ban-client set <jail> banip <ip>.

        Args:
            ip: IP-адрес для блокировки
            jail: целевой jail, по умолчанию sshd

        Returns:
            True, если операция успешна

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
            ValueError: некорректный IP или имя jail
        """
        self._verify_available()
        if not ip or not ip.strip():
            raise ValueError("IP-адрес не может быть пустым")
        if not jail or not jail.strip():
            raise ValueError("Имя jail не может быть пустым")

        try:
            self._run("set", jail, "banip", ip)
            _logger.info("IP заблокирован вручную: %s (jail=%s)", ip, jail)
            return True
        except Exception as e:
            _logger.error("Не удалось заблокировать IP '%s' (jail=%s): %s", ip, jail, e)
            return False

    def unban_ip(self, ip: str) -> bool:
        """Разблокировать IP.

        Выполняет fail2ban-client unban <ip>.

        Args:
            ip: IP-адрес для разблокировки

        Returns:
            True, если операция успешна

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
            ValueError: некорректный IP-адрес
        """
        self._verify_available()
        if not ip or not ip.strip():
            raise ValueError("IP-адрес не может быть пустым")

        try:
            self._run("unban", ip)
            _logger.info("IP разблокирован: %s", ip)
            return True
        except Exception as e:
            _logger.error("Не удалось разблокировать IP '%s': %s", ip, e)
            return False

    def reload(self) -> bool:
        """Перезагрузить конфигурацию fail2ban.

        Выполняет fail2ban-client reload.

        Returns:
            True, если операция успешна

        Raises:
            Fail2banNotAvailableError: fail2ban-client недоступен
        """
        self._verify_available()
        try:
            self._run("reload", timeout=60)
            _logger.info("Конфигурация fail2ban перезагружена")
            return True
        except Exception as e:
            _logger.error("Не удалось перезагрузить конфигурацию fail2ban: %s", e)
            return False


# ──────────────────────────────────────────────
# Самопроверка (нужна среда с fail2ban; здесь — только проверка импорта)
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Проверка импорта Fail2banManager ===")
    mgr = Fail2banManager()
    print(f"Экземпляр создан: {mgr}")

    try:
        status = mgr.get_status()
        print(f"Статус: {status}")
    except Fail2banNotAvailableError:
        print("fail2ban недоступен (ожидаемо: не Linux или не установлен)")
        print("Импорт без ошибок; исключение только при вызове — ожидаемое поведение")
