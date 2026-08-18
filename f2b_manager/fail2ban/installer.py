"""
f2b_manager.fail2ban.installer
===============================

Установщик Fail2ban: установка, удаление и обновление.

Реализует интерфейс IFail2banInstaller и отвечает за полный жизненный цикл fail2ban:
- Установка: определение дистрибутива → установка через пакетный менеджер → генерация конфигурации → развёртывание action → включение systemd
- Удаление: остановка службы → отключение → удаление пакета → резервное копирование конфигурации (опционально)
- Обновление: фиксация старой версии → обновление пакета → перезапуск → фиксация новой версии

Все методы с полной обработкой ошибок и логированием.
"""

from __future__ import annotations

import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Union

from ..config import AppConfig, Fail2banConfig
from ..storage.models import InstallResult, DistroInfo
from ..utils.distro import (
    detect_distro,
    get_install_command,
    get_remove_command,
    get_upgrade_command,
    PackageManager,
)
from ..utils.shell import run_command, which
from ..utils.logger import get_logger
from .config_builder import JailConfigBuilder

_logger = get_logger(__name__)

# Константы путей развёртывания
_FAIL2BAN_ACTION_DIR = "/etc/fail2ban/action.d"
_FAIL2BAN_JAIL_LOCAL = "/etc/fail2ban/jail.local"
_FAIL2BAN_CONFIG_DIR = "/etc/fail2ban"
_NOTIFY_SCRIPT_PATH = "/usr/local/bin/f2b-notify.sh"
_PACKAGE_NAME = "fail2ban"


class InstallError(RuntimeError):
    """Выбрасывается при ошибке установки, удаления или обновления."""
    pass


class Fail2banInstaller:
    """Установщик Fail2ban.

    Usage:
        cfg = Fail2banConfig(...)
        installer = Fail2banInstaller(cfg)
        result = installer.install()
    """

    # Каталоги, необходимые при развёртывании
    _REQUIRED_DIRS = [
        _FAIL2BAN_ACTION_DIR,
        _FAIL2BAN_CONFIG_DIR,
        Path(_NOTIFY_SCRIPT_PATH).parent,
    ]

    def __init__(self, config: Union[Fail2banConfig, AppConfig]):
        if isinstance(config, AppConfig):
            config = config.fail2ban
        self._config = config
        self._builder = JailConfigBuilder(config)
        self._distro_info: DistroInfo | None = None

    # ── Внутренние вспомогательные методы ──────────────────────────

    def _get_distro(self) -> DistroInfo:
        """Получить информацию о дистрибутиве (с кешированием)."""
        if self._distro_info is None:
            self._distro_info = detect_distro()
            _logger.info("Обнаружен дистрибутив: distro=%s version=%s pkg=%s",
                          self._distro_info.distro.value,
                          self._distro_info.version,
                          self._distro_info.package_manager.value)
        return self._distro_info

    def _is_installed(self) -> bool:
        """Проверить, установлен ли fail2ban."""
        # Проверить наличие fail2ban-server и fail2ban-client
        server = which("fail2ban-server")
        client = which("fail2ban-client")
        return server is not None and client is not None

    def _get_f2b_version(self) -> str:
        """Получить версию установленного fail2ban; при ошибке — до 3 попыток."""
        from .parser import parse_version
        for attempt in range(3):
            try:
                result = run_command("fail2ban-client version", timeout=10, check=False)
                if result.success:
                    ver = parse_version(result.stdout)
                    if ver:
                        return ver
            except Exception as e:
                _logger.warning("Не удалось получить версию fail2ban (попытка %d/3): %s", attempt + 1, e)
            if attempt < 2:
                time.sleep(1)
        return "unknown"

    def _run_systemctl(self, action: str, service: str = "fail2ban") -> bool:
        """Выполнить команду systemctl.

        Args:
            action: действие systemctl (start/stop/enable/disable/restart/daemon-reload)
            service: имя службы

        Returns:
            True, если команда выполнена успешно
        """
        cmd = f"systemctl {action} {service}"
        _logger.info("Выполнение: %s", cmd)
        result = run_command(cmd, timeout=60, check=False)
        if not result.success:
            _logger.warning("systemctl %s %s завершился с ошибкой: %s", action, service, result.stderr)
        return result.success

    def _ensure_dirs(self) -> None:
        """Убедиться, что каталоги для развёртывания существуют."""
        for d in self._REQUIRED_DIRS:
            try:
                Path(d).mkdir(parents=True, exist_ok=True)
                _logger.debug("Каталог готов: %s", d)
            except (PermissionError, OSError) as e:
                _logger.warning("Не удалось создать каталог %s: %s", d, e)

    def _write_file(self, path: str, content: str, mode: int = 0o644) -> bool:
        """Записать файл, автоматически создав родительские каталоги.

        Args:
            path: путь к файлу
            content: содержимое файла
            mode: права доступа

        Returns:
            True, если запись выполнена успешно
        """
        try:
            filepath = Path(path)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content, encoding="utf-8")
            filepath.chmod(mode)
            _logger.info("Файл записан: %s (права %o)", path, mode)
            return True
        except (PermissionError, OSError) as e:
            _logger.error("Не удалось записать файл %s: %s", path, e)
            return False

    def _backup_config(self) -> str:
        """Создать резервную копию каталога /etc/fail2ban.

        Returns:
            Путь к каталогу резервной копии
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        src = Path(_FAIL2BAN_CONFIG_DIR)
        dst = Path(f"{_FAIL2BAN_CONFIG_DIR}.backup.{timestamp}")

        if not src.exists():
            _logger.info("Каталог конфигурации %s не существует, резервное копирование пропущено", src)
            return ""

        try:
            shutil.copytree(src, dst, symlinks=True)
            _logger.info("Конфигурация сохранена в резервной копии: %s", dst)
            return str(dst)
        except (OSError, shutil.Error) as e:
            _logger.warning("Не удалось создать резервную копию конфигурации: %s", e)
            return ""

    def _cleanup_f2b_manager_files(self) -> None:
        """Удалить файлы fail2ban, развёрнутые f2b-manager."""
        files_to_remove = [
            _FAIL2BAN_JAIL_LOCAL,
            os.path.join(_FAIL2BAN_ACTION_DIR, "telegram-notify.conf"),
        ]
        for f in files_to_remove:
            try:
                path = Path(f)
                if path.exists():
                    path.unlink()
                    _logger.info("Удалён: %s", f)
            except OSError as e:
                _logger.warning("Не удалось удалить %s: %s", f, e)

    # ── Реализация интерфейса IFail2banInstaller ───────────

    def install(self) -> InstallResult:
        """Установить fail2ban.

        Полный процесс установки:
        1. Проверить, установлен ли fail2ban
        2. Определить дистрибутив
        3. Установить fail2ban через пакетный менеджер
        4. Сгенерировать jail.local
        5. Развернуть конфигурацию action telegram-notify
        6. Развернуть скрипт-мост notify.sh
        7. systemctl enable --now fail2ban
        8. Проверить fail2ban-client ping

        Returns:
            InstallResult: результат установки
        """
        start_time = time.monotonic()
        details: list[str] = []

        # Шаг 1: проверить, установлен ли fail2ban
        if self._is_installed():
            version = self._get_f2b_version()
            _logger.info("fail2ban уже установлен (версия %s), установка пропущена", version)
            return InstallResult(
                success=True,
                message=f"fail2ban уже установлен (версия {version})",
                version=version,
                details=["fail2ban уже установлен, установка пропущена"],
                elapsed_seconds=round(time.monotonic() - start_time, 1),
            )

        # Шаг 2: определить дистрибутив
        distro = self._get_distro()
        if distro.package_manager == PackageManager.UNKNOWN:
            return InstallResult(
                success=False,
                message=f"Неподдерживаемый дистрибутив: {distro.distro.value}",
                details=["Не удалось определить пакетный менеджер"],
                elapsed_seconds=round(time.monotonic() - start_time, 1),
            )

        # Шаг 3: установить пакет
        install_cmd = get_install_command(distro.package_manager, _PACKAGE_NAME)
        _logger.info("Начало установки fail2ban: %s", install_cmd)
        details.append(f"Дистрибутив: {distro.distro.value} ({distro.version})")
        details.append(f"Пакетный менеджер: {distro.package_manager.value}")

        # Для APT сначала обновить индекс пакетов
        if distro.package_manager == PackageManager.APT:
            _logger.info("Обновление индекса APT: apt-get update")
            run_command("apt-get update", timeout=120, check=False)

        result = run_command(install_cmd, timeout=300, check=False)
        if not result.success:
            _logger.error("Установка fail2ban не удалась: %s", result.stderr)
            return InstallResult(
                success=False,
                message=f"Ошибка установки: {result.stderr[:200]}",
                details=details + [f"Ошибка: {result.stderr}"],
                elapsed_seconds=round(time.monotonic() - start_time, 1),
            )
        details.append("Пакет успешно установлен")

        # Шаг 4: сгенерировать и развернуть jail.local
        self._ensure_dirs()
        jail_content = self._builder.generate_jail_local()
        if self._write_file(_FAIL2BAN_JAIL_LOCAL, jail_content, mode=0o644):
            details.append(f"jail.local развёрнут в {_FAIL2BAN_JAIL_LOCAL}")
        else:
            details.append("⚠ Не удалось развернуть jail.local")

        # Шаг 5: развернуть конфигурацию action telegram-notify
        action_content = self._builder.generate_telegram_action()
        action_path = os.path.join(_FAIL2BAN_ACTION_DIR, "telegram-notify.conf")
        if self._write_file(action_path, action_content, mode=0o644):
            details.append(f"action telegram-notify развёрнут в {action_path}")
        else:
            details.append("⚠ Не удалось развернуть action telegram-notify")

        # Шаг 6: развернуть скрипт-мост notify.sh
        notify_content = self._builder.generate_notify_script()
        if self._write_file(_NOTIFY_SCRIPT_PATH, notify_content, mode=0o755):
            details.append(f"notify.sh развёрнут в {_NOTIFY_SCRIPT_PATH}")
        else:
            details.append("⚠ Не удалось развернуть notify.sh")

        # Шаг 7: systemctl enable --now
        self._run_systemctl("enable", "fail2ban")
        if self._run_systemctl("start", "fail2ban"):
            details.append("Служба fail2ban запущена и добавлена в автозагрузку")
        else:
            # Попробовать restart вместо start
            self._run_systemctl("restart", "fail2ban")
            details.append("Служба fail2ban включена (запуск может занять время)")

        # Шаг 8: проверка
        version = "unknown"
        try:
            time.sleep(1)  # Дождаться полного запуска службы
            ping = run_command("fail2ban-client ping", timeout=10, check=False)
            if ping.success:
                version = self._get_f2b_version()
                details.append(f"Проверка успешна: fail2ban v{version} работает")
            else:
                details.append("⚠ Проверка fail2ban ping не пройдена, проверьте журнал")
        except Exception as e:
            details.append(f"⚠ Ошибка при проверке: {e}")

        elapsed = round(time.monotonic() - start_time, 1)
        _logger.info("Установка fail2ban завершена (%.1fs)", elapsed)
        return InstallResult(
            success=True,
            message=f"fail2ban v{version} успешно установлен",
            version=version,
            details=details,
            elapsed_seconds=elapsed,
        )

    def uninstall(self, keep_config: bool = True) -> InstallResult:
        """Удалить fail2ban.

        Процесс удаления:
        1. systemctl stop fail2ban
        2. systemctl disable fail2ban
        3. Резервное копирование конфигурации (если keep_config=True)
        4. Удаление через пакетный менеджер
        5. Очистка конфигурационных файлов, развёрнутых f2b-manager

        Args:
            keep_config: сохранять ли резервную копию конфигурации

        Returns:
            InstallResult: результат удаления
        """
        start_time = time.monotonic()
        details: list[str] = []

        if not self._is_installed():
            _logger.info("fail2ban не установлен, удаление пропущено")
            return InstallResult(
                success=True,
                message="fail2ban не установлен",
                details=["fail2ban не установлен, удаление не требуется"],
                elapsed_seconds=round(time.monotonic() - start_time, 1),
            )

        version = self._get_f2b_version()
        details.append(f"Текущая версия: {version}")

        # Шаг 1+2: остановить и отключить службу
        self._run_systemctl("stop", "fail2ban")
        details.append("Служба fail2ban остановлена")
        self._run_systemctl("disable", "fail2ban")
        details.append("Автозагрузка fail2ban отключена")

        # Шаг 3: резервное копирование конфигурации
        backup_path = ""
        if keep_config:
            backup_path = self._backup_config()
            if backup_path:
                details.append(f"Конфигурация сохранена в резервной копии: {backup_path}")
            else:
                details.append("⚠ Резервное копирование не выполнено или каталог конфигурации отсутствует")

        # Шаг 4: удалить пакет
        distro = self._get_distro()
        if distro.package_manager != PackageManager.UNKNOWN:
            remove_cmd = get_remove_command(distro.package_manager, _PACKAGE_NAME)
            _logger.info("Удаление fail2ban: %s", remove_cmd)

            result = run_command(remove_cmd, timeout=120, check=False)
            if result.success:
                details.append("Пакет успешно удалён")
            else:
                details.append(f"⚠ Удаление пакета могло выполниться не полностью: {result.stderr[:200]}")
        else:
            details.append("⚠ Не удалось определить пакетный менеджер, удалите fail2ban вручную")

        # Шаг 5: очистить файлы, развёрнутые f2b-manager
        self._cleanup_f2b_manager_files()
        details.append("Файлы конфигурации f2b-manager удалены")

        elapsed = round(time.monotonic() - start_time, 1)
        _logger.info("Удаление fail2ban завершено (%.1fs)", elapsed)
        return InstallResult(
            success=True,
            message=f"fail2ban v{version} удалён"
            + (f", резервная копия конфигурации: {backup_path}" if backup_path else ""),
            version="",
            details=details,
            elapsed_seconds=elapsed,
        )

    def update(self) -> InstallResult:
        """Обновить fail2ban.

        Процесс обновления:
        1. Зафиксировать текущую версию
        2. Проверить, установлен ли fail2ban
        3. Обновить через пакетный менеджер
        4. Перезапустить службу fail2ban
        5. Зафиксировать новую версию

        Returns:
            InstallResult: результат обновления с информацией об изменении версии
        """
        start_time = time.monotonic()
        details: list[str] = []

        # Шаг 1: зафиксировать текущую версию
        if not self._is_installed():
            _logger.warning("fail2ban не установлен, обновление невозможно")
            return InstallResult(
                success=False,
                message="fail2ban не установлен, сначала выполните установку",
                details=["fail2ban не установлен"],
                elapsed_seconds=round(time.monotonic() - start_time, 1),
            )

        old_version = self._get_f2b_version()
        details.append(f"Версия до обновления: {old_version}")

        # Шаг 2: определить дистрибутив
        distro = self._get_distro()
        if distro.package_manager == PackageManager.UNKNOWN:
            return InstallResult(
                success=False,
                message=f"Неподдерживаемый дистрибутив: {distro.distro.value}",
                details=["Не удалось определить пакетный менеджер"],
                elapsed_seconds=round(time.monotonic() - start_time, 1),
            )

        # Шаг 3: выполнить обновление
        upgrade_cmd = get_upgrade_command(distro.package_manager, _PACKAGE_NAME)
        _logger.info("Обновление fail2ban: %s", upgrade_cmd)

        # Для APT сначала обновить индекс пакетов
        if distro.package_manager == PackageManager.APT:
            _logger.info("Обновление индекса APT: apt-get update")
            run_command("apt-get update", timeout=120, check=False)

        result = run_command(upgrade_cmd, timeout=300, check=False)
        if not result.success:
            _logger.error("Обновление fail2ban не удалось: %s", result.stderr)
            return InstallResult(
                success=False,
                message=f"Ошибка обновления: {result.stderr[:200]}",
                details=details + [f"Ошибка: {result.stderr}"],
                elapsed_seconds=round(time.monotonic() - start_time, 1),
            )

        # Шаг 4: перезапустить службу
        self._run_systemctl("restart", "fail2ban")
        details.append("Служба fail2ban перезапущена")
        time.sleep(1)  # Дождаться стабильного запуска службы

        # Шаг 5: зафиксировать новую версию
        new_version = self._get_f2b_version()
        details.append(f"Версия после обновления: {new_version}")

        if old_version != new_version:
            details.append(f"Изменение версии: {old_version} → {new_version}")
        else:
            details.append("Версия не изменилась (уже установлена актуальная)")

        elapsed = round(time.monotonic() - start_time, 1)
        _logger.info("Обновление fail2ban завершено: %s → %s (%.1fs)",
                      old_version, new_version, elapsed)

        return InstallResult(
            success=True,
            message=f"Обновление fail2ban завершено: {old_version} → {new_version}",
            version=new_version,
            old_version=old_version,
            details=details,
            elapsed_seconds=elapsed,
        )


# ──────────────────────────────────────────────
# Самопроверка (только проверка импорта)
# ──────────────────────────────────────────────

if __name__ == "__main__":
    from ..config import Fail2banConfig

    print("=== Проверка импорта Fail2banInstaller ===")
    cfg = Fail2banConfig()
    installer = Fail2banInstaller(cfg)
    print(f"Экземпляр создан: {installer}")

    if installer._is_installed():
        print(f"fail2ban установлен, версия: {installer._get_f2b_version()}")
    else:
        print("fail2ban не установлен (ожидаемо для среды без Linux)")
        print("✅ Импорт прошёл без ошибок, как и ожидалось")
