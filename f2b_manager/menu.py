"""
f2b_manager.menu
================

Интерактивное меню управления.

Меню с числовым выбором для начинающих пользователей VPS, оформленное
ANSI-цветами. Поддерживает установку/удаление/обновление fail2ban, настройку
Telegram-бота, просмотр состояния, управление блокировками IP, службами и журналами.

Использование:
    from f2b_manager.menu import InteractiveMenu
    menu = InteractiveMenu(config_path="/etc/f2b-manager/config.yaml")
    menu.run()
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from typing import Optional

import httpx

from . import __version__ as LOCAL_VERSION

# ── ANSI-коды цветов ──────────────────────────────────
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[0;31m"
C_GREEN = "\033[0;32m"
C_YELLOW = "\033[1;33m"
C_BLUE = "\033[0;34m"
C_CYAN = "\033[0;36m"
C_MAGENTA = "\033[0;35m"
C_BG_RED = "\033[41m"
C_BG_GREEN = "\033[42m"

# Ширина терминала
_TERM_WIDTH = 70

def _print_separator(char: str = "─", color: str = C_DIM) -> None:
    """Выводит разделительную линию."""
    print(f"{color}{char * _TERM_WIDTH}{C_RESET}")


def _print_header(title: str) -> None:
    """Выводит заголовок голубого цвета."""
    print()
    _print_separator("═", C_CYAN)
    # Центрирование заголовка и номера версии
    pad = max(0, (_TERM_WIDTH - len(title)) // 2)
    print(f"{C_CYAN}{' ' * pad}{C_BOLD}{title}{C_RESET}")
    _print_separator("═", C_CYAN)
    print()


def _print_success(msg: str) -> None:
    """Выводит сообщение об успехе."""
    print(f"  {C_GREEN}✓ {msg}{C_RESET}")


def _print_error(msg: str) -> None:
    """Выводит сообщение об ошибке."""
    print(f"  {C_RED}✗ {msg}{C_RESET}")


def _print_warning(msg: str) -> None:
    """Выводит предупреждение."""
    print(f"  {C_YELLOW}⚠ {msg}{C_RESET}")


def _print_info(msg: str) -> None:
    """Выводит информационное сообщение."""
    print(f"  {C_CYAN}ℹ {msg}{C_RESET}")


def _clear_screen() -> None:
    """Очищает экран в различных терминалах."""
    os.system("clear")
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def _read_input(prompt: str, default: str = "") -> str:
    """Считывает ввод пользователя; пустой ввод возвращает значение по умолчанию."""
    if default:
        raw = input(f"  {prompt} [{default}]: ")
        return raw if raw.strip() else default
    return input(f"  {prompt}: ")


def _read_choice(prompt: str, choices: list[str], default: int = 0) -> int:
    """Считывает числовой выбор и возвращает индекс (с нуля).

    Ввод 1–N соответствует вариантам с 1-го по N-й.
    Ввод 0 соответствует последнему варианту (для «Назад/Выход»).
    """
    while True:
        raw = _read_input(prompt).strip()
        if not raw:
            return default
        # Поддержка буквенных горячих клавиш
        raw_upper = raw.upper()
        for i, c in enumerate(choices):
            if c == raw or (c.isalpha() and c == raw_upper):
                return i
        try:
            num = int(raw)
            if num == 0:
                return len(choices) - 1  # 0 = последний пункт («Назад/Выход»)
            idx = num - 1  # отсчёт с 1 → отсчёт с 0
            if 0 <= idx < len(choices):
                return idx
            _print_error(f"Введите число от 0 до {len(choices)}")
        except ValueError:
            _print_error("Введите корректное число")


def _confirm(prompt: str) -> bool:
    """Запрашивает подтверждение и возвращает True/False."""
    raw = _read_input(f"{prompt} (y/n)", "n").strip().lower()
    return raw in ("y", "yes", "да")


def _compare_versions(a: str, b: str) -> int:
    """Сравнивает два номера версий.

    Returns:
        1 (a > b), -1 (a < b), 0 (равны)
    """
    try:
        from packaging.version import Version
        return (Version(a) > Version(b)) - (Version(a) < Version(b))
    except ImportError:
        # Упрощённое сравнение по числовым компонентам
        def _parse(v):
            return [int(x) for x in re.findall(r"\d+", v)]
        pa, pb = _parse(a), _parse(b)
        return (pa > pb) - (pa < pb)


def _check_pkg_update(package: str) -> tuple[str, bool]:
    """Проверяет доступные обновления пакета через менеджер пакетов.

    Returns:
        (available_version, has_update)
    """
    try:
        # APT (Debian/Ubuntu)
        r = subprocess.run(
            ["apt-cache", "policy", package],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            installed = ""
            candidate = ""
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("Installed:"):
                    installed = line.split(":", 1)[1].strip()
                    if installed == "(none)":
                        installed = ""
                elif line.startswith("Candidate:"):
                    candidate = line.split(":", 1)[1].strip()
            if installed and candidate and installed != candidate:
                # Удаление префикса epoch (например, 1:1.1.0-1 → 1.1.0-1)
                installed = installed.split(":", 1)[-1] if ":" in installed else installed
                candidate = candidate.split(":", 1)[-1] if ":" in candidate else candidate
                return candidate, _compare_versions(installed, candidate) < 0
            return candidate, False
    except Exception:
        pass

    try:
        # DNF (CentOS/RHEL/Rocky/Fedora)
        r = subprocess.run(
            ["dnf", "list", "available", package],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith(package):
                    return parts[1], True
    except Exception:
        pass

    return "", False


def _get_override(db, key: str, default: str) -> str:
    """Читает переопределённое значение из БД или возвращает значение по умолчанию."""
    if db is None:
        return default
    val = db.get_config_override(key, "")
    return val if val else default


class InteractiveMenu:
    """Интерактивное меню управления.

    Предназначено для начинающих пользователей VPS: все операции выполняются
    числовым выбором, а вывод оформляется ANSI-цветами.
    """

    def __init__(self, config_path: str = "/etc/f2b-manager/config.yaml"):
        self._config_path = config_path
        self._config = None
        self._f2b_manager = None
        self._f2b_installer = None
        # Состояние fail2ban (проверка установки и версии)
        self._f2b_installed: Optional[bool] = None
        self._f2b_version: str = ""
        self._f2b_latest: str = ""
        self._f2b_has_update: bool = False

    # ── Основной цикл ──────────────────────────────

    def run(self) -> None:
        """Запускает основной цикл интерактивного меню."""
        # Загрузка конфигурации
        from .config import load_config
        self._config = load_config(self._config_path)

        # Инициализация модулей fail2ban
        self._init_modules()

        # Проверка состояния и версии fail2ban
        self._check_fail2ban_status()

        while True:
            _clear_screen()
            self._show_main_menu()
            # Особая обработка «0» → выход (в меню отображается [0] Выход)
            raw = _read_input("Выберите действие").strip()
            if raw == "0":
                print()
                print(f"{C_GREEN}  До свидания! Повторно открыть меню можно командами 'f2b' или 'f2b-manager menu'.{C_RESET}")
                print()
                break

            raw_upper = raw.upper()
            # Буквенные горячие клавиши
            if raw_upper == "D":
                self._menu_uninstall_manager()
                continue
            if raw_upper == "C":
                self._menu_f2b_config()
                continue

            try:
                idx = int(raw) - 1  # 1-based → 0-based
            except ValueError:
                _print_error("Введите корректное число")
                _read_input("Нажмите Enter для продолжения")
                continue
            if idx < 0 or idx > 8:
                _print_error("Введите число от 0 до 9 или D/C для управления f2b-manager")
                _read_input("Нажмите Enter для продолжения")
                continue

            choice = idx
            print()

            if choice == 0:
                self._menu_install()
            elif choice == 1:
                self._menu_uninstall()
            elif choice == 2:
                self._menu_update()
            elif choice == 3:
                self._menu_config_telegram()
            elif choice == 4:
                self._menu_status()
            elif choice == 5:
                self._menu_banned_ips()
            elif choice == 6:
                self._menu_ban_manage()
            elif choice == 7:
                self._menu_service_control()
            elif choice == 8:
                self._menu_view_logs()

    def _init_modules(self) -> None:
        """Лениво инициализирует модули fail2ban."""
        # Fail2banManager (не требует параметра config)
        try:
            from .fail2ban.manager import Fail2banManager
            self._f2b_manager = Fail2banManager()
        except ImportError:
            self._f2b_manager = None

        # Fail2banInstaller (требует Fail2banConfig)
        try:
            from .fail2ban.installer import Fail2banInstaller
            self._f2b_installer = Fail2banInstaller(self._config.fail2ban)
        except ImportError:
            self._f2b_installer = None

    def _check_fail2ban_status(self) -> None:
        """Проверяет установку fail2ban, версию и доступные обновления."""
        # 1. Установлен ли пакет
        try:
            from shutil import which
            if which("fail2ban-client"):
                self._f2b_installed = True
                try:
                    result = subprocess.run(
                        ["fail2ban-client", "version"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0:
                        self._f2b_version = result.stdout.strip().splitlines()[0].strip()
                except Exception:
                    self._f2b_version = "?"
            else:
                self._f2b_installed = False
        except Exception:
            self._f2b_installed = False

        if not self._f2b_installed:
            return

        # 2. Проверка доступных обновлений через менеджер пакетов
        self._f2b_latest, self._f2b_has_update = _check_pkg_update("fail2ban")

    def _show_main_menu(self) -> None:
        """Отображает главное меню и сведения о версиях."""
        _print_header("Меню управления f2b-manager")

        # ── Строка версии f2b-manager ──
        print(f"  f2b-manager: {C_GREEN}v{LOCAL_VERSION}{C_RESET}")

        # ── Строка состояния fail2ban ──
        if self._f2b_installed is None:
            pass  # Не проверено
        elif self._f2b_installed:
            f2b_line = f"  fail2ban:    {C_GREEN}установлен{C_RESET}"
            if self._f2b_version:
                f2b_line += f"  v{self._f2b_version}"
            if self._f2b_has_update and self._f2b_latest:
                f2b_line += (
                    f"  {C_YELLOW}{C_BOLD}🆕 доступно обновление до {self._f2b_latest}"
                    f" → выберите [3]{C_RESET}"
                )
            else:
                f2b_line += f"  {C_DIM}(последняя версия){C_RESET}"
            print(f2b_line)
        else:
            print(f"  fail2ban:    {C_RED}не установлен{C_RESET}  → выберите [1] для установки")
        print()

        menu_items = [
            ("1", "Установить Fail2ban", "Автоматически определить дистрибутив и установить fail2ban"),
            ("2", "Удалить Fail2ban", "Остановить службу, создать резервную копию конфигурации и удалить"),
            ("3", "Обновить Fail2ban", "Обновить до последней версии"),
            ("4", "Настроить уведомления Telegram-бота", "Пошаговая настройка токена бота и Chat ID"),
            ("5", "Просмотреть состояние", "Просмотр состояния службы fail2ban и информации о jail"),
            ("6", "Просмотреть заблокированные IP", "Список всех заблокированных IP"),
            ("7", "Заблокировать / разблокировать IP вручную", "Добавить или снять блокировку IP вручную"),
            ("8", "Запустить / остановить / перезапустить службы", "Управление службами f2b-manager и fail2ban"),
            ("9", "Просмотреть журналы", "Просмотр последних журналов работы"),
            ("C", "Настройка параметров fail2ban", "Изменение длительности блокировки, окна обнаружения, числа повторов и т. д."),
            ("D", "Удалить f2b-manager", "Удалить программу управления и все её компоненты"),
            ("0", "Выход", "Выйти из меню управления"),
        ]
        for num, title, desc in menu_items:
            color = C_GREEN
            print(f"  {C_BOLD}{color}[{num}]{C_RESET} {C_BOLD}{title}{C_RESET}")
            print(f"   {C_DIM}{desc}{C_RESET}")
        print()

    # ── 1. Установка Fail2ban ──────────────────────

    def _menu_install(self) -> None:
        """Устанавливает Fail2ban."""
        _clear_screen()
        _print_header("Установка Fail2ban")

        if self._f2b_installer is None:
            _print_error("Модуль установки Fail2ban не готов; убедитесь, что программа установлена полностью")
            _read_input("Нажмите Enter для возврата")
            return

        _print_info("Определяется система и устанавливается fail2ban, подождите...")
        print()

        try:
            result = self._f2b_installer.install()
            if result.success:
                _print_success(result.message)
                if result.version:
                    print(f"  {C_GREEN}  Версия: {result.version}{C_RESET}")
                if result.details:
                    print(f"  {C_DIM}  Подробности:{C_RESET}")
                    for d in result.details:
                        print(f"    {C_DIM}• {d}{C_RESET}")
            else:
                _print_error(result.message)
                if result.details:
                    for d in result.details:
                        print(f"    {C_DIM}• {d}{C_RESET}")
        except Exception as e:
            _print_error(f"Ошибка во время установки: {e}")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")

    # ── 2. Удаление Fail2ban ───────────────────────

    def _menu_uninstall(self) -> None:
        """Удаляет Fail2ban."""
        _clear_screen()
        _print_header("Удаление Fail2ban")

        if self._f2b_installer is None:
            _print_error("Модуль установки Fail2ban не готов")
            _read_input("Нажмите Enter для возврата")
            return

        if not _confirm("Удалить Fail2ban? Это действие необратимо"):
            print(f"  {C_DIM}Отменено{C_RESET}")
            _read_input("Нажмите Enter для возврата")
            return

        print()
        _print_info("Удаляется fail2ban, подождите...")
        print()

        try:
            result = self._f2b_installer.uninstall(keep_config=True)
            if result.success:
                _print_success(result.message)
                if result.details:
                    for d in result.details:
                        print(f"    {C_DIM}• {d}{C_RESET}")
            else:
                _print_error(result.message)
        except Exception as e:
            _print_error(f"Ошибка во время удаления: {e}")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")

    # ── 3. Обновление Fail2ban ─────────────────────

    def _menu_update(self) -> None:
        """Обновляет Fail2ban."""
        _clear_screen()
        _print_header("Обновление Fail2ban")

        if self._f2b_installer is None:
            _print_error("Модуль установки Fail2ban не готов")
            _read_input("Нажмите Enter для возврата")
            return

        _print_info("Проверяется и обновляется fail2ban...")
        print()

        try:
            result = self._f2b_installer.update()
            if result.success:
                _print_success(result.message)
                if result.version:
                    print(f"  {C_GREEN}  Версия: {result.version}{C_RESET}")
                if result.details:
                    for d in result.details:
                        print(f"    {C_DIM}• {d}{C_RESET}")
            else:
                _print_error(result.message)
                if result.details:
                    for d in result.details:
                        print(f"    {C_DIM}• {d}{C_RESET}")
        except Exception as e:
            _print_error(f"Ошибка во время обновления: {e}")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")

    # ── D. Удаление f2b-manager ───────────────────

    def _menu_uninstall_manager(self) -> None:
        """Удаляет сам f2b-manager."""
        _clear_screen()
        _print_header("Удаление f2b-manager")

        print(f"  {C_YELLOW}{C_BOLD}⚠️  Внимание: будут удалены f2b-manager и все его компоненты{C_RESET}")
        print()
        print(f"  Будут удалены:")
        print(f"    • /opt/f2b-manager/  (файлы программы)")
        print(f"    • /etc/f2b-manager/  (файлы конфигурации)")
        print(f"    • /usr/local/bin/f2b-manager (CLI)")
        print(f"    • /usr/local/bin/f2b (быстрая команда)")
        print(f"    • /usr/local/bin/f2b-notify.sh (скрипт уведомлений)")
        print(f"    • служба systemd")
        print(f"    • /var/lib/f2b-manager/ (база данных)")
        print()
        print(f"  {C_GREEN}Не затрагиваются:{C_RESET}")
        print(f"    • fail2ban и его конфигурация")
        print(f"    • Telegram-бот (удалите его вручную через BotFather)")
        print()

        if not _confirm("Удалить f2b-manager? Это действие необратимо!"):
            print(f"  {C_DIM}Отменено{C_RESET}")
            _read_input("Нажмите Enter для возврата в главное меню")
            return

        # Повторное подтверждение
        if not _confirm("Подтвердите ещё раз: действительно удалить f2b-manager?"):
            print(f"  {C_DIM}Отменено{C_RESET}")
            _read_input("Нажмите Enter для возврата в главное меню")
            return

        print()
        _print_info("Удаляется f2b-manager...")

        errors = []

        # 1. Остановка и отключение службы
        for svc in ["f2b-manager"]:
            r = subprocess.run(["systemctl", "stop", svc], capture_output=True, text=True)
            r2 = subprocess.run(["systemctl", "disable", svc], capture_output=True, text=True)
            if r.returncode == 0 or "not loaded" in r.stderr.lower():
                _print_success(f"Служба {svc} остановлена и отключена")
            else:
                errors.append(f"Остановка {svc}: {r.stderr.strip()}")

        # 2. Удаление файла systemd
        svc_file = "/etc/systemd/system/f2b-manager.service"
        if os.path.exists(svc_file):
            os.remove(svc_file)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            _print_success("Файл службы systemd удалён")

        # 3. Удаление исполняемых файлов и быстрых команд
        for f in ["/usr/local/bin/f2b-manager", "/usr/local/bin/f2b-notify.sh"]:
            if os.path.lexists(f):
                os.remove(f)
                _print_success(f"Удалено: {f}")
        # f2b является символической ссылкой
        if os.path.lexists("/usr/local/bin/f2b"):
            os.remove("/usr/local/bin/f2b")
            _print_success("Удалено: /usr/local/bin/f2b")

        # 4. Удаление каталогов программы
        import shutil
        for d in ["/opt/f2b-manager", "/var/lib/f2b-manager"]:
            if os.path.isdir(d):
                shutil.rmtree(d)
                _print_success(f"Удалено: {d}")

        # 5. Запрос на сохранение конфигурации
        if os.path.isdir("/etc/f2b-manager"):
            if _confirm("Сохранить файлы конфигурации /etc/f2b-manager/ для будущей установки?"):
                print(f"  {C_DIM}Файлы конфигурации сохранены в /etc/f2b-manager/{C_RESET}")
            else:
                shutil.rmtree("/etc/f2b-manager")
                _print_success("Файлы конфигурации удалены")

        print()
        if errors:
            _print_warning(f"Во время удаления возникло предупреждений: {len(errors)}")
            for e in errors:
                print(f"    {C_DIM}• {e}{C_RESET}")
        else:
            _print_success("f2b-manager полностью удалён!")

        print()
        print(f"  {C_GREEN}Спасибо за использование f2b-manager!{C_RESET}")
        print()

        sys.exit(0)

    # ── C. Параметры Fail2ban ──────────────────────

    def _menu_f2b_config(self) -> None:
        """Подменю настройки параметров fail2ban."""
        _clear_screen()
        while True:
            _print_header("Параметры Fail2ban")

            # Чтение текущей конфигурации
            cfg = self._config.fail2ban
            db = None
            try:
                from .storage.database import StateDB
                db = StateDB()
            except Exception:
                pass

            bantime = _get_override(db, "f2b_bantime", cfg.default_bantime)
            findtime = _get_override(db, "f2b_findtime", cfg.default_findtime)
            maxretry = int(_get_override(db, "f2b_maxretry", str(cfg.default_maxretry)))
            incremental = _get_override(db, "f2b_incremental", "on" if cfg.incremental else "off") == "on"
            max_bantime = _get_override(db, "f2b_max_bantime", cfg.max_bantime)

            inc_icon = "✅" if incremental else "❌"
            print(f"  ⏱ Длительность блокировки: {C_GREEN}{bantime}{C_RESET}")
            print(f"  🔍 Окно обнаружения: {C_GREEN}{findtime}{C_RESET}")
            print(f"  🔢 Макс. попыток: {C_GREEN}{maxretry}{C_RESET}")
            print(f"  {inc_icon} Нарастающая блокировка: {'вкл.' if incremental else 'выкл.'}")
            print(f"  📈 Макс. длительность: {C_GREEN}{max_bantime}{C_RESET}")
            print()

            print(f"  {C_BOLD}{C_GREEN}[1]{C_RESET} {C_BOLD}Изменить длительность блокировки{C_RESET}")
            print(f"   {C_DIM}Сейчас: {bantime}, варианты: 10m, 30m, 1h, 2h, 6h, 12h, 1d, 7d{C_RESET}")
            print(f"  {C_BOLD}{C_GREEN}[2]{C_RESET} {C_BOLD}Изменить окно обнаружения{C_RESET}")
            print(f"   {C_DIM}Сейчас: {findtime}, варианты: 5m, 10m, 30m, 1h, 2h{C_RESET}")
            print(f"  {C_BOLD}{C_GREEN}[3]{C_RESET} {C_BOLD}Изменить макс. попыток{C_RESET}")
            print(f"   {C_DIM}Сейчас: {maxretry}, варианты: 2, 3, 5, 10, 20{C_RESET}")
            print(f"  {C_BOLD}{C_GREEN}[4]{C_RESET} {C_BOLD}Вкл./выкл. нарастающую блокировку{C_RESET}")
            print(f"   {C_DIM}Сейчас: {'вкл.' if incremental else 'выкл.'}{C_RESET}")
            print(f"  {C_BOLD}{C_GREEN}[5]{C_RESET} {C_BOLD}Изменить макс. длительность блокировки{C_RESET}")
            print(f"   {C_DIM}Сейчас: {max_bantime}, варианты: 1h, 12h, 1d, 3d, 1w, 2w, 1M{C_RESET}")
            print(f"  {C_BOLD}{C_GREEN}[A]{C_RESET} {C_BOLD}Применить и перезагрузить fail2ban{C_RESET}")
            print(f"   {C_DIM}Пересоздать jail.local и выполнить fail2ban-client reload{C_RESET}")
            print(f"  {C_BOLD}{C_GREEN}[0]{C_RESET} {C_BOLD}Назад{C_RESET}")
            print(f"   {C_DIM}Вернуться в главное меню{C_RESET}")
            print()

            # Чтение выбора
            raw = _read_input("Выберите действие").strip()
            if raw == "0":
                break

            raw_upper = raw.upper()
            if raw_upper == "A":
                self._apply_f2b_cfg()
                _read_input("Нажмите Enter для продолжения")
                continue

            try:
                idx = int(raw) - 1
            except ValueError:
                _print_error("Введите корректное число")
                _read_input("Нажмите Enter для продолжения")
                continue

            if idx < 0 or idx > 4:
                _print_error("Введите 1–5 или A")
                _read_input("Нажмите Enter для продолжения")
                continue

            if db is None:
                _print_error("База состояния не загружена, сохранить настройки нельзя")
                _read_input("Нажмите Enter для продолжения")
                continue

            presets_map = {
                0: ("f2b_bantime", ["10m", "30m", "1h", "2h", "6h", "12h", "1d", "7d"], "Длительность блокировки"),
                1: ("f2b_findtime", ["5m", "10m", "30m", "1h", "2h"], "Окно обнаружения"),
                2: ("f2b_maxretry", ["2", "3", "5", "10", "20"], "Макс. число попыток"),
                3: None,  # переключатель, отдельная обработка
                4: ("f2b_max_bantime", ["1h", "12h", "1d", "3d", "1w", "2w", "1M"], "Макс. длительность блокировки"),
            }

            if idx == 3:
                # Переключение нарастающей блокировки
                new_val = "off" if incremental else "on"
                db.set_config_override("f2b_incremental", new_val)
                _print_success(
                    f"Нарастающая блокировка {'включена' if new_val == 'on' else 'выключена'}"
                )
                _read_input("Нажмите Enter для продолжения")
                continue

            entry = presets_map[idx]
            if entry is None:
                continue
            dbkey, presets, label = entry

            # Текущее значение
            current_vals = {0: bantime, 1: findtime, 2: str(maxretry), 4: max_bantime}
            current_val = str(current_vals[idx])

            # Выбор из предустановок
            print()
            print(f"  {C_BOLD}Выберите {label}:{C_RESET}")
            for i, val in enumerate(presets, 1):
                marker = f" {C_GREEN}(текущее){C_RESET}" if str(val) == current_val else ""
                print(f"  {C_BOLD}{C_GREEN}[{i}]{C_RESET} {val}{marker}")
            print()

            choice = _read_choice("Выберите", [str(i) for i in range(1, len(presets) + 1)], default=0)
            if 0 <= choice < len(presets):
                val = presets[choice]
                db.set_config_override(dbkey, val)
                _print_success(f"{label} установлено: {val}")

            _read_input("Нажмите Enter для продолжения")


    def _apply_f2b_cfg(self) -> None:
        """Пересоздаёт jail.local и перезагружает fail2ban."""
        if self._f2b_installer is None:
            _print_error("Установщик не готов")
            return

        try:
            # Читаем переопределения из БД и обновляем объект config
            db = None
            try:
                from .storage.database import StateDB
                db = StateDB()
            except Exception:
                pass

            fc = self._config.fail2ban
            if db is not None:
                for key, dbkey in [
                    ("default_bantime", "f2b_bantime"),
                    ("default_findtime", "f2b_findtime"),
                    ("default_maxretry", "f2b_maxretry"),
                    ("max_bantime", "f2b_max_bantime"),
                ]:
                    val = db.get_config_override(dbkey, "")
                    if val:
                        if key == "default_maxretry":
                            setattr(fc, key, int(val))
                        else:
                            setattr(fc, key, val)
                inc = db.get_config_override("f2b_incremental", "")
                if inc:
                    fc.incremental = inc == "on"

            jail_content = self._f2b_installer._builder.generate_jail_local()
            with open("/etc/fail2ban/jail.local", "w") as f:
                f.write(jail_content)
            _print_success("jail.local пересоздан")

            if self._f2b_manager is not None:
                self._f2b_manager.reload()
                _print_success("fail2ban перезагружен")
        except Exception as e:
            _print_error(f"Не удалось применить конфигурацию: {e}")


    # ── 4. Настройка Telegram Bot ─────────────────

    def _menu_config_telegram(self) -> None:
        """Пошаговая настройка Telegram Bot."""
        _clear_screen()
        _print_header("Настройка уведомлений Telegram Bot")

        # ── Если уже настроено — показать статус ──
        token = self._config.telegram.bot_token
        if token and len(token) > 10:
            self._show_telegram_status()
            return

        # ── Мастер первой настройки ──
        self._run_telegram_wizard()

    def _show_telegram_status(self) -> None:
        """Показывает информацию о настроенном Telegram Bot."""
        token = self._config.telegram.bot_token
        admin_ids = self._config.telegram.admin_chat_ids

        print(f"  {C_GREEN}✅ Telegram Bot настроен{C_RESET}")
        print()
        print(f"  {C_BOLD}Bot Token:{C_RESET}")
        # Маскировка: первые 8 + **** + последние 4
        if len(token) > 16:
            masked = token[:8] + "****" + token[-4:]
        else:
            masked = token[:5] + "****"
        print(f"    {C_DIM}{masked}{C_RESET}")
        print()
        print(f"  {C_BOLD}Chat ID администраторов:{C_RESET}")
        for uid in admin_ids:
            print(f"    {uid}")
        if not admin_ids:
            print(f"    {C_RED}не задано{C_RESET}")
        print()
        print(f"  {C_BOLD}Chat ID операторов:{C_RESET}")
        ops = self._config.telegram.operator_chat_ids
        if ops:
            for uid in ops:
                print(f"    {uid}")
        else:
            print(f"    {C_DIM}нет{C_RESET}")
        print()

        print(f"  {C_BOLD}{C_GREEN}[1]{C_RESET} {C_BOLD}Перенастроить{C_RESET}")
        print(f"   {C_DIM}Запустить мастер заново, изменить Token или Chat ID{C_RESET}")
        print(f"  {C_BOLD}{C_GREEN}[2]{C_RESET} {C_BOLD}Изменить только Chat ID{C_RESET}")
        print(f"   {C_DIM}Оставить текущий Token, обновить Chat ID администратора{C_RESET}")
        print(f"  {C_BOLD}{C_GREEN}[0]{C_RESET} {C_BOLD}Назад{C_RESET}")
        print(f"   {C_DIM}Вернуться в главное меню{C_RESET}")
        print()

        raw = _read_input("Выберите действие").strip()
        if raw == "0":
            return
        if raw == "1":
            self._run_telegram_wizard()
        elif raw == "2":
            self._run_telegram_chatid_only()

    def _run_telegram_chatid_only(self) -> None:
        """Изменяет только Chat ID."""
        _clear_screen()
        _print_header("Изменение Telegram Chat ID")

        token = self._config.telegram.bot_token
        print(f"  Текущий Token: {C_DIM}{token[:8]}****{C_RESET}")
        print()

        print(f"  {C_BOLD}[Шаг 1] Узнайте свой Chat ID{C_RESET}")
        print("    1. В Telegram найдите @userinfobot")
        print("    2. Отправьте любое сообщение — получите User ID")
        print()

        while True:
            raw = _read_input("Введите ваш Chat ID (только цифры, Enter — отмена)").strip()
            if not raw:
                print(f"  {C_DIM}Отменено{C_RESET}")
                _read_input("Нажмите Enter для возврата")
                return
            if raw.isdigit():
                break
            _print_error("Chat ID должен состоять только из цифр")
        chat_id = int(raw)

        extra = _read_input("Доп. Chat ID операторов (необязательно, Enter — пропуск)").strip()
        extra_ids = []
        if extra:
            for eid in extra.split(","):
                eid = eid.strip()
                if eid.isdigit():
                    extra_ids.append(int(eid))

        print()
        _print_info("Проверка соединения...")
        try:
            resp = httpx.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": "✅ f2b-manager: Chat ID обновлён"},
                timeout=10,
            )
            if resp.status_code == 200 and resp.json().get("ok"):
                _print_success("Тест соединения успешен")
            else:
                _print_warning("Тестовое сообщение не отправлено, но настройки всё равно будут сохранены")
        except Exception as e:
            _print_warning(f"Тест не удался: {e}")

        print()
        _print_info("Сохранение...")
        from .config import save_config
        self._config.telegram.admin_chat_ids = [chat_id] + extra_ids
        self._config.telegram.notify_chat_id = chat_id
        if extra_ids:
            self._config.telegram.operator_chat_ids = extra_ids
        save_config(self._config, self._config_path)
        _print_success("Chat ID обновлён")

        print()
        _print_info("Чтобы изменения вступили в силу, нужно перезапустить службу")
        if _confirm("Перезапустить службу f2b-manager сейчас?"):
            r = subprocess.run(["systemctl", "restart", "f2b-manager"], capture_output=True)
            if r.returncode == 0:
                _print_success("Служба перезапущена")
            else:
                _print_warning("Перезапуск не удался, выполните вручную")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")

    def _run_telegram_wizard(self) -> None:
        """Запускает полный мастер настройки."""
        _clear_screen()
        _print_header("Настройка уведомлений Telegram Bot")
        print("  Мастер поможет настроить Telegram Bot без ручного редактирования файлов.")
        print(f"  {C_DIM}(Enter без ввода — выход из текущего шага){C_RESET}")
        print()
        print(f"  {C_BOLD}[Шаг 1] Создайте бота{C_RESET}")
        print("    1. Откройте Telegram и найдите @BotFather")
        print("    2. Отправьте /newbot и укажите имя и username бота")
        print("    3. Скопируйте Bot Token (формат: 123456789:ABCdef...)")
        print()

        # Если token уже есть — показать и разрешить пропуск Enter'ом
        existing = self._config.telegram.bot_token
        if existing:
            existing_masked = existing[:8] + "****" if len(existing) > 16 else ""
            print(f"  {C_DIM}Текущий Token: {existing_masked}{C_RESET}")
            print()

        while True:
            token = _read_input("Введите Bot Token (формат: цифры:буквы/цифры)").strip()
            if not token:
                print(f"  {C_DIM}Отменено{C_RESET}")
                _read_input("Нажмите Enter для возврата")
                return
            if re.match(r"^\d+:[A-Za-z0-9_-]+$", token):
                break
            _print_error("Неверный формат Token: ожидается цифры:буквы/цифры")
        _print_success("Формат Token корректен")
        print()

        print(f"  {C_BOLD}[Шаг 2] Узнайте свой Chat ID{C_RESET}")
        print("    1. В Telegram найдите @userinfobot")
        print("    2. Отправьте любое сообщение")
        print("    3. Бот ответит User ID (только цифры)")
        print()

        while True:
            chat_id_raw = _read_input("Введите ваш Telegram Chat ID (только цифры)").strip()
            if not chat_id_raw:
                print(f"  {C_DIM}Отменено{C_RESET}")
                _read_input("Нажмите Enter для возврата")
                return
            if chat_id_raw.isdigit():
                break
            _print_error("Chat ID должен состоять только из цифр")
        chat_id = int(chat_id_raw)
        print()

        # Необязательно: операторы
        extra = _read_input("Доп. Chat ID операторов (необязательно, Enter — пропуск)").strip()
        extra_ids = []
        if extra:
            for eid in extra.split(","):
                eid = eid.strip()
                if eid.isdigit():
                    extra_ids.append(int(eid))
        print()

        print(f"  {C_BOLD}[Шаг 3] Проверка соединения{C_RESET}")
        _print_info("Отправка тестового сообщения в Telegram...")

        send_ok = False
        try:
            resp = httpx.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": (
                        "✅ Тест настройки f2b-manager успешен!\n\n"
                        "Бот готов: оповещения о блокировках будут приходить автоматически."
                    ),
                },
                timeout=10,
            )
            data = resp.json() if resp.status_code == 200 else {}
            if data.get("ok"):
                send_ok = True
                _print_success("Тестовое сообщение отправлено — проверьте Telegram")
            else:
                _print_error(
                    f"Не удалось отправить тестовое сообщение: "
                    f"{data.get('description', resp.text[:200])}"
                )
        except Exception as e:
            _print_error(f"Не удалось отправить тестовое сообщение: {e}")

        if not send_ok:
            print()
            print(f"  {C_YELLOW}Возможные причины:{C_RESET}")
            print("    - Token неверный или устарел")
            print("    - Chat ID неверный")
            print("    - Сначала нужно написать боту любое сообщение в Telegram")
            print("    - На VPS нет доступа к Telegram API")

        print()
        if not send_ok and not _confirm("Тест не прошёл. Всё равно сохранить настройки?"):
            print(f"  {C_DIM}Отменено{C_RESET}")
            _read_input("Нажмите Enter для возврата")
            return

        # Сохранение конфигурации
        print()
        _print_info("Сохранение конфигурации...")

        from .config import save_config
        self._config.telegram.bot_token = token
        self._config.telegram.admin_chat_ids = [chat_id] + extra_ids
        self._config.telegram.notify_chat_id = chat_id
        if extra_ids:
            self._config.telegram.operator_chat_ids = extra_ids

        save_config(self._config, self._config_path)
        _print_success(f"Конфигурация сохранена: {self._config_path}")

        print()
        _print_info("Настройка завершена! Чтобы применить изменения, перезапустите службу")
        if _confirm("Перезапустить службу f2b-manager сейчас?"):
            r = subprocess.run(["systemctl", "restart", "f2b-manager"], capture_output=True)
            if r.returncode == 0:
                _print_success("Служба перезапущена")
            else:
                _print_warning(
                    "Перезапуск не удался, выполните вручную: systemctl restart f2b-manager"
                )
        else:
            print(f"  {C_DIM}Позже можно выполнить: systemctl restart f2b-manager{C_RESET}")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")

    # ── 5. Просмотр состояния ───────────────────────

    def _menu_status(self) -> None:
        """Показывает состояние Fail2ban."""
        _clear_screen()
        _print_header("Состояние Fail2ban")

        if self._f2b_manager is None:
            _print_error("Модуль управления Fail2ban не готов")
            _read_input("Нажмите Enter для возврата")
            return

        try:
            status = self._f2b_manager.get_status()
            print(f"  Версия: {C_GREEN}{status.version}{C_RESET}")
            state_color = C_GREEN if status.state.value == "running" else C_RED
            print(f"  Состояние: {state_color}{status.state.value}{C_RESET}")
            print(f"  Число jail: {status.jail_count}")
            print(f"  Всего блокировок: {status.total_bans}")
            print(f"  Время работы: {status.uptime}")
            print()

            # Детали по jail
            jails = self._f2b_manager.get_jails()
            if jails:
                print(f"  {C_BOLD}Список jail:{C_RESET}")
                for j in jails:
                    icon = "✅" if j.enabled else "❌"
                    print(
                        f"    {icon} {j.name}: блокировок {j.current_ban} | "
                        f"ошибок {j.total_failed} | всего {j.total_banned}"
                    )
        except Exception as e:
            _print_error(f"Не удалось получить состояние: {e}")
            _print_info("Убедитесь, что fail2ban установлен и запущен")
            _print_info("Можно проверить: systemctl status fail2ban")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")

    # ── 6. Список заблокированных IP ────────────────

    def _menu_banned_ips(self) -> None:
        """Показывает список заблокированных IP."""
        _clear_screen()
        _print_header("Заблокированные IP")

        if self._f2b_manager is None:
            _print_error("Модуль управления Fail2ban не готов")
            _read_input("Нажмите Enter для возврата")
            return

        try:
            ips = self._f2b_manager.get_banned_ips()
            if not ips:
                _print_success("Сейчас нет заблокированных IP")
            else:
                # GeoIP-запрос (временно глушим логи httpx)
                import logging
                httpx_logger = logging.getLogger("httpx")
                old_level = httpx_logger.level
                httpx_logger.setLevel(logging.WARNING)
                try:
                    from .notify.geoip import lookup_country_sync
                    print(f"  {C_BOLD}Заблокировано IP: {len(ips)}{C_RESET}")
                    print()
                    for i, ip in enumerate(ips, 1):
                        country = lookup_country_sync(ip)
                        country_str = f"  {C_DIM}{country}{C_RESET}" if country else ""
                        print(f"  {C_BOLD}{i}.{C_RESET} {C_RED}{ip}{C_RESET}{country_str}")
                finally:
                    httpx_logger.setLevel(old_level)
        except Exception as e:
            _print_error(f"Не удалось получить список блокировок: {e}")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")

    # ── 7. Ручная блокировка / разблокировка IP ───

    def _menu_ban_manage(self) -> None:
        """Подменю ручной блокировки/разблокировки."""
        _clear_screen()
        while True:
            _print_header("Ручная блокировка / разблокировка IP")
            menu_items = [
                ("1", "Заблокировать IP", "Вручную заблокировать указанный IP"),
                ("2", "Разблокировать IP", "Вручную разблокировать указанный IP"),
                ("0", "Назад", "Вернуться в главное меню"),
            ]
            for num, title, desc in menu_items:
                print(f"  {C_BOLD}{C_GREEN}[{num}]{C_RESET} {C_BOLD}{title}{C_RESET}")
                print(f"   {C_DIM}{desc}{C_RESET}")
            print()

            choice = _read_choice("Выберите действие", [str(i) for i in range(len(menu_items))])
            print()

            if choice == 0:
                self._menu_ban_ip()
            elif choice == 1:
                self._menu_unban_ip()
            elif choice == 2:
                break

    def _menu_ban_ip(self) -> None:
        """Процедура ручной блокировки IP."""
        _clear_screen()
        _print_header("Ручная блокировка IP")

        if self._f2b_manager is None:
            _print_error("Модуль управления Fail2ban не готов")
            _read_input("Нажмите Enter для возврата")
            return

        while True:
            ip = _read_input("Введите IP для блокировки (например 192.168.1.100)").strip()
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
                break
            except ValueError:
                _print_error("Неверный формат IP, укажите корректный IPv4-адрес")

        jail = _read_input("Имя jail (по умолчанию: sshd)", "sshd").strip()
        print()

        try:
            success = self._f2b_manager.ban_ip(ip, jail)
            if success:
                _print_success(f"Заблокирован {ip} (jail: {jail})")
            else:
                _print_error(f"Не удалось заблокировать {ip}")
        except Exception as e:
            _print_error(f"Ошибка блокировки: {e}")

        print()
        _read_input("Нажмите Enter для продолжения")

    def _menu_unban_ip(self) -> None:
        """Процедура ручной разблокировки IP."""
        _clear_screen()
        _print_header("Ручная разблокировка IP")

        if self._f2b_manager is None:
            _print_error("Модуль управления Fail2ban не готов")
            _read_input("Нажмите Enter для возврата")
            return

        while True:
            ip = _read_input("Введите IP для разблокировки").strip()
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
                break
            except ValueError:
                _print_error("Неверный формат IP, укажите корректный IPv4-адрес")

        # Проверка, заблокирован ли IP
        found_jail = None
        try:
            for j in self._f2b_manager.get_jails():
                js = self._f2b_manager.get_jail_status(j.name)
                if ip in js.banned_ips:
                    found_jail = j.name
                    break
        except Exception:
            pass

        if found_jail is None:
            _print_warning(f"{ip} нет ни в одном списке блокировок jail — разблокировка не нужна")
            print()
            _read_input("Нажмите Enter для продолжения")
            return

        print()
        try:
            success = self._f2b_manager.unban_ip(ip)
            if success:
                _print_success(f"Разблокирован {ip} (jail: {found_jail})")
            else:
                _print_error(f"Не удалось разблокировать {ip}")
        except Exception as e:
            _print_error(f"Ошибка разблокировки: {e}")

        print()
        _read_input("Нажмите Enter для продолжения")

    # ── 8. Управление службами ────────────────────

    def _menu_service_control(self) -> None:
        """Подменю запуска/остановки/перезапуска служб."""
        _clear_screen()
        while True:
            _print_header("Управление службами")
            menu_items = [
                ("1", "Запустить f2b-manager", "Запустить демон"),
                ("2", "Остановить f2b-manager", "Остановить демон"),
                ("3", "Перезапустить f2b-manager", "Перезапустить демон"),
                ("4", "Запустить fail2ban", "Запустить службу защиты fail2ban"),
                ("5", "Остановить fail2ban", "Остановить службу защиты fail2ban"),
                ("6", "Перезапустить fail2ban", "Перезапустить службу fail2ban"),
                ("7", "Статус служб", "Показать systemctl-статус обеих служб"),
                ("0", "Назад", "Вернуться в главное меню"),
            ]
            for num, title, desc in menu_items:
                print(f"  {C_BOLD}{C_GREEN}[{num}]{C_RESET} {C_BOLD}{title}{C_RESET}")
                print(f"   {C_DIM}{desc}{C_RESET}")
            print()

            choice = _read_choice("Выберите действие", [str(i) for i in range(len(menu_items))])
            print()

            if choice == 0:
                self._systemctl("start", "f2b-manager")
            elif choice == 1:
                if _confirm("Остановить службу f2b-manager?"):
                    self._systemctl("stop", "f2b-manager")
            elif choice == 2:
                self._systemctl("restart", "f2b-manager")
            elif choice == 3:
                self._systemctl("start", "fail2ban")
            elif choice == 4:
                if _confirm("Остановить fail2ban? После остановки защита от атак прекратится"):
                    self._systemctl("stop", "fail2ban")
            elif choice == 5:
                self._systemctl("restart", "fail2ban")
            elif choice == 6:
                self._systemctl_status()
            elif choice == 7:
                break

    def _systemctl(self, action: str, service: str) -> None:
        """Выполняет команду systemctl."""
        r = subprocess.run(
            ["systemctl", action, service],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            _print_success(f"systemctl {action} {service} — успешно")
        else:
            _print_error(f"systemctl {action} {service} — ошибка: {r.stderr.strip()}")

    def _systemctl_status(self) -> None:
        """Показывает статус служб."""
        print(f"  {C_BOLD}f2b-manager:{C_RESET}")
        r = subprocess.run(
            ["systemctl", "is-active", "f2b-manager"],
            capture_output=True, text=True,
        )
        status = "active" if "active" in r.stdout else r.stdout.strip()
        color = C_GREEN if status == "active" else C_RED
        print(f"    Состояние: {color}{status}{C_RESET}")

        print(f"  {C_BOLD}fail2ban:{C_RESET}")
        r = subprocess.run(
            ["systemctl", "is-active", "fail2ban"],
            capture_output=True, text=True,
        )
        status = "active" if "active" in r.stdout else r.stdout.strip()
        color = C_GREEN if status == "active" else C_RED
        print(f"    Состояние: {color}{status}{C_RESET}")

    # ── 9. Просмотр журналов ──────────────────────

    def _menu_view_logs(self) -> None:
        """Показывает журналы."""
        _clear_screen()
        _print_header("Журнал работы (последние 50 строк)")

        r = subprocess.run(
            ["journalctl", "-u", "f2b-manager", "--no-pager", "-n", "50"],
            capture_output=True, text=True,
        )
        if r.stdout:
            print(r.stdout)
        else:
            _print_info("Журнал пуст или недоступен")

        print()
        _read_input("Нажмите Enter для возврата в главное меню")
