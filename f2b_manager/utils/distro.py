"""
f2b_manager.utils.distro
========================

Определение дистрибутива Linux.

Читает /etc/os-release и сопоставляет дистрибутив с менеджером пакетов.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..storage.models import Distro, DistroInfo, PackageManager


# Дистрибутив → менеджер пакетов
_DISTRO_TO_PKG = {
    Distro.DEBIAN: PackageManager.APT,
    Distro.UBUNTU: PackageManager.APT,
    Distro.CENTOS: PackageManager.DNF,   # CentOS 8+ — dnf
    Distro.RHEL: PackageManager.DNF,
    Distro.ROCKY: PackageManager.DNF,
    Distro.ALMA: PackageManager.DNF,
    Distro.FEDORA: PackageManager.DNF,
    Distro.ALPINE: PackageManager.APK,
    Distro.ARCH: PackageManager.PACMAN,
}

# Поле ID из os-release → Distro
_ID_TO_DISTRO = {
    "debian": Distro.DEBIAN,
    "ubuntu": Distro.UBUNTU,
    "centos": Distro.CENTOS,
    "rhel": Distro.RHEL,
    "rocky": Distro.ROCKY,
    "rockylinux": Distro.ROCKY,
    "almalinux": Distro.ALMA,
    "alma": Distro.ALMA,
    "fedora": Distro.FEDORA,
    "alpine": Distro.ALPINE,
    "arch": Distro.ARCH,
    "archlinux": Distro.ARCH,
}


def detect_distro() -> DistroInfo:
    """Определить текущий дистрибутив.

    Читает /etc/os-release, разбирает ID и VERSION_ID.
    Если не удалось — запасной путь через наличие команд менеджера пакетов.

    Returns:
        DistroInfo: имя дистрибутива, версия, менеджер пакетов.
    """
    os_release = Path("/etc/os-release")

    if os_release.exists():
        info = _parse_os_release(os_release.read_text())
        distro_id = info.get("ID", "").strip('"').lower()
        version = info.get("VERSION_ID", "").strip('"')

        distro = _ID_TO_DISTRO.get(distro_id, Distro.UNKNOWN)

        if distro != Distro.UNKNOWN:
            pkg = _DISTRO_TO_PKG[distro]
            return DistroInfo(distro=distro, version=version, package_manager=pkg)

    # Запасной вариант: по наличию команд
    return _detect_by_command()


def _parse_os_release(content: str) -> dict[str, str]:
    """Разобрать содержимое /etc/os-release в словарь."""
    result: dict[str, str] = {}
    for line in content.splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def _detect_by_command() -> DistroInfo:
    """Определить дистрибутив по командам (запасной путь)."""
    from .shell import which

    if which("apt-get"):
        return DistroInfo(Distro.DEBIAN, "", PackageManager.APT)
    if which("dnf"):
        return DistroInfo(Distro.CENTOS, "", PackageManager.DNF)
    if which("yum"):
        return DistroInfo(Distro.CENTOS, "", PackageManager.YUM)
    if which("apk"):
        return DistroInfo(Distro.ALPINE, "", PackageManager.APK)
    if which("pacman"):
        return DistroInfo(Distro.ARCH, "", PackageManager.PACMAN)

    return DistroInfo(Distro.UNKNOWN, "", PackageManager.UNKNOWN)


def get_install_command(pkg_manager: PackageManager, package: str) -> str:
    """Команда установки пакета."""
    commands = {
        PackageManager.APT: f"apt-get install -y {package}",
        PackageManager.DNF: f"dnf install -y {package}",
        PackageManager.YUM: f"yum install -y {package}",
        PackageManager.APK: f"apk add --no-cache {package}",
        PackageManager.PACMAN: f"pacman -S --noconfirm {package}",
    }
    return commands.get(pkg_manager, f"echo 'Неподдерживаемый менеджер пакетов: {pkg_manager}'")


def get_remove_command(pkg_manager: PackageManager, package: str) -> str:
    """Команда удаления пакета."""
    commands = {
        PackageManager.APT: f"apt-get remove --purge -y {package}",
        PackageManager.DNF: f"dnf remove -y {package}",
        PackageManager.YUM: f"yum remove -y {package}",
        PackageManager.APK: f"apk del {package}",
        PackageManager.PACMAN: f"pacman -R --noconfirm {package}",
    }
    return commands.get(pkg_manager, f"echo 'Неподдерживаемый менеджер пакетов: {pkg_manager}'")


def get_upgrade_command(pkg_manager: PackageManager, package: str) -> str:
    """Команда обновления пакета."""
    commands = {
        PackageManager.APT: f"apt-get install --only-upgrade -y {package}",
        PackageManager.DNF: f"dnf upgrade -y {package}",
        PackageManager.YUM: f"yum update -y {package}",
        PackageManager.APK: f"apk upgrade --no-cache {package}",
        PackageManager.PACMAN: f"pacman -Syu --noconfirm {package}",
    }
    return commands.get(pkg_manager, f"echo 'Неподдерживаемый менеджер пакетов: {pkg_manager}'")
