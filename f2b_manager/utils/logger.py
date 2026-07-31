"""
f2b_manager.utils.logger
========================

Настройка логирования.

Логгер с ротацией файлов: вывод в консоль и в файл.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# Формат логов
_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"

# Флаг, чтобы не инициализировать повторно
_initialized = False


def setup_logging(
    level: str = "INFO",
    log_file: str = "/var/log/f2b-manager.log",
    max_size_mb: int = 10,
    backup_count: int = 5,
) -> logging.Logger:
    """Инициализировать глобальное логирование.

    Args:
        level: уровень (DEBUG/INFO/WARNING/ERROR)
        log_file: путь к файлу лога
        max_size_mb: макс. размер одного файла, МБ
        backup_count: число резервных копий

    Returns:
        Настроенный корневой логгер.
    """
    global _initialized

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if _initialized:
        return root_logger

    formatter = logging.Formatter(_FMT, datefmt=_DATE_FMT)

    # Консоль
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Файл с ротацией
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except (PermissionError, OSError):
            # Нет прав на запись (не root) — только консоль
            root_logger.warning(
                "Не удалось записать лог-файл %s — только вывод в консоль",
                log_file,
            )

    _initialized = True
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Получить именованный логгер."""
    return logging.getLogger(name)
