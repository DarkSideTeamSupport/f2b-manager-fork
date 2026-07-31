"""
Пакет f2b_manager.monitor
=========================

Планировщик и мониторинг (M4).

Публичный API:
    F2BScheduler  — планировщик задач на базе APScheduler
    BanReporter   — генератор отчётов о банах (протокол IReporter)
    HealthChecker — проверка здоровья Fail2ban и автовосстановление
"""

from .health import HealthChecker
from .reporter import BanReporter
from .scheduler import F2BScheduler

__all__ = [
    "F2BScheduler",
    "BanReporter",
    "HealthChecker",
]
