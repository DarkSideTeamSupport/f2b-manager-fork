"""Пакет f2b_manager.notify — модуль оповещений в реальном времени.

Запрос геолокации IP, дедупликация/лимит сообщений, сборка и отправка оповещений.
События fail2ban приходят через кастомный action (telegram-notify.conf)
и мост (f2b-notify.sh), далее через CLI-подкоманду notify в этот модуль.
"""

from .geoip import GeoIPLookup
from .dedup import DedupTracker
from .sender import AlertSender, BAN_TEMPLATE, UNBAN_TEMPLATE

__all__ = [
    "GeoIPLookup",
    "DedupTracker",
    "AlertSender",
    "BAN_TEMPLATE",
    "UNBAN_TEMPLATE",
]
