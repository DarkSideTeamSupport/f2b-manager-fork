"""
f2b_manager.notify.geoip
========================

Запрос геолокации по IP.

Приоритет отдаётся локальной базе данных maxminddb GeoLite2-Country;
если файл отсутствует или запрос не удался, выполняется автоматический
откат к онлайн API ip-api.com.

Ограничения трафика:
- Для частных IP (127.x, 10.x, 192.168.x, 172.16–31.x) сразу
  возвращается пустой результат, запрос не выполняется
- Бесплатная версия ip-api.com ограничена 45 запросами в минуту;
  этот модуль дополнительно не ограничивает частоту (дедупликация
  на стороне вызывающего кода)
"""

from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
from typing import Optional

# Путь к базе данных GeoIP по умолчанию
_GEOIP_DB_PATH = "/var/lib/GeoIP/GeoLite2-Country.mmdb"

# Ограничение частоты API: время последнего вызова
_api_last_call = 0.0

from ..storage.models import GeoInfo

logger = logging.getLogger("notify.geoip")


def _country_code_to_flag(code: str) -> str:
    """Преобразует двухбуквенный код страны в emoji-флаг.

    Используются символы Unicode Regional Indicator (U+1F1E6–U+1F1FF).
    """
    if not code or len(code) != 2:
        return ""
    code = code.upper()
    offset = 0x1F1E6 - ord("A")
    try:
        return chr(ord(code[0]) + offset) + chr(ord(code[1]) + offset)
    except (ValueError, IndexError):
        return ""


def _is_private_ip(ip: str) -> bool:
    """Проверяет, является ли адрес частным/локальным — для таких IP геолокация не запрашивается."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # Некорректный IP тоже считается частным, запрос не выполняется


class GeoIPLookup:
    """Запрос геолокации по IP.

    Два режима:
    - local: локальный файл maxminddb (рекомендуется, без задержки)
    - api: прямой вызов онлайн API ip-api.com

    При сбое режима local выполняется автоматический откат к api.
    """

    def __init__(self, db_path: str = "/var/lib/GeoIP/GeoLite2-Country.mmdb",
                 method: str = "local"):
        """
        Args:
            db_path: путь к файлу базы данных maxminddb
            method: способ запроса ("local" / "api")
        """
        self._db_path = db_path
        self._method = method
        self._reader: Optional[object] = None  # экземпляр maxminddb.Reader
        self._reader_loaded = False

        if method == "local":
            self._init_local_db()

    def _init_local_db(self) -> None:
        """Пытается загрузить локальную базу mmdb."""
        try:
            import maxminddb
        except ImportError:
            logger.warning("Библиотека maxminddb не установлена, будет использован откат к API")
            return

        db_file = Path(self._db_path)
        if not db_file.exists():
            logger.warning("Файл базы данных GeoIP не найден: %s, будет использован откат к API",
                           self._db_path)
            return

        try:
            self._reader = maxminddb.open_database(str(db_file))
            self._reader_loaded = True
            logger.info("Загружена локальная база данных GeoIP: %s", self._db_path)
        except Exception as e:
            logger.warning("Не удалось открыть базу данных GeoIP %s: %s, будет использован откат к API",
                           self._db_path, e)

    def _lookup_local(self, ip: str) -> Optional[GeoInfo]:
        """Запрашивает геолокацию IP через локальную базу mmdb."""
        if not self._reader_loaded or self._reader is None:
            return None

        try:
            result = self._reader.get(ip)
            if result is None:
                return None

            country_info = result.get("country", {})
            if not country_info:
                return None

            iso_code = country_info.get("iso_code", "")
            country_name = country_info.get("names", {}).get("zh-CN", "")
            if not country_name:
                country_name = country_info.get("names", {}).get("en", "")

            return GeoInfo(
                country=country_name or iso_code,
                country_code=iso_code,
                flag=_country_code_to_flag(iso_code),
            )
        except Exception as e:
            logger.debug("Локальный запрос GeoIP не удался ip=%s: %s", ip, e)
            return None

    async def _lookup_api(self, ip: str) -> Optional[GeoInfo]:
        """Запрашивает геолокацию IP через бесплатный API ip-api.com.

        Ограничения бесплатной версии:
        - 45 запросов в минуту
        - HTTPS не поддерживается (только HTTP)
        - в одном запросе можно передать до ~150 IP (этот модуль запрашивает по одному IP)
        """
        try:
            import httpx
        except ImportError:
            logger.warning("httpx не установлен, невозможно запросить геолокацию IP")
            return None

        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode&lang=zh-CN"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    logger.debug("ip-api.com вернул %d for ip=%s",
                                 resp.status_code, ip)
                    return None

                data = resp.json()
                if data.get("status") == "fail":
                    logger.debug("Запрос ip-api.com не удался ip=%s: %s",
                                 ip, data.get("message", ""))
                    return None

                country = data.get("country", "")
                country_code = data.get("countryCode", "")
                return GeoInfo(
                    country=country,
                    country_code=country_code,
                    flag=_country_code_to_flag(country_code),
                )
        except Exception as e:
            logger.debug("Ошибка запроса к ip-api.com ip=%s: %s", ip, e)
            return None

    async def lookup(self, ip: str) -> GeoInfo:
        """Запрашивает геолокацию IP.

        Args:
            ip: строка с IP-адресом

        Returns:
            GeoInfo: результат запроса. При ошибке (частный IP, сбой сети, нет данных)
                     возвращается пустой GeoInfo (country, country_code и flag — пустые строки).
        """
        # Частный IP — пропускаем
        if _is_private_ip(ip):
            logger.debug("Пропускаем запрос для частного IP: %s", ip)
            return GeoInfo()

        # Сначала локальная база mmdb
        if self._method == "local" and self._reader_loaded:
            result = self._lookup_local(ip)
            if result is not None:
                return result
            logger.debug("Локальный запрос не удался, откат к API ip=%s", ip)

        # Откат к онлайн API
        result = await self._lookup_api(ip)
        if result is not None:
            return result

        # Все способы не сработали — пустой результат
        logger.debug("Не удалось определить геолокацию IP: %s", ip)
        return GeoInfo()

    def close(self) -> None:
        """Закрывает соединение с локальной базой mmdb."""
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
            self._reader_loaded = False

    def __del__(self) -> None:
        """При уничтожении объекта закрывает соединение."""
        self.close()


def lookup_country_sync(ip: str, db_path: str = _GEOIP_DB_PATH) -> str:
    """Синхронно запрашивает страну по IP (сначала локальная БД, затем откат к API).

    Для синхронных контекстов, например CLI. Встроенное ограничение частоты
    снижает повторные запросы за короткий интервал.

    Args:
        ip: IP-адрес
        db_path: путь к базе данных maxminddb

    Returns:
        Строка вида «Название страны» с emoji-флагом; при неудаче — пустая строка
    """
    if _is_private_ip(ip):
        return ""

    # 1. Локальная база mmdb
    try:
        import maxminddb
        if os.path.exists(db_path):
            reader = maxminddb.open_database(db_path)
            try:
                result = reader.get(ip)
                if result and "country" in result:
                    country = result["country"].get("names", {}).get("zh-CN", "")
                    code = result["country"].get("iso_code", "")
                    if country:
                        flag = _country_code_to_flag(code)
                        return f"{country} {flag}" if flag else country
            finally:
                reader.close()
    except Exception:
        pass

    # 2. Откат к ip-api.com (последовательно + ограничение: до 40 запросов в минуту)
    try:
        import httpx
        import time as _time
        # Ограничение частоты: минимум 1,5 с между запросами (40/мин с запасом)
        now = _time.monotonic()
        elapsed = now - _api_last_call
        if elapsed < 1.5:
            _time.sleep(1.5 - elapsed)
        _api_last_call = _time.monotonic()

        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "country,countryCode", "lang": "zh-CN"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            country = data.get("country", "")
            code = data.get("countryCode", "")
            if country:
                flag = _country_code_to_flag(code)
                return f"{country} {flag}" if flag else country
    except Exception:
        pass

    return ""
