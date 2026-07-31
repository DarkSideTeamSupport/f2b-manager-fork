"""
tests/test_database.py
======================
Тестирование модели данных StateDB.

Покрытие: record_ban / get_ban_history / set_current_bans / get_current_bans /
       update_daily_stats / get_daily_stats / count_bans_today /
       top_banned_ips / top_banned_countries / config_overrides

Граничные условия: пустая таблица, большой объем данных, повторяющиеся записи, аномальные параметры.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from f2b_manager.storage.models import BanAction, BanEvent, DailyStat


class TestRecordBan:
    """Тест на запись событий запрета"""

    def test_record_single(self, tmp_db):
        """Записывайте единичные события бана и проверяйте целостность данных."""
        event = BanEvent(
            ip="192.0.2.1",
            jail="sshd",
            action=BanAction.BAN,
            failures=3,
            country="US",
            matches="auth.log line 42",
            timestamp=datetime(2026, 7, 1, 12, 0, 0),
        )
        tmp_db.record_ban(event)

        history = tmp_db.get_ban_history(days=365)
        assert len(history) == 1
        assert history[0].ip == "192.0.2.1"
        assert history[0].jail == "sshd"
        assert history[0].action == BanAction.BAN
        assert history[0].failures == 3
        assert history[0].country == "US"

    def test_record_multiple(self, tmp_db):
        """Запишите несколько событий бана и проверьте правильность числа."""
        for i in range(10):
            event = BanEvent(
                ip=f"192.0.2.{i}",
                jail="sshd",
                action=BanAction.BAN,
                timestamp=datetime(2026, 7, 1, 12, 0, i),
            )
            tmp_db.record_ban(event)

        history = tmp_db.get_ban_history(days=365)
        assert len(history) == 10

    def test_record_unban(self, tmp_db):
        """Запишите событие разблокировки и проверьте правильность поля action."""
        event = BanEvent(
            ip="192.0.2.1",
            jail="sshd",
            action=BanAction.UNBAN,
            timestamp=datetime(2026, 7, 1, 12, 0, 0),
        )
        tmp_db.record_ban(event)

        history = tmp_db.get_ban_history(days=365)
        assert len(history) == 1
        assert history[0].action == BanAction.UNBAN

    def test_matches_truncation(self, tmp_db):
        """Тест matches Поле усекается, если его длина превышает 500 символов."""
        long_matches = "x" * 600
        event = BanEvent(
            ip="192.0.2.1",
            jail="sshd",
            action=BanAction.BAN,
            matches=long_matches,
            timestamp=datetime(2026, 7, 1, 12, 0, 0),
        )
        tmp_db.record_ban(event)

        history = tmp_db.get_ban_history(days=365)
        assert len(history[0].matches) <= 500


class TestBanHistory:
    """Тест запроса истории банов"""

    def test_get_history_days_filter(self, tmp_db):
        """Тестовая фильтрация истории по количеству дней."""
        # Запишите событие, произошедшее 30 дней назад.
        old_event = BanEvent(
            ip="10.0.0.1",
            jail="sshd",
            action=BanAction.BAN,
            timestamp=datetime.now() - timedelta(days=30),
        )
        # Запишите событие сегодня
        new_event = BanEvent(
            ip="10.0.0.2",
            jail="sshd",
            action=BanAction.BAN,
            timestamp=datetime.now(),
        )
        tmp_db.record_ban(old_event)
        tmp_db.record_ban(new_event)

        # Запрос за последние 7 дней, должны быть только новые события
        history_7 = tmp_db.get_ban_history(days=7)
        assert len(history_7) == 1
        assert history_7[0].ip == "10.0.0.2"

        # Запрос за последние 60 дней, есть оба
        history_60 = tmp_db.get_ban_history(days=60)
        assert len(history_60) == 2

    def test_get_history_empty(self, tmp_db):
        """Запросы к пустой базе данных не должны сообщать об ошибках."""
        history = tmp_db.get_ban_history(days=365)
        assert history == []

    def test_get_history_desc_order(self, tmp_db):
        """История отсортирована в обратном хронологическом порядке."""
        for i in range(3):
            event = BanEvent(
                ip=f"10.0.0.{i}",
                jail="sshd",
                action=BanAction.BAN,
                timestamp=datetime(2026, 7, 1, 12, 0, i),
            )
            tmp_db.record_ban(event)

        history = tmp_db.get_ban_history(days=365)
        # Сначала это должно быть самое новое.
        assert history[0].ip == "10.0.0.2"
        assert history[1].ip == "10.0.0.1"
        assert history[2].ip == "10.0.0.0"

    def test_mark_notified(self, tmp_db):
        """Функция уведомления о тестовой отметке."""
        event = BanEvent(
            ip="10.0.0.1",
            jail="sshd",
            action=BanAction.BAN,
            timestamp=datetime.now(),
        )
        tmp_db.record_ban(event)
        unnotified = tmp_db.get_unnotified_bans()
        assert len(unnotified) == 1

        event_id = unnotified[0][0]
        tmp_db.mark_notified(event_id)

        unnotified_after = tmp_db.get_unnotified_bans()
        assert len(unnotified_after) == 0


class TestCurrentBans:
    """Текущий запрещенный тест снимков"""

    def test_set_and_get_current_bans(self, tmp_db):
        """Запишите и прочитайте текущий запрещенный снимок."""
        bans = [
            ("192.0.2.1", "sshd"),
            ("192.0.2.2", "sshd"),
            ("203.0.113.1", "nginx-http-auth"),
        ]
        tmp_db.set_current_bans(bans)

        result = tmp_db.get_current_bans()
        assert len(result) == 3
        assert ("192.0.2.1", "sshd") in result
        assert ("203.0.113.1", "nginx-http-auth") in result

    def test_get_current_bans_empty(self, tmp_db):
        """Пустые запросы моментальных снимков не должны сообщать об ошибках."""
        bans = tmp_db.get_current_bans()
        assert bans == []

    def test_set_overwrites_previous(self, tmp_db):
        """set снова перезапишет предыдущий снимок."""
        tmp_db.set_current_bans([("192.0.2.1", "sshd")])
        tmp_db.set_current_bans([("192.0.2.2", "sshd")])

        result = tmp_db.get_current_bans()
        assert len(result) == 1
        assert result[0] == ("192.0.2.2", "sshd")

    def test_record_ban_syncs_current_bans(self, tmp_db):
        """record_ban(BAN) должен быть записан синхронно с таблицей current_bans."""
        event = BanEvent(
            ip="203.0.113.1",
            jail="sshd",
            action=BanAction.BAN,
            timestamp=datetime(2026, 7, 11, 14, 30, 0),
        )
        tmp_db.record_ban(event)

        bans = tmp_db.get_current_bans()
        assert ("203.0.113.1", "sshd") in bans

    def test_record_unban_removes_from_current_bans(self, tmp_db):
        """record_ban(UNBAN) должен удалить соответствующую запись из таблицы current_bans."""
        # Сначала запишите бан
        ban_event = BanEvent(
            ip="203.0.113.1",
            jail="sshd",
            action=BanAction.BAN,
            timestamp=datetime(2026, 7, 11, 14, 30, 0),
        )
        tmp_db.record_ban(ban_event)

        # Убедитесь, что current_bans включен.
        bans_before = tmp_db.get_current_bans()
        assert ("203.0.113.1", "sshd") in bans_before

        # разблокировка записи
        unban_event = BanEvent(
            ip="203.0.113.1",
            jail="sshd",
            action=BanAction.UNBAN,
            timestamp=datetime(2026, 7, 11, 15, 0, 0),
        )
        tmp_db.record_ban(unban_event)

        # Подтвердите, что current_bans был удален.
        bans_after = tmp_db.get_current_bans()
        assert ("203.0.113.1", "sshd") not in bans_after


class TestDailyStats:
    """Тест ежедневной статистики"""

    def test_update_and_get_daily_stats(self, tmp_db):
        """Напишите и запросите ежедневную статистику."""
        today = datetime.now()
        date1 = today.strftime("%Y-%m-%d")
        date2 = (today - timedelta(days=1)).strftime("%Y-%m-%d")

        tmp_db.update_daily_stats(date2, 10, 5, "US")
        tmp_db.update_daily_stats(date1, 20, 8, "CN")

        stats = tmp_db.get_daily_stats(days=10)
        assert len(stats) == 2

        # Сортировать по дате в обратном порядке
        assert stats[0].date == date1
        assert stats[0].total_bans == 20
        assert stats[0].unique_ips == 8
        assert stats[0].top_country == "CN"

    def test_upsert_overwrites(self, tmp_db):
        """upsert Поведение: Другая запись в тот же день должна обновить данные."""
        today_str = datetime.now().strftime("%Y-%m-%d")

        tmp_db.update_daily_stats(today_str, 10, 5, "US")
        tmp_db.update_daily_stats(today_str, 15, 7, "CN")

        stats = tmp_db.get_daily_stats(days=10)
        assert len(stats) == 1
        assert stats[0].total_bans == 15
        assert stats[0].unique_ips == 7
        assert stats[0].top_country == "CN"

    def test_get_daily_stats_days_filter(self, tmp_db):
        """Фильтрация статистики по дням."""
        # Получить вчерашнюю дату
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        old_date = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d")

        tmp_db.update_daily_stats(yesterday, 10, 5, "US")
        tmp_db.update_daily_stats(old_date, 20, 8, "CN")

        # Запрос за последние 7 дней, это должно быть только вчера.
        stats = tmp_db.get_daily_stats(days=7)
        assert len(stats) == 1
        assert stats[0].date == yesterday

    def test_get_daily_stats_empty(self, tmp_db):
        """Пустой запрос статистики."""
        stats = tmp_db.get_daily_stats(days=30)
        assert stats == []


class TestCountBansToday:
    """Сегодняшний тест статистики банов"""

    def test_count_bans_today(self, tmp_db):
        """Посчитайте количество банов сегодня."""
        today = datetime.now().strftime("%Y-%m-%d")
        for i in range(3):
            event = BanEvent(
                ip=f"10.0.0.{i}",
                jail="sshd",
                action=BanAction.BAN,
                timestamp=datetime.now(),
            )
            tmp_db.record_ban(event)

        # Также записывает событие разблокировки (не должно учитываться)
        unban = BanEvent(
            ip="10.0.0.1",
            jail="sshd",
            action=BanAction.UNBAN,
            timestamp=datetime.now(),
        )
        tmp_db.record_ban(unban)

        count = tmp_db.count_bans_today()
        assert count == 3

    def test_count_bans_today_empty(self, tmp_db):
        """Это 0 в случае пустой таблицы."""
        assert tmp_db.count_bans_today() == 0


class TestTopBannedIPs:
    """Бан IP Рейтинговый тест"""

    def test_top_banned_ips(self, tmp_db):
        """Логика ранжирования теста верна."""
        # IP 10.0.0.1 был заменен на ban 3 раза
        for _ in range(3):
            tmp_db.record_ban(BanEvent(
                ip="10.0.0.1", jail="sshd",
                action=BanAction.BAN, timestamp=datetime.now(),
            ))
        # IP 10.0.0.2 был заменен на ban 5 раз.
        for _ in range(5):
            tmp_db.record_ban(BanEvent(
                ip="10.0.0.2", jail="sshd",
                action=BanAction.BAN, timestamp=datetime.now(),
            ))
        # IP 10.0.0.3 заменен на ban 1 раз
        tmp_db.record_ban(BanEvent(
            ip="10.0.0.3", jail="sshd",
            action=BanAction.BAN, timestamp=datetime.now(),
        ))

        top = tmp_db.top_banned_ips(days=365, limit=10)
        assert len(top) >= 2
        assert top[0] == ("10.0.0.2", 5)
        assert top[1] == ("10.0.0.1", 3)

    def test_top_banned_ips_limit(self, tmp_db):
        """Проверьте параметр limit, чтобы ограничить количество результатов."""
        for i in range(10):
            tmp_db.record_ban(BanEvent(
                ip=f"10.0.0.{i}", jail="sshd",
                action=BanAction.BAN, timestamp=datetime.now(),
            ))

        top = tmp_db.top_banned_ips(days=365, limit=3)
        assert len(top) == 3

    def test_top_banned_ips_empty(self, tmp_db):
        """Пустая база данных возвращает пустой список."""
        assert tmp_db.top_banned_ips() == []


class TestTopBannedCountries:
    """Тест на рейтинг запрещенных стран"""

    def test_top_banned_countries(self, tmp_db):
        """Тестовые страны ранжированы правильно."""
        for _ in range(4):
            tmp_db.record_ban(BanEvent(
                ip="1.1.1.1", jail="sshd",
                action=BanAction.BAN, country="US", timestamp=datetime.now(),
            ))
        for _ in range(7):
            tmp_db.record_ban(BanEvent(
                ip="2.2.2.2", jail="sshd",
                action=BanAction.BAN, country="CN", timestamp=datetime.now(),
            ))
        for _ in range(2):
            tmp_db.record_ban(BanEvent(
                ip="3.3.3.3", jail="sshd",
                action=BanAction.BAN, country="RU", timestamp=datetime.now(),
            ))

        top = tmp_db.top_banned_countries(days=365, limit=10)
        assert top[0] == ("CN", 7)
        assert top[1] == ("US", 4)
        assert top[2] == ("RU", 2)

    def test_top_banned_countries_excludes_empty(self, tmp_db):
        """Пустые поля country не должны участвовать в ранжировании."""
        for _ in range(3):
            tmp_db.record_ban(BanEvent(
                ip="1.1.1.1", jail="sshd",
                action=BanAction.BAN, country="", timestamp=datetime.now(),
            ))

        top = tmp_db.top_banned_countries(days=365, limit=10)
        assert all(c != "" for c, _ in top)

    def test_top_banned_countries_empty(self, tmp_db):
        """Пустая база данных возвращает пустой список."""
        assert tmp_db.top_banned_countries() == []


class TestConfigOverride:
    """Настройка тестирования покрытия"""

    def test_set_and_get_override(self, tmp_db):
        """Устанавливает и считывает переопределения конфигурации."""
        tmp_db.set_config_override("test_key", "test_value")
        val = tmp_db.get_config_override("test_key")
        assert val == "test_value"

    def test_get_override_default(self, tmp_db):
        """key, который не существует, возвращает значение по умолчанию."""
        val = tmp_db.get_config_override("nonexistent", default="fallback")
        assert val == "fallback"

    def test_set_override_overwrites(self, tmp_db):
        """Установка того же key перезаписывает старое значение."""
        tmp_db.set_config_override("key1", "v1")
        tmp_db.set_config_override("key1", "v2")
        assert tmp_db.get_config_override("key1") == "v2"

    def test_delete_override(self, tmp_db):
        """После удаления запрос должен вернуть значение по умолчанию."""
        tmp_db.set_config_override("key1", "v1")
        tmp_db.delete_config_override("key1")
        assert tmp_db.get_config_override("key1", "gone") == "gone"


class TestBoundaryConditions:
    """Проверка граничных условий"""

    def test_large_dataset(self, tmp_db):
        """Запись больших данных и проверка производительности запросов."""
        count = 200
        for i in range(count):
            tmp_db.record_ban(BanEvent(
                ip=f"10.0.{i // 256}.{i % 256}",
                jail=("sshd" if i % 2 == 0 else "nginx-http-auth"),
                action=BanAction.BAN,
                timestamp=datetime.now(),
            ))

        history = tmp_db.get_ban_history(days=365)
        assert len(history) == count

        top_ips = tmp_db.top_banned_ips(days=365, limit=50)
        assert len(top_ips) == 50

    def test_init_is_idempotent(self, tmp_db):
        """init() не сообщает об ошибке при многократном вызове."""
        tmp_db.init()
        tmp_db.init()
        tmp_db.init()
        # Данные могут быть вставлены обычным образом
        tmp_db.record_ban(BanEvent(
            ip="10.0.0.1", jail="sshd",
            action=BanAction.BAN, timestamp=datetime.now(),
        ))
        assert tmp_db.count_bans_today() == 1
