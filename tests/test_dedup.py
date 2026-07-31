"""
tests/test_dedup.py
===================
Тест логики ограничения тока дедупликации.

Охват: Первый выпуск уведомления / Дедупликация в пределах окна / Выпуск после истечения срока действия окна / Различные IP не влияют /
       reset / reset_all / cleanup / Потокобезопасный.
"""
from __future__ import annotations

import time
import threading

import pytest

from f2b_manager.notify.dedup import DedupTracker


class TestShouldSend:
    """Тест на дедупликацию"""

    def test_first_call_allows(self):
        """Первый звонок должен разрешить отправку."""
        tracker = DedupTracker(window_seconds=300)
        assert tracker.should_send("1.2.3.4", "sshd") is True

    def test_second_call_within_window_blocks(self):
        """Повторные вызовы внутри окна должны быть заблокированы."""
        tracker = DedupTracker(window_seconds=300)
        assert tracker.should_send("1.2.3.4", "sshd") is True
        assert tracker.should_send("1.2.3.4", "sshd") is False

    def test_after_window_expires_allows(self):
        """Повторные отправки должны быть разрешены после истечения срока действия окна."""
        tracker = DedupTracker(window_seconds=1)
        assert tracker.should_send("1.2.3.4", "sshd") is True
        assert tracker.should_send("1.2.3.4", "sshd") is False

        # Подождите, пока окно истечет
        time.sleep(1.1)
        assert tracker.should_send("1.2.3.4", "sshd") is True

    def test_different_ips_dont_interfere(self):
        """Дедупликация разных IP не влияет друг на друга."""
        tracker = DedupTracker(window_seconds=300)
        assert tracker.should_send("1.2.3.4", "sshd") is True
        assert tracker.should_send("5.6.7.8", "sshd") is True
        # Первый IP дедуплицирован.
        assert tracker.should_send("1.2.3.4", "sshd") is False
        # Второй IP также дедуплицирован.
        assert tracker.should_send("5.6.7.8", "sshd") is False

    def test_different_jails_dont_interfere(self):
        """Дедупликация одного и того же IP и разных jail не влияет друг на друга."""
        tracker = DedupTracker(window_seconds=300)
        assert tracker.should_send("1.2.3.4", "sshd") is True
        assert tracker.should_send("1.2.3.4", "nginx-http-auth") is True
        # Дедупликация sshd не влияет
        assert tracker.should_send("1.2.3.4", "sshd") is False
        assert tracker.should_send("1.2.3.4", "nginx-http-auth") is False

    def test_same_ip_same_jail_same_window_blocks(self):
        """Те же IP и тот же jail дедуплицируются в одном окне."""
        tracker = DedupTracker(window_seconds=10)
        assert tracker.should_send("10.0.0.1", "recidive") is True
        for _ in range(5):
            assert tracker.should_send("10.0.0.1", "recidive") is False

    def test_custom_window(self):
        """Пользовательское время окна вступает в силу."""
        tracker = DedupTracker(window_seconds=2)
        assert tracker.should_send("1.2.3.4", "sshd") is True
        assert tracker.should_send("1.2.3.4", "sshd") is False
        time.sleep(2.1)
        assert tracker.should_send("1.2.3.4", "sshd") is True


class TestReset:
    """Сброс теста работы"""

    def test_reset_single(self):
        """Сброс статуса дедупликации одной комбинации."""
        tracker = DedupTracker(window_seconds=300)
        tracker.should_send("1.2.3.4", "sshd")
        assert tracker.should_send("1.2.3.4", "sshd") is False

        tracker.reset("1.2.3.4", "sshd")
        # Отправка должна быть разрешена после сброса
        assert tracker.should_send("1.2.3.4", "sshd") is True

    def test_reset_all(self):
        """Очистите все состояния дедупликации."""
        tracker = DedupTracker(window_seconds=300)
        tracker.should_send("1.2.3.4", "sshd")
        tracker.should_send("5.6.7.8", "nginx-http-auth")

        assert len(tracker) == 2
        tracker.reset_all()
        assert len(tracker) == 0

        # Можно отправить после сброса
        assert tracker.should_send("1.2.3.4", "sshd") is True
        assert tracker.should_send("5.6.7.8", "nginx-http-auth") is True

    def test_reset_nonexistent_no_error(self):
        """При сбросе несуществующих комбинаций ошибок не будет."""
        tracker = DedupTracker()
        tracker.reset("nonexistent", "jail")

    def test_len_tracking(self):
        """__len__ правильно отслеживает количество комбинаций."""
        tracker = DedupTracker(window_seconds=300)
        assert len(tracker) == 0

        tracker.should_send("1.2.3.4", "sshd")
        assert len(tracker) == 1

        tracker.should_send("1.2.3.4", "sshd")  # Повторы не засчитываются
        assert len(tracker) == 1

        tracker.should_send("5.6.7.8", "sshd")
        assert len(tracker) == 2

        tracker.should_send("1.2.3.4", "nginx-http-auth")
        assert len(tracker) == 3


class TestCleanup:
    """Тест очистки просроченной записи"""

    def test_cleanup_removes_stale(self):
        """Очистка должна удалить просроченные записи."""
        tracker = DedupTracker(window_seconds=1)
        tracker.should_send("1.2.3.4", "sshd")

        # Подождите, пока истечет срок действия записи
        time.sleep(2.1)

        removed = tracker.cleanup(max_age_seconds=1)
        assert removed == 1
        assert len(tracker) == 0

    def test_cleanup_keeps_fresh(self):
        """Очистка должна сохранять записи с неистекшим сроком действия."""
        tracker = DedupTracker(window_seconds=300)
        tracker.should_send("1.2.3.4", "sshd")

        removed = tracker.cleanup(max_age_seconds=600)
        assert removed == 0
        assert len(tracker) == 1

    def test_cleanup_default_uses_2x_window(self):
        """Время очистки по умолчанию использует окно 2x."""
        tracker = DedupTracker(window_seconds=1)
        tracker.should_send("1.2.3.4", "sshd")
        time.sleep(2.1)

        # По умолчанию max_age = 2*window = 2 секунды, срок действия записи истек.
        removed = tracker.cleanup()
        assert removed == 1

    def test_cleanup_empty(self):
        """Пустой tracker очищается без сообщения об ошибке."""
        tracker = DedupTracker()
        removed = tracker.cleanup()
        assert removed == 0


class TestThreadSafety:
    """Тестирование безопасности потоков"""

    def test_concurrent_access(self):
        """Многопоточный параллелизм не должен вызывать сбоев или потери данных."""
        tracker = DedupTracker(window_seconds=10)
        errors = []

        def worker(ip_prefix: str):
            try:
                for i in range(50):
                    ip = f"{ip_prefix}.{i % 256}.{i % 256}"
                    tracker.should_send(ip, "sshd")
            except Exception as e:
                errors.append(e)

        threads = []
        for prefix in range(4):
            t = threading.Thread(target=worker, args=(f"10.{prefix}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0
        # Должно быть 4*50 = 200 записей (все разрешены впервые)
        assert len(tracker) == 200
