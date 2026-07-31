"""
f2b_manager.monitor.health
===========================

Проверка работоспособности Fail2ban и автоматическое восстановление.

Периодически проверяется состояние службы fail2ban:
1. Выполняется fail2ban-client ping для проверки ответа службы
2. Проверяется статус службы systemd
3. При сбое — автоматический перезапуск (до 3 раз), после превышения лимита только оповещение
4. Уведомления об аномалиях отправляются через Telegram Bot
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from typing import Optional

from ..config import AppConfig
from ..storage.models import IMessageSender
from ..utils.logger import get_logger

logger = get_logger("monitor.health")


class HealthChecker:
    """Проверка работоспособности Fail2ban.

    Основная логика:
        check() → ping_fail2ban
            ↓ успех → сброс счётчика повторов → True
            ↓ сбой
        check_systemd_status()
            ↓ лимит не достигнут → restart_fail2ban() → пауза 3 сек → повторный ping
            ↓ лимит достигнут → только оповещение → False

    Параметры конструктора:
        config: глобальная конфигурация приложения (переключатель health_alert)
        bot: интерфейс отправки сообщений (может быть None — тогда только логирование)

    Usage:
        checker = HealthChecker(config, bot)
        ok = await checker.check()           # выполнить проверку
        print(checker.restart_count)         # текущее число повторов
        checker.reset_restart_count()        # сброс вручную
    """

    # Максимальное число автоматических перезапусков; после превышения — только оповещение
    MAX_RESTART_ATTEMPTS = 3

    # Пауза после перезапуска для стабилизации службы (секунды)
    RESTART_STABILIZE_SECONDS = 3

    def __init__(
        self,
        config: AppConfig,
        bot: Optional[IMessageSender] = None,
    ):
        self._config = config
        self._bot = bot

        # Счётчик попыток перезапуска (сбрасывается после восстановления службы)
        self._restart_count = 0

    # ── Публичные методы ──────────────────────────────

    async def check(self) -> bool:
        """Выполнить полную проверку работоспособности.

        Алгоритм:
        1. ping fail2ban → при успехе сброс счётчика и True
        2. Проверка статуса службы systemd
        3. Если лимит повторов не превышен → systemctl restart fail2ban
        4. Ожидание стабилизации → повторная проверка ping
        5. Отправка соответствующих оповещений

        Returns:
            True — служба работает или восстановлена автоматически.
            False — сбой и восстановление не удалось.
        """
        # Шаг 1: ping
        if self._ping_fail2ban():
            if self._restart_count > 0:
                logger.info(
                    "Служба fail2ban восстановлена (ранее было %d попыток перезапуска)",
                    self._restart_count,
                )
            self._restart_count = 0
            return True

        # Шаг 2: сбой службы
        logger.warning("Сбой службы fail2ban (ping не прошёл)")

        # Шаг 3: статус systemd
        systemd_status = self._check_systemd_status()
        logger.info("Статус службы fail2ban в systemd: %s", systemd_status)

        # Шаг 4: решение о повторной попытке
        if self._restart_count >= self.MAX_RESTART_ATTEMPTS:
            # Лимит исчерпан — только оповещение, без перезапуска
            logger.error(
                "Автовосстановление fail2ban: достигнут лимит (%d попыток), повторы прекращены",
                self.MAX_RESTART_ATTEMPTS,
            )
            await self._send_alert(
                "🚨 <b>Автовосстановление Fail2ban не удалось</b>\n\n"
                f"Выполнено {self.MAX_RESTART_ATTEMPTS} попыток перезапуска — безуспешно.\n\n"
                "Проверьте вручную:\n"
                "  • <code>systemctl status fail2ban</code>\n"
                "  • <code>journalctl -u fail2ban -n 50</code>\n"
                "  • <code>fail2ban-client -v start</code>"
            )
            return False

        # Шаг 5: попытка перезапуска
        attempt = self._restart_count + 1
        logger.info(
            "Попытка перезапуска fail2ban (%d/%d)...",
            attempt, self.MAX_RESTART_ATTEMPTS,
        )

        restart_ok = self._restart_fail2ban()
        self._restart_count += 1

        if restart_ok:
            # Ожидание стабилизации службы
            await asyncio.sleep(self.RESTART_STABILIZE_SECONDS)

            if self._ping_fail2ban():
                logger.info("fail2ban перезапущен, служба восстановлена")
                await self._send_alert(
                    "✅ <b>Fail2ban автоматически восстановлен</b>\n\n"
                    f"Попытка перезапуска: {self._restart_count}-я\n"
                    "Текущее состояние: работает нормально"
                )
                self._restart_count = 0
                return True
            else:
                logger.warning(
                    "После перезапуска fail2ban ping по-прежнему не проходит "
                    "(осталось попыток: %d)",
                    self.MAX_RESTART_ATTEMPTS - self._restart_count,
                )
                await self._send_alert(
                    "⚠️ <b>Fail2ban после перезапуска всё ещё недоступен</b>\n\n"
                    f"Попытка перезапуска: {self._restart_count}/{self.MAX_RESTART_ATTEMPTS}\n"
                    "Будут продолжены попытки перезапуска..."
                )
        else:
            logger.error(
                "Команда перезапуска fail2ban завершилась с ошибкой "
                "(осталось попыток: %d)",
                self.MAX_RESTART_ATTEMPTS - self._restart_count,
            )
            await self._send_alert(
                "❌ <b>Не удалось перезапустить Fail2ban</b>\n\n"
                f"Попытка: {self._restart_count}/{self.MAX_RESTART_ATTEMPTS}\n"
                "Команда <code>systemctl restart fail2ban</code> завершилась с ошибкой"
            )

        return False

    def reset_restart_count(self) -> None:
        """Сбросить счётчик повторов.

        Вызывается после ручного восстановления службы администратором,
        чтобы следующий сбой не учитывал старые попытки.
        """
        self._restart_count = 0
        logger.info("Счётчик повторов сброшен вручную")

    @property
    def restart_count(self) -> int:
        """Текущее число попыток перезапуска."""
        return self._restart_count

    # ── Внутренние методы ─────────────────────────────

    def _ping_fail2ban(self) -> bool:
        """Выполнить fail2ban-client ping и проверить ответ службы.

        Returns:
            True — служба отвечает (ping вернул pong).
        """
        try:
            result = subprocess.run(
                ["fail2ban-client", "ping"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and "pong" in result.stdout.lower():
                logger.debug("fail2ban ping успешен")
                return True
            else:
                logger.debug(
                    "fail2ban ping не прошёл: rc=%d stdout=%s stderr=%s",
                    result.returncode,
                    result.stdout.strip(),
                    result.stderr.strip(),
                )
                return False
        except FileNotFoundError:
            logger.error("fail2ban-client не установлен")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("Таймаут fail2ban-client ping")
            return False
        except Exception as e:
            logger.error("Ошибка fail2ban ping: %s", e)
            return False

    def _check_systemd_status(self) -> str:
        """Проверить статус службы fail2ban в systemd.

        Returns:
            Человекочитаемое описание статуса.
        """
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "fail2ban"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            status = result.stdout.strip()
            mapping = {
                "active": "active (работает)",
                "inactive": "inactive (остановлена)",
                "failed": "failed (ошибка запуска)",
                "activating": "activating (запускается)",
                "deactivating": "deactivating (останавливается)",
            }
            return mapping.get(status, f"unknown ({status})")
        except FileNotFoundError:
            return "systemctl недоступен (не systemd-система)"
        except Exception as e:
            logger.warning("Не удалось проверить статус systemd: %s", e)
            return f"Ошибка запроса: {e}"

    def _restart_fail2ban(self) -> bool:
        """Перезапустить службу fail2ban через systemctl.

        Returns:
            True — команда systemctl restart завершилась с кодом 0.
        """
        try:
            result = subprocess.run(
                ["systemctl", "restart", "fail2ban"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("fail2ban успешно перезапущен")
                return True
            else:
                logger.error(
                    "Не удалось перезапустить fail2ban: rc=%d stderr=%s",
                    result.returncode,
                    result.stderr.strip(),
                )
                return False
        except FileNotFoundError:
            logger.error("systemctl недоступен, перезапуск невозможен")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Таймаут systemctl restart")
            return False
        except Exception as e:
            logger.error("Ошибка перезапуска fail2ban: %s", e)
            return False

    async def _send_alert(self, message: str) -> None:
        """Отправить оповещение о проверке работоспособности.

        Перед отправкой проверяется:
        - переключатель notify.enable_health_alert
        - наличие bot и notify_chat_id
        """
        if not self._config.notify.enable_health_alert:
            logger.debug("Оповещения о проверке работоспособности отключены")
            return

        if self._bot is None:
            logger.debug("bot не настроен, отправка оповещения пропущена")
            return

        chat_id = self._config.telegram.notify_chat_id
        if chat_id == 0:
            logger.warning("notify_chat_id не задан, оповещение не отправлено")
            return

        try:
            await self._bot.send_alert(
                chat_id=chat_id,
                message=message,
                parse_mode="HTML",
            )
            logger.info("Оповещение о проверке работоспособности отправлено")
        except Exception as e:
            logger.error("Не удалось отправить оповещение о проверке работоспособности: %s", e)
