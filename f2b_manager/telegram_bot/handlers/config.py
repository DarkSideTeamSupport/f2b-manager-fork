"""
f2b_manager.telegram_bot.handlers.config
==========================================

Обработчик команд управления настройками.

Команды:
    /whitelist [add|remove <ip>]  — просмотр и управление белым списком
    /setnotify on|off              — включение/выключение оповещений в реальном времени
    /setschedule <type> <args>     — настройка расписания отчётов

Права:
    /whitelist     — администратор (ADMIN)
    /setnotify     — оператор (OPERATOR) и выше
    /setschedule   — администратор (ADMIN)
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from ...storage.models import AuthLevel
from ..auth import ensure_authorized, require_admin, require_operator
from ..deps import get_deps
from ..formatters import esc, format_error, format_success
from ..keyboards import (
    CB_SCHEDULE, CB_F2BCFG, WEEKDAY_MAP,
    BANTIME_PRESETS, FINDTIME_PRESETS,
    MAXRETRY_PRESETS, MAX_BANTIME_PRESETS,
    schedule_main_keyboard, schedule_time_keyboard, schedule_weekday_keyboard,
    f2bconfig_main_keyboard, f2bconfig_preset_keyboard,
)

logger = logging.getLogger(__name__)

# Ключи переопределения конфигурации.
KEY_WHITELIST = "whitelist_ips"
KEY_NOTIFY_ENABLED = "notify_enabled"
KEY_SCHEDULE_DAILY_TIME = "schedule_daily_time"
KEY_SCHEDULE_DAILY_ENABLED = "schedule_daily_enabled"
KEY_SCHEDULE_WEEKLY_TIME = "schedule_weekly_time"
KEY_SCHEDULE_WEEKLY_DAY = "schedule_weekly_day"
KEY_SCHEDULE_WEEKLY_ENABLED = "schedule_weekly_enabled"

# Ключи переопределения параметров Fail2ban.
KEY_F2B_BANTIME = "f2b_bantime"
KEY_F2B_FINDTIME = "f2b_findtime"
KEY_F2B_MAXRETRY = "f2b_maxretry"
KEY_F2B_INCREMENTAL = "f2b_incremental"
KEY_F2B_MAX_BANTIME = "f2b_max_bantime"

VALID_DAYS = [
    "monday", "tuesday", "wednesday", "thursday",
    "friday", "saturday", "sunday",
]


# ──────────────────────────────────────────────
# /whitelist
# ──────────────────────────────────────────────

@require_admin
async def cmd_whitelist(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/whitelist [add|remove <ip>] — просмотр и управление белым списком."""
    deps = get_deps(context)

    # Без параметров: показываем текущий белый список.
    if not context.args:
        await _show_whitelist(update, deps)
        return

    sub = context.args[0].lower()

    if sub in ("add", "remove", "del", "delete") and len(context.args) < 2:
        await update.message.reply_text(
            format_error("Использование: /whitelist add|remove <ip>"), parse_mode="HTML"
        )
        return

    if sub in ("add",):
        await _whitelist_add(update, context, deps)
    elif sub in ("remove", "del", "delete"):
        await _whitelist_remove(update, context, deps)
    else:
        await update.message.reply_text(
            format_error(
                "Использование:\n"
                "  /whitelist              — показать белый список\n"
                "  /whitelist add <ip>     — добавить IP в белый список\n"
                "  /whitelist remove <ip>  — удалить IP из белого списка"
            ),
            parse_mode="HTML",
        )


def _get_whitelist(deps) -> list[str]:
    """Читает белый список из db (config_overrides)."""
    if deps.db is None:
        return list(deps.config.fail2ban.ignoreip)
    raw = deps.db.get_config_override(KEY_WHITELIST, "")
    if raw:
        return [ip.strip() for ip in raw.split(",") if ip.strip()]
    return list(deps.config.fail2ban.ignoreip)


def _set_whitelist(deps, ips: list[str]) -> None:
    """Сохраняет белый список в db."""
    if deps.db is None:
        return
    deps.db.set_config_override(KEY_WHITELIST, ",".join(ips))


async def _show_whitelist(update, deps) -> None:
    """Показывает текущий белый список."""
    ips = _get_whitelist(deps)

    lines = ["\U0001f6e1\ufe0f <b>Белый список IP</b>", ""]

    if not ips:
        lines.append("Белый список пуст")
    else:
        for i, ip in enumerate(ips, 1):
            lines.append(f"  {i}. <code>{esc(ip)}</code>")

    lines.append("")
    lines.append("Использование: /whitelist add|remove <ip>")

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


async def _whitelist_add(update, context, deps) -> None:
    """Добавляет IP в белый список."""
    from .ban import validate_ip

    ip = context.args[1].strip()

    if not validate_ip(ip):
        await update.message.reply_text(
            format_error(f"Недопустимый IP-адрес: {ip}"), parse_mode="HTML"
        )
        return

    ips = _get_whitelist(deps)
    if ip in ips:
        await update.message.reply_text(
            format_error(f"{ip} уже находится в белом списке"), parse_mode="HTML"
        )
        return

    ips.append(ip)
    _set_whitelist(deps, ips)

    await update.message.reply_text(
        format_success(f"{ip} добавлен в белый список\n\nВсего IP в белом списке: {len(ips)}"),
        parse_mode="HTML",
    )

    # Напоминаем о необходимости перезагрузки.
    if deps.f2b_manager is not None:
        await update.message.reply_text(
            "\u2139\ufe0f Белый список сохранён. Выполните команду /reload, чтобы применить изменения.",
            parse_mode="HTML",
        )


async def _whitelist_remove(update, context, deps) -> None:
    """Удаляет IP из белого списка."""
    ip = context.args[1].strip()

    ips = _get_whitelist(deps)
    if ip not in ips:
        await update.message.reply_text(
            format_error(f"{ip} отсутствует в белом списке"), parse_mode="HTML"
        )
        return

    ips.remove(ip)
    _set_whitelist(deps, ips)

    await update.message.reply_text(
        format_success(f"{ip} удалён из белого списка\n\nВсего IP в белом списке: {len(ips)}"),
        parse_mode="HTML",
    )


# ──────────────────────────────────────────────
# /setnotify
# ──────────────────────────────────────────────

@require_operator
async def cmd_setnotify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/setnotify on|off — включение/выключение оповещений в реальном времени."""
    deps = get_deps(context)

    if not context.args:
        # Показать текущий статус
        current = "on"
        if deps.db is not None:
            current = deps.db.get_config_override(KEY_NOTIFY_ENABLED, "on")

        status_icon = "\U0001f7e2" if current == "on" else "\U0001f534"
        await update.message.reply_text(
            f"{status_icon} <b>Оповещения в реальном времени:</b> {current}\n\n"
            "Использование: /setnotify on|off",
            parse_mode="HTML",
        )
        return

    arg = context.args[0].lower()

    if arg not in ("on", "off"):
        await update.message.reply_text(
            format_error("Использование: /setnotify on|off"), parse_mode="HTML"
        )
        return

    if deps.db is None:
        await update.message.reply_text(
            format_error("База состояния не загружена, сохранить настройки нельзя"),
            parse_mode="HTML",
        )
        return

    deps.db.set_config_override(KEY_NOTIFY_ENABLED, arg)

    status_icon = "\U0001f7e2" if arg == "on" else "\U0001f534"
    await update.message.reply_text(
        format_success(
            f"Оповещения в реальном времени {'включены' if arg == 'on' else 'выключены'}"
        ),
        parse_mode="HTML",
    )

    logger.info(
        "Оповещения установлены в %s (chat_id=%s)",
        arg,
        update.effective_chat.id,
    )


# ──────────────────────────────────────────────
# /setschedule
# ──────────────────────────────────────────────

@require_admin
async def cmd_setschedule(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/setschedule — панель настройки расписания отчётов."""
    await _show_schedule_panel(update, context)


async def handle_schedule_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обрабатывает все callback-кнопки настройки расписания."""
    if not await ensure_authorized(update, context, AuthLevel.ADMIN):
        return

    query = update.callback_query
    await query.answer()

    data = query.data or ""
    deps = get_deps(context)

    if not data.startswith(CB_SCHEDULE):
        return

    action = data[len(CB_SCHEDULE) + 1:]  # убрать префикс "sch_"

    if action == "del":
        await query.delete_message()
        return

    if action == "main":
        await _refresh_panel(query, deps)
        return

    if action == "tog_d":
        await _toggle_schedule(query, deps, "daily")
        return

    if action == "tog_w":
        await _toggle_schedule(query, deps, "weekly")
        return

    if action == "timed":
        await _show_time_picker(query, "daily")
        return

    if action == "timew":
        await _show_time_picker(query, "weekly")
        return

    if action == "dayw":
        await _show_day_picker(query, deps)
        return

    # Установка времени: sch_tm_daily:08:00 или sch_tm_weekly:12:00
    if action.startswith("tm_"):
        rest = action[3:]  # "daily:08:00" или "weekly:12:00"
        target, _, time_str = rest.partition(":")
        await _set_time(query, deps, target, time_str)
        return

    # Установка дня недели: sch_dy_monday
    if action.startswith("dy_"):
        day = action[3:]
        await _set_weekday(query, deps, day)
        return


# ── Внутренние вспомогательные функции ────────

def _read_schedule(deps) -> dict:
    """Читает текущие настройки расписания отчётов."""
    cfg = deps.config.schedule
    result = {
        "daily_enabled": cfg.daily_report_enabled,
        "daily_time": cfg.daily_report_time,
        "weekly_enabled": cfg.weekly_report_enabled,
        "weekly_day": cfg.weekly_report_day,
        "weekly_time": cfg.weekly_report_time,
    }
    if deps.db is not None:
        en = deps.db.get_config_override(KEY_SCHEDULE_DAILY_ENABLED, "")
        if en:
            result["daily_enabled"] = en == "on"
        tm = deps.db.get_config_override(KEY_SCHEDULE_DAILY_TIME, "")
        if tm:
            result["daily_time"] = tm
        en = deps.db.get_config_override(KEY_SCHEDULE_WEEKLY_ENABLED, "")
        if en:
            result["weekly_enabled"] = en == "on"
        tm = deps.db.get_config_override(KEY_SCHEDULE_WEEKLY_TIME, "")
        if tm:
            result["weekly_time"] = tm
        dy = deps.db.get_config_override(KEY_SCHEDULE_WEEKLY_DAY, "")
        if dy:
            result["weekly_day"] = dy
    return result


async def _show_schedule_panel(update, context, from_callback: bool = False) -> None:
    """Показывает панель настройки расписания отчётов."""
    deps = get_deps(context)
    s = _read_schedule(deps)

    text = "⏰ <b>Настройка расписания отчётов</b>"
    keyboard = schedule_main_keyboard(
        daily_enabled=s["daily_enabled"],
        daily_time=s["daily_time"],
        weekly_enabled=s["weekly_enabled"],
        weekly_day=s["weekly_day"],
        weekly_time=s["weekly_time"],
    )

    if from_callback:
        query = update.callback_query
        await query.edit_message_text(text, reply_markup=keyboard, parse_mode="HTML")
    else:
        await update.message.reply_text(text, reply_markup=keyboard, parse_mode="HTML")


async def _refresh_panel(query, deps) -> None:
    """Обновляет панель (оставляет текущее меню)."""
    s = _read_schedule(deps)
    text = "⏰ <b>Настройка расписания отчётов</b>"
    keyboard = schedule_main_keyboard(
        daily_enabled=s["daily_enabled"],
        daily_time=s["daily_time"],
        weekly_enabled=s["weekly_enabled"],
        weekly_day=s["weekly_day"],
        weekly_time=s["weekly_time"],
    )
    await query.edit_message_text(text, reply_markup=keyboard, parse_mode="HTML")


async def _show_time_picker(query, target: str) -> None:
    """Показывает клавиатуру выбора времени."""
    label = "ежедневного" if target == "daily" else "еженедельного"
    text = f"🕐 <b>Выберите время {label} отчёта</b>"
    keyboard = schedule_time_keyboard(target)
    await query.edit_message_text(text, reply_markup=keyboard, parse_mode="HTML")


async def _show_day_picker(query, deps) -> None:
    """Показывает клавиатуру выбора дня недели."""
    s = _read_schedule(deps)
    text = "📅 <b>Выберите день еженедельного отчёта</b>"
    keyboard = schedule_weekday_keyboard(s["weekly_day"])
    await query.edit_message_text(text, reply_markup=keyboard, parse_mode="HTML")


async def _toggle_schedule(query, deps, target: str) -> None:
    """Переключает включение отчёта."""
    if deps.db is None:
        await query.answer("База состояния не загружена", show_alert=True)
        return

    if target == "daily":
        key_en = KEY_SCHEDULE_DAILY_ENABLED
        label = "Ежедневный отчёт"
    else:
        key_en = KEY_SCHEDULE_WEEKLY_ENABLED
        label = "Еженедельный отчёт"

    current = deps.db.get_config_override(key_en, "")
    if not current:
        # Значение по умолчанию из config
        cfg = deps.config.schedule
        current = "on" if (
            cfg.daily_report_enabled if target == "daily" else cfg.weekly_report_enabled
        ) else "off"

    new_val = "off" if current == "on" else "on"
    deps.db.set_config_override(key_en, new_val)

    await query.answer(f"{label} {'включён' if new_val == 'on' else 'выключен'}")
    await _refresh_panel(query, deps)


async def _set_time(query, deps, target: str, time_str: str) -> None:
    """Устанавливает время отчёта."""
    if deps.db is None:
        await query.answer("База состояния не загружена", show_alert=True)
        return

    if not _validate_time(time_str):
        await query.answer(f"Неверное время: {time_str}", show_alert=True)
        return

    if target == "daily":
        deps.db.set_config_override(KEY_SCHEDULE_DAILY_TIME, time_str)
        deps.db.set_config_override(KEY_SCHEDULE_DAILY_ENABLED, "on")
    else:
        deps.db.set_config_override(KEY_SCHEDULE_WEEKLY_TIME, time_str)
        deps.db.set_config_override(KEY_SCHEDULE_WEEKLY_ENABLED, "on")

    kind = "Ежедневный" if target == "daily" else "Еженедельный"
    await query.answer(f"{kind} отчёт: время {time_str}")
    await _refresh_panel(query, deps)


async def _set_weekday(query, deps, day: str) -> None:
    """Устанавливает день еженедельного отчёта."""
    if deps.db is None:
        await query.answer("База состояния не загружена", show_alert=True)
        return

    if day not in VALID_DAYS:
        await query.answer(f"Неверный день недели: {day}", show_alert=True)
        return

    deps.db.set_config_override(KEY_SCHEDULE_WEEKLY_DAY, day)
    deps.db.set_config_override(KEY_SCHEDULE_WEEKLY_ENABLED, "on")

    for eng, chn in WEEKDAY_MAP:
        if eng == day:
            await query.answer(
                f"Еженедельный отчёт: {chn} {_read_schedule(deps)['weekly_time']}"
            )
            break

    await _refresh_panel(query, deps)


def _validate_time(time_str: str) -> bool:
    """Проверяет формат HH:MM."""
    try:
        parts = time_str.split(":")
        if len(parts) != 2:
            return False
        h, m = int(parts[0]), int(parts[1])
        return 0 <= h <= 23 and 0 <= m <= 59
    except (ValueError, IndexError):
        return False


# ──────────────────────────────────────────────
# /f2bconfig — панель параметров Fail2ban
# ──────────────────────────────────────────────

@require_admin
async def cmd_f2bconfig(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/f2bconfig — панель параметров fail2ban."""
    await _show_f2bconfig_panel(update, context)


async def handle_f2bconfig_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обрабатывает все callback-кнопки настроек fail2ban."""
    if not await ensure_authorized(update, context, AuthLevel.ADMIN):
        return

    query = update.callback_query
    await query.answer()

    data = query.data or ""
    deps = get_deps(context)

    if not data.startswith(CB_F2BCFG):
        return

    action = data[len(CB_F2BCFG) + 1:]  # убрать префикс "f2bcfg_"

    if action == "del":
        await query.delete_message()
        return

    if action == "main":
        await _refresh_f2bconfig(query, deps)
        return

    if action == "tog_inc":
        await _toggle_incremental(query, deps)
        return

    if action == "apply":
        await _apply_f2b_config(query, deps)
        return

    # Панель предустановок: f2bcfg_bantime / findtime / maxretry / maxbt
    if action in ("bantime", "findtime", "maxretry", "maxbt"):
        presets_map = {
            "bantime": (BANTIME_PRESETS, "длительность блокировки"),
            "findtime": (FINDTIME_PRESETS, "окно обнаружения"),
            "maxretry": (MAXRETRY_PRESETS, "макс. число попыток"),
            "maxbt": (MAX_BANTIME_PRESETS, "макс. длительность блокировки"),
        }
        presets, label = presets_map[action]
        cfg = _read_f2b_config(deps)
        # action → ключ конфигурации
        key_map = {
            "bantime": cfg["bantime"], "findtime": cfg["findtime"],
            "maxretry": str(cfg["maxretry"]), "maxbt": cfg["max_bantime"],
        }
        text = f"⚙️ <b>Выберите {label}</b>"
        keyboard = f2bconfig_preset_keyboard(action, presets, key_map[action])
        await query.edit_message_text(text, reply_markup=keyboard, parse_mode="HTML")
        return

    # Установка значения: f2bcfg_set_bantime:1h
    if action.startswith("set_"):
        rest = action[4:]  # "bantime:1h"
        target, _, val = rest.partition(":")
        await _set_f2b_param(query, deps, target, val)
        return


def _read_f2b_config(deps) -> dict:
    """Читает текущую конфигурацию fail2ban (с переопределениями из БД)."""
    cfg = deps.config.fail2ban
    result = {
        "bantime": cfg.default_bantime,
        "findtime": cfg.default_findtime,
        "maxretry": cfg.default_maxretry,
        "incremental": cfg.incremental,
        "max_bantime": cfg.max_bantime,
    }
    if deps.db is not None:
        for key, dbkey in [
            ("bantime", KEY_F2B_BANTIME), ("findtime", KEY_F2B_FINDTIME),
            ("maxretry", KEY_F2B_MAXRETRY), ("max_bantime", KEY_F2B_MAX_BANTIME),
        ]:
            val = deps.db.get_config_override(dbkey, "")
            if val:
                result[key] = val
        inc = deps.db.get_config_override(KEY_F2B_INCREMENTAL, "")
        if inc:
            result["incremental"] = inc == "on"
    # maxretry возвращаем как int
    result["maxretry"] = int(result["maxretry"])
    return result


async def _show_f2bconfig_panel(update, context, from_callback: bool = False) -> None:
    """Показывает панель параметров fail2ban."""
    deps = get_deps(context)
    cfg = _read_f2b_config(deps)

    lines = ["⚙️ <b>Параметры Fail2ban</b>", ""]
    lines.append(f"⏱ Длительность блокировки: <code>{cfg['bantime']}</code>")
    lines.append(f"🔍 Окно обнаружения: <code>{cfg['findtime']}</code>")
    lines.append(f"🔢 Макс. попыток: <code>{cfg['maxretry']}</code>")
    lines.append(
        f"{'✅' if cfg['incremental'] else '❌'} Нарастающая блокировка: "
        f"{'вкл.' if cfg['incremental'] else 'выкл.'}"
    )
    lines.append(f"📈 Макс. длительность: <code>{cfg['max_bantime']}</code>")

    text = "\n".join(lines)
    keyboard = f2bconfig_main_keyboard(
        bantime=cfg["bantime"],
        findtime=cfg["findtime"],
        maxretry=cfg["maxretry"],
        incremental=cfg["incremental"],
        max_bantime=cfg["max_bantime"],
    )

    if from_callback:
        query = update.callback_query
        await query.edit_message_text(text, reply_markup=keyboard, parse_mode="HTML")
    else:
        await update.message.reply_text(text, reply_markup=keyboard, parse_mode="HTML")


async def _refresh_f2bconfig(query, deps) -> None:
    """Обновляет панель параметров."""
    cfg = _read_f2b_config(deps)
    lines = ["⚙️ <b>Параметры Fail2ban</b>", ""]
    lines.append(f"⏱ Длительность блокировки: <code>{cfg['bantime']}</code>")
    lines.append(f"🔍 Окно обнаружения: <code>{cfg['findtime']}</code>")
    lines.append(f"🔢 Макс. попыток: <code>{cfg['maxretry']}</code>")
    lines.append(
        f"{'✅' if cfg['incremental'] else '❌'} Нарастающая блокировка: "
        f"{'вкл.' if cfg['incremental'] else 'выкл.'}"
    )
    lines.append(f"📈 Макс. длительность: <code>{cfg['max_bantime']}</code>")

    text = "\n".join(lines)
    keyboard = f2bconfig_main_keyboard(
        bantime=cfg["bantime"],
        findtime=cfg["findtime"],
        maxretry=cfg["maxretry"],
        incremental=cfg["incremental"],
        max_bantime=cfg["max_bantime"],
    )
    await query.edit_message_text(text, reply_markup=keyboard, parse_mode="HTML")


async def _set_f2b_param(query, deps, target: str, val: str) -> None:
    """Устанавливает один параметр fail2ban."""
    if deps.db is None:
        await query.answer("База состояния не загружена", show_alert=True)
        return

    key_map = {
        "bantime": (KEY_F2B_BANTIME, "Длительность блокировки"),
        "findtime": (KEY_F2B_FINDTIME, "Окно обнаружения"),
        "maxretry": (KEY_F2B_MAXRETRY, "Макс. число попыток"),
        "maxbt": (KEY_F2B_MAX_BANTIME, "Макс. длительность блокировки"),
    }

    if target not in key_map:
        await query.answer(f"Неизвестный параметр: {target}", show_alert=True)
        return

    dbkey, label = key_map[target]
    deps.db.set_config_override(dbkey, val)
    await query.answer(f"{label}: {val}")
    await _refresh_f2bconfig(query, deps)


async def _toggle_incremental(query, deps) -> None:
    """Переключает нарастающую блокировку."""
    if deps.db is None:
        await query.answer("База состояния не загружена", show_alert=True)
        return

    cfg = _read_f2b_config(deps)
    new_val = "off" if cfg["incremental"] else "on"
    deps.db.set_config_override(KEY_F2B_INCREMENTAL, new_val)
    await query.answer(
        f"Нарастающая блокировка {'включена' if new_val == 'on' else 'выключена'}"
    )
    await _refresh_f2bconfig(query, deps)


async def _apply_f2b_config(query, deps) -> None:
    """Применяет конфигурацию: пересоздаёт jail.local и перезагружает fail2ban."""
    if deps.f2b_manager is None:
        await query.answer("Модуль управления Fail2ban не готов", show_alert=True)
        return

    cfg = _read_f2b_config(deps)
    try:
        # Пересоздаём jail.local через config_builder установщика
        installer = deps.get_installer()
        if installer is not None and hasattr(installer, "_builder"):
            # Обновляем атрибуты config в builder по значениям из БД
            builder = installer._builder
            builder._config.default_bantime = cfg["bantime"]
            builder._config.default_findtime = cfg["findtime"]
            builder._config.default_maxretry = cfg["maxretry"]
            builder._config.incremental = cfg["incremental"]
            builder._config.max_bantime = cfg["max_bantime"]

            jail_content = builder.generate_jail_local()
            with open("/etc/fail2ban/jail.local", "w") as f:
                f.write(jail_content)
            # Перезагрузка fail2ban
            deps.f2b_manager.reload()
            await query.answer("Конфигурация применена, fail2ban перезагружен", show_alert=True)
        else:
            await query.answer("Установщик не готов, сгенерировать конфигурацию нельзя", show_alert=True)
    except Exception as e:
        logger.error("Не удалось применить конфигурацию fail2ban: %s", e)
        await query.answer(f"Ошибка применения: {e}", show_alert=True)
