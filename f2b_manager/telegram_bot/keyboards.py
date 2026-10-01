"""
f2b_manager.telegram_bot.keyboards
==================================

Компоненты встроенных клавиатур.

В основном используются для повторного подтверждения опасных операций (например, /uninstall).
"""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

# ── Константы callback-данных ─────────────────

CALLBACK_CONFIRM = "uninstall_confirm"
CALLBACK_CANCEL = "uninstall_cancel"


def confirm_uninstall_keyboard() -> InlineKeyboardMarkup:
    """Клавиатура подтверждения удаления (подтвердить / отменить)."""
    keyboard = [
        [
            InlineKeyboardButton(
                "\u26a0\ufe0f Подтвердить удаление", callback_data=CALLBACK_CONFIRM
            ),
            InlineKeyboardButton(
                "✖️ Отмена", callback_data=CALLBACK_CANCEL
            ),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


def confirm_keyboard(
    confirm_text: str = "Подтвердить",
    cancel_text: str = "Отмена",
    confirm_callback: str = "confirm",
    cancel_callback: str = "cancel",
) -> InlineKeyboardMarkup:
    """Универсальная клавиатура подтверждения."""
    keyboard = [
        [
            InlineKeyboardButton(
                confirm_text, callback_data=confirm_callback
            ),
            InlineKeyboardButton(
                cancel_text, callback_data=cancel_callback
            ),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


# ── Клавиатура настройки параметров Fail2ban ──

# Префикс callback-данных.
CB_F2BCFG = "f2bcfg"

# Предустановки параметров
BANTIME_PRESETS = ["10m", "30m", "1h", "2h", "6h", "12h", "1d", "7d"]
FINDTIME_PRESETS = ["5m", "10m", "30m", "1h", "2h"]
MAXRETRY_PRESETS = ["2", "3", "5", "10", "20"]
MAX_BANTIME_PRESETS = ["6h", "12h", "1d", "3d", "1w", "2w", "1M"]


def f2bconfig_main_keyboard(
    bantime: str, findtime: str, maxretry: int,
    incremental: bool, max_bantime: str,
) -> InlineKeyboardMarkup:
    """Главная панель настройки Fail2ban."""
    inc_text = "✅ Нарастающая блокировка: вкл." if incremental else "❌ Нарастающая блокировка: выкл."
    keyboard = [
        [InlineKeyboardButton(
            f"⏱ Срок блокировки: {bantime}", callback_data=f"{CB_F2BCFG}_bantime"
        )],
        [InlineKeyboardButton(
            f"🔍 Окно обнаружения: {findtime}", callback_data=f"{CB_F2BCFG}_findtime"
        )],
        [InlineKeyboardButton(
            f"🔢 Максимум попыток: {maxretry}", callback_data=f"{CB_F2BCFG}_maxretry"
        )],
        [InlineKeyboardButton(
            inc_text, callback_data=f"{CB_F2BCFG}_tog_inc"
        )],
        [InlineKeyboardButton(
            f"📈 Макс. срок бана: {max_bantime}", callback_data=f"{CB_F2BCFG}_maxbt"
        )],
        [
            InlineKeyboardButton(
                "🔄 Применить и перезагрузить fail2ban", callback_data=f"{CB_F2BCFG}_apply"
            ),
        ],
        [
            InlineKeyboardButton("✖ Закрыть", callback_data=f"{CB_F2BCFG}_del"),
        ],
    ]
    return InlineKeyboardMarkup(keyboard)


def f2bconfig_preset_keyboard(
    target: str, presets: list[str], current: str
) -> InlineKeyboardMarkup:
    """Клавиатура выбора предустановленного значения.

    Args:
        target: имя параметра (bantime/findtime/maxretry/maxbt)
        presets: список предустановленных значений
        current: текущее значение для выделения
    """
    keyboard = []
    row = []
    for val in presets:
        label = f"● {val}" if val == current else val
        row.append(InlineKeyboardButton(
            label, callback_data=f"{CB_F2BCFG}_set_{target}:{val}"
        ))
        if len(row) == 3:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([
        InlineKeyboardButton("↩ Назад", callback_data=f"{CB_F2BCFG}_main"),
        InlineKeyboardButton("✖ Закрыть", callback_data=f"{CB_F2BCFG}_del"),
    ])
    return InlineKeyboardMarkup(keyboard)


# ── Клавиатура настройки отчётов по расписанию ─

# Префикс callback-данных.
CB_SCHEDULE = "sch"

# Список предустановленных значений времени.
PRESET_TIMES = ["06:00", "08:00", "10:00", "12:00", "18:00", "20:00", "22:00"]

# Соответствия дней недели.
WEEKDAY_MAP = [
    ("monday", "Понедельник"),
    ("tuesday", "Вторник"),
    ("wednesday", "Среда"),
    ("thursday", "Четверг"),
    ("friday", "Пятница"),
    ("saturday", "Суббота"),
    ("sunday", "Воскресенье"),
]


def schedule_main_keyboard(
    daily_enabled: bool,
    daily_time: str,
    weekly_enabled: bool,
    weekly_day: str,
    weekly_time: str,
) -> InlineKeyboardMarkup:
    """Главная панель настройки отчётов по расписанию."""
    daily_label = f"{'🟢' if daily_enabled else '🔴'} Ежедневный отчёт: {daily_time}"
    weekly_label = f"{'🟢' if weekly_enabled else '🔴'} Еженедельный отчёт: {weekly_day} {weekly_time}"

    keyboard = [
        [
            InlineKeyboardButton(
                "✅ Включить ежедневный" if not daily_enabled else "❌ Отключить ежедневный",
                callback_data=f"{CB_SCHEDULE}_tog_d",
            ),
            InlineKeyboardButton(
                "🕐 Время ежедневного", callback_data=f"{CB_SCHEDULE}_timed"
            ),
        ],
        [
            InlineKeyboardButton(
                "✅ Включить еженедельный" if not weekly_enabled else "❌ Отключить еженедельный",
                callback_data=f"{CB_SCHEDULE}_tog_w",
            ),
            InlineKeyboardButton(
                "🕐 Время еженедельного", callback_data=f"{CB_SCHEDULE}_timew"
            ),
            InlineKeyboardButton(
                "📅 День еженедельного", callback_data=f"{CB_SCHEDULE}_dayw"
            ),
        ],
        [
            InlineKeyboardButton(
                "✖ Закрыть меню", callback_data=f"{CB_SCHEDULE}_del"
            ),
        ],
    ]
    # Строка состояния (некликабельная).
    status_line = f"{'🟢' if daily_enabled else '🔴'} Ежедневный: {daily_time} ｜ "
    status_line += f"{'🟢' if weekly_enabled else '🔴'} Еженедельный: {weekly_day} {weekly_time}"

    return InlineKeyboardMarkup(keyboard)


def schedule_time_keyboard(target: str) -> InlineKeyboardMarkup:
    """Клавиатура выбора предустановленного времени.

    Args:
        target: 'daily' или 'weekly', определяет целевую настройку
    """
    keyboard = []
    row = []
    for t in PRESET_TIMES:
        row.append(
            InlineKeyboardButton(t, callback_data=f"{CB_SCHEDULE}_tm_{target}:{t}")
        )
        if len(row) == 3:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([
        InlineKeyboardButton("↩ Назад", callback_data=f"{CB_SCHEDULE}_main"),
        InlineKeyboardButton("✖ Закрыть", callback_data=f"{CB_SCHEDULE}_del"),
    ])
    return InlineKeyboardMarkup(keyboard)


def schedule_weekday_keyboard(current_day: str = "monday") -> InlineKeyboardMarkup:
    """Клавиатура выбора дня недели.

    Args:
        current_day: текущий день недели для выделения
    """
    keyboard = []
    row = []
    for eng, chn in WEEKDAY_MAP:
        label = f"● {chn}" if eng == current_day else chn
        row.append(
            InlineKeyboardButton(label, callback_data=f"{CB_SCHEDULE}_dy_{eng}")
        )
        if len(row) == 4:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([
        InlineKeyboardButton("↩ Назад", callback_data=f"{CB_SCHEDULE}_main"),
        InlineKeyboardButton("✖ Закрыть", callback_data=f"{CB_SCHEDULE}_del"),
    ])
    return InlineKeyboardMarkup(keyboard)
