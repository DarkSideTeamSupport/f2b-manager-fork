# Руководство по развёртыванию f2b-manager

> Для начинающих пользователей и системных администраторов.
> Цель: полностью развернуть f2b-manager на Linux VPS (управление Fail2ban, Telegram Bot и уведомления в реальном времени).

---

## 1. Системные требования

| Компонент | Требование |
|------|------|
| Операционная система | Debian / Ubuntu / CentOS / RHEL / Rocky / AlmaLinux |
| Права | **root** (необходимы для установки и управления fail2ban) |
| Python | **3.10 или новее** |
| Управление процессом | systemd |
| Сеть | доступ к `api.telegram.org` по исходящему порту 443 |
| Дополнительно | аккаунт Telegram для получения уведомлений |

---

## 2. Подготовка Telegram Bot

### Шаг 1. Создайте Bot и получите Token

1. Найдите в Telegram **@BotFather** и откройте диалог.
2. Отправьте команду `/newbot`.
3. Укажите отображаемое имя Bot, например `My VPS Guard`.
4. Укажите имя пользователя Bot: оно должно оканчиваться на `bot`, например `my_vps_guard_bot`.
5. BotFather вернёт **Token**, который является значением `bot_token`:

```
Use this token to access the HTTP API:
123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567890
```

> ⚠️ **Token равнозначен паролю Bot. Не раскрывайте его и не отправляйте в публичные репозитории.**

### Шаг 2. Получите свой chat_id

`chat_id` — числовой идентификатор личного диалога между вами и Bot в Telegram. Чтобы получить его:

1. Откройте созданный Bot, нажмите **START** или отправьте любое сообщение, например `/start`.
2. Откройте в браузере URL ниже, заменив `TOKEN` на фактический Token:

```
https://api.telegram.org/botTOKEN/getUpdates
```

> Внимание: после `bot` **нет слеша** — используйте слитную запись `botTOKEN`.

3. Найдите в возвращённом JSON `result[0].message.chat.id`, например:

```json
{
  "ok": true,
  "result": [
    {
      "message": {
        "chat": { "id": 123456789, "type": "private" }
      }
    }
  ]
}
```

Значение `123456789` — ваш **chat_id**. Укажите его в `admin_chat_ids` и `notify_chat_id`.

> 💡 Если `result` пустой (`[]`), вы ещё не отправляли сообщение Bot. Отправьте его и обновите страницу.

---

## 3. Загрузка проекта на сервер

Передайте проект на VPS, например с помощью `scp`:

```bash
# Выполните на локальном компьютере
scp -r ./f2b-manager-fork root@IP_ВАШЕГО_СЕРВЕРА:/root/
```

Подключитесь к серверу по SSH и перейдите в каталог проекта:

```bash
ssh root@IP_ВАШЕГО_СЕРВЕРА
cd /root/f2b-manager-fork
```

> Можно также выполнить `git clone https://github.com/DarkSideTeamSupport/f2b-manager-fork.git`; на сервере должны присутствовать `install.sh`, `f2b_manager/`, `config/`, `systemd/` и `scripts/`.

---

## 4. Быстрая установка

```bash
sudo bash install.sh
```

Скрипт автоматически:

1. ✅ проверит права **root** и **Python 3.10+**;
2. ✅ создаст `/opt/f2b-manager` и `/etc/f2b-manager`;
3. ✅ скопирует код приложения в `/opt/f2b-manager`;
4. ✅ создаст виртуальное окружение Python и установит зависимости;
5. ✅ создаст CLI-обёртку `/usr/local/bin/f2b-manager`;
6. ✅ создаст `/etc/f2b-manager/config.yaml` с правами 600;
7. ✅ установит и настроит fail2ban (`f2b-manager fail2ban install`);
8. ✅ развернёт и включит автозапуск сервиса systemd;
9. ✅ развернёт скрипт-мост `/usr/local/bin/f2b-notify.sh`.

> Чтобы пропустить установку уже установленного fail2ban, добавьте аргумент:
> ```bash
> sudo bash install.sh --no-fail2ban
> ```

В конце успешной установки будет показано:

```
✅ f2b-manager установлен!

Дальнейшие действия:
  1. Отредактируйте конфигурацию: vim /etc/f2b-manager/config.yaml
     Замените bot_token / admin_chat_ids / notify_chat_id фактическими значениями.
  2. Запустите сервис: systemctl start f2b-manager
  3. Просмотрите журнал: journalctl -u f2b-manager -f
  4. Проверьте Telegram: отправьте Bot команду /start
```

---

## 5. Настройка конфигурации

Откройте конфигурационный файл:

```bash
vim /etc/f2b-manager/config.yaml
```

**Обязательно измените три значения**; остальные можно оставить по умолчанию:

```yaml
telegram:
  bot_token: "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567890"  # ← укажите свой Token
  admin_chat_ids: [123456789]        # ← укажите свой chat_id
  notify_chat_id: 123456789          # ← укажите chat_id получателя отчётов
```

После сохранения убедитесь, что права файла остаются `600`:

```bash
ls -l /etc/f2b-manager/config.yaml
# -rw------- 1 root root ... config.yaml
```

---

## 6. Запуск сервиса

```bash
systemctl start f2b-manager
systemctl status f2b-manager --no-pager
```

Ожидаемый статус: `active (running)`.

Просмотрите журнал в реальном времени, чтобы проверить подключение к Telegram:

```bash
journalctl -u f2b-manager -f
```

---

## 7. Проверка развёртывания

Отправьте своему Bot в Telegram следующие команды:

| Команда | Ожидаемый результат |
|------|----------|
| `/start` | Возвращает приветствие и ваш chat_id |
| `/status` | Показывает версию и состояние fail2ban, число jail и блокировок |
| `/jails` | Выводит включённые jail |

Если все три команды отвечают корректно, развёртывание завершено 🎉

---

## 8. Контрольный список начальной настройки

После развёртывания проверьте каждый пункт:

- [ ] Telegram Bot создан, `bot_token` получен.
- [ ] Сообщение Bot отправлено, `chat_id` получен.
- [ ] В `/etc/f2b-manager/config.yaml` указан `bot_token`.
- [ ] Указаны `admin_chat_ids` и `notify_chat_id`.
- [ ] Конфигурационный файл имеет права `600` (доступен только root).
- [ ] `systemctl status f2b-manager` показывает `active (running)`.
- [ ] Команда `/start` возвращает приветствие.
- [ ] Команда `/status` возвращает состояние fail2ban.
- [ ] Сервис fail2ban запущен: `systemctl status fail2ban`.
- [ ] Скрипт-мост существует: `ls -l /usr/local/bin/f2b-notify.sh`.

---

## 9. Необязательно: включение геолокации IP

Уведомления в реальном времени могут показывать страну/регион атакующего IP; для этого нужна база GeoLite2.

```bash
# Узнайте, как получить License Key и включить автоматическое обновление
sudo bash scripts/geoip-update.sh --setup

# Способ 1: официальный MaxMind (требуется Key)
export GEOIP_LICENSE_KEY="ВАШ_КЛЮЧ"
sudo bash scripts/geoip-update.sh

# Способ 2: публичное зеркало (Key не нужен, данные могут обновляться с задержкой)
sudo bash scripts/geoip-update.sh --mirror

# Включить еженедельное обновление (рекомендуется)
sudo bash scripts/geoip-update.sh --cron
```

Убедитесь, что в `config.yaml` указано:

```yaml
notify:
  geoip:
    enabled: true
    method: local
    db_path: "/var/lib/GeoIP/GeoLite2-Country.mmdb"
```

---

## 10. Обновление и переустановка

### Обновление приложения

```bash
cd /root/f2b-manager-fork
git pull            # или загрузите актуальную версию кода повторно
sudo bash install.sh --no-fail2ban   # использовать текущий fail2ban и обновить только приложение
systemctl restart f2b-manager
```

### Полное удаление

```bash
sudo bash uninstall.sh
```

Скрипт интерактивно спросит, удалять ли каталог приложения, конфигурацию, базу состояния и журналы. **По умолчанию конфигурация сохраняется** для упрощения переустановки.

---

## 11. Справочник каталогов и путей

| Назначение | Путь |
|------|------|
| Каталог приложения | `/opt/f2b-manager` |
| Виртуальное окружение | `/opt/f2b-manager/venv` |
| Конфигурационный файл | `/etc/f2b-manager/config.yaml` (права 600) |
| Сервис systemd | `/etc/systemd/system/f2b-manager.service` |
| Скрипт-мост | `/usr/local/bin/f2b-notify.sh` |
| CLI-обёртка | `/usr/local/bin/f2b-manager` |
| База состояния (SQLite) | `/var/lib/f2b-manager/state.db` |
| Журнал | `/var/log/f2b-manager.log` |
| База GeoIP | `/var/lib/GeoIP/GeoLite2-Country.mmdb` |
| Action fail2ban | `/etc/fail2ban/action.d/telegram-notify.conf` |
