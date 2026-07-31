# Руководство по устранению неполадок f2b-manager

> При проблемах следуйте порядку «симптом → причина → решение».
> В конце приведён **справочник диагностических команд**.

---

## 1. Сервис не запускается

### Симптом
```bash
systemctl start f2b-manager
# Job failed. See "systemctl status f2b-manager" and "journalctl"
```

### Шаги диагностики

**1. Просмотрите подробный журнал**
```bash
journalctl -u f2b-manager -n 50 --no-pager
```

**2. Распространённые причины**

| Причина | Симптом | Решение |
|------|------|------|
| Устаревшая версия Python | `module ... requires Python '>=3.10'` | Обновите Python до 3.10+ и снова запустите `install.sh` |
| Отсутствует виртуальное окружение | `No such file or directory: /opt/f2b-manager/venv/bin/python` | Повторно выполните `sudo bash install.sh` |
| Нет конфигурационного файла | `Конфигурационный файл не найден` | `cp /opt/f2b-manager/config.example.yaml /etc/f2b-manager/config.yaml` |
| Ошибка проверки конфигурации | `Ошибка конфигурации: bot_token не указан` | Укажите фактический `bot_token` в `config.yaml` |
| Не установлены зависимости | `ModuleNotFoundError: No module named 'telegram'` | `sudo /opt/f2b-manager/venv/bin/pip install -r /opt/f2b-manager/requirements.txt` |
| Конфликт прав/порта | `Permission denied` | Убедитесь, что сервис работает от root (`User=root`) |

**3. Быстрая самопроверка**
```bash
# 1) Пробный запуск через Python из venv (выводит результат проверки конфигурации)
sudo /opt/f2b-manager/venv/bin/python -m f2b_manager run --dry-run

# 2) Убедитесь, что файл сервиса существует и сервис включён
systemctl cat f2b-manager
```

---

## 2. Bot не отвечает на команды

### Симптом
Bot не отвечает на `/status` в Telegram.

### Шаги диагностики

**1. Убедитесь, что сервис запущен**
```bash
systemctl status f2b-manager --no-pager
```

**2. Проверьте правильность bot_token**
```bash
# Найдите в журнале ошибки, связанные с token
journalctl -u f2b-manager -n 100 --no-pager | grep -i "token\|unauthorized\|401"
```
- `401 Unauthorized` означает, что `bot_token` неверен или больше недействителен; скопируйте его повторно из @BotFather.
- В Token есть двоеточие `:`; копируйте всю строку без пробелов в начале и конце.

**3. Убедитесь, что Bot не отключён**
Отправьте Bot `/start` в Telegram. Если не отвечает даже он, обычно проблема в token или незапущенном процессе.

**4. Проверьте авторизацию chat_id**
```bash
journalctl -u f2b-manager -n 100 --no-pager | grep -i "unauthorized\|not authorized\|chat"
```
- Если выводится «Не авторизован», добавьте свой `chat_id` в `admin_chat_ids` в `config.yaml`, затем:
  ```bash
  systemctl restart f2b-manager
  ```
- Свой chat_id можно узнать командой `/start`.

**5. Проверьте наличие нескольких экземпляров (конфликт polling)**
Два процесса с одним Token перехватывают сообщения друг у друга, поэтому Bot отвечает нестабильно.
```bash
ps aux | grep "python -m f2b_manager" | grep -v grep
```
Убедитесь, что процесс один. Завершите лишние и выполните `systemctl restart f2b-manager`.

**6. Проверьте доступ сервера к Telegram**
```bash
curl -s https://api.telegram.org/bot<TOKEN>/getMe
```
Если ответ содержит `"ok":true` и правильное имя Bot, сеть работает. При тайм-ауте проверьте firewall и правила исходящего трафика.

---

## 3. fail2ban не установлен или установка не удалась

### Симптом
- `/status` сообщает, что fail2ban недоступен;
- команда `f2b-manager fail2ban install` в `install.sh` завершается ошибкой.

### Шаги диагностики

**1. Убедитесь, что fail2ban установлен**
```bash
which fail2ban-server fail2ban-client
fail2ban-client --version
systemctl status fail2ban --no-pager
```

**2. Установите вручную, если автоматическая установка не удалась**
```bash
# Debian / Ubuntu
apt-get update && apt-get install -y fail2ban

# CentOS / RHEL / Rocky
dnf install -y fail2ban

systemctl enable --now fail2ban
```

**3. Передайте настройку fail2ban в управление f2b-manager**
```bash
f2b-manager fail2ban install     # создаёт jail.local и развёртывает Telegram action
systemctl restart fail2ban
systemctl restart f2b-manager
```

**4. Ошибка определения дистрибутива**
Если `install.sh` сообщает, что не может определить дистрибутив, проверьте наличие и содержимое `/etc/os-release`. В крайнем случае установите fail2ban вручную и запустите `sudo bash install.sh --no-fail2ban`.

---

## 4. Уведомления не приходят

### Симптом
fail2ban блокирует IP (в журнале есть `Ban 1.2.3.4`), но уведомление о блокировке в Telegram не приходит.

### Шаги диагностики

**1. Убедитесь, что уведомления в реальном времени включены**
```bash
# Отправьте в Telegram
/setnotify on
```
Также проверьте, что в `config.yaml` указано `notify.enable_ban_alert: true`.

**2. Проверьте notify_chat_id**
Получателем уведомлений является `notify_chat_id`; он должен совпадать с chat_id, в котором вы получаете сообщения.
```bash
grep notify_chat_id /etc/f2b-manager/config.yaml
```

**3. Проверьте скрипт-мост**
Уведомления в реальном времени зависят от вызова `/usr/local/bin/f2b-notify.sh` через action fail2ban.
```bash
ls -l /usr/local/bin/f2b-notify.sh      # файл должен существовать и иметь права 755
cat /etc/fail2ban/action.d/telegram-notify.conf | grep actionban
```
- Если `f2b-notify.sh` отсутствует, повторно запустите `install.sh` или выполните вручную:
  ```bash
  cp scripts/f2b-notify.sh /usr/local/bin/f2b-notify.sh
  chmod 755 /usr/local/bin/f2b-notify.sh
  ```
- Если отсутствует `telegram-notify.conf`, повторно выполните `f2b-manager fail2ban install`.

**4. Убедитесь, что к jail подключён Telegram action**
```bash
fail2ban-client get sshd actions
# Вывод должен содержать telegram-notify
```
Если отсутствует, Telegram action не добавлен в `jail.local`. Повторно выполните `f2b-manager fail2ban install`, затем `fail2ban-client reload`.

**5. Проверьте работу демона f2b-manager**
Скрипт-мост передаёт событие демону, который отправляет сообщение. Если демон остановлен, события теряются; резервный polling компенсирует их, но требует работающего процесса.
```bash
systemctl status f2b-manager
journalctl -u f2b-manager -n 50 --no-pager | grep -i "notify\|ban"
```

**6. Ошибка GeoIP мешает отправке?**
Если включён `geoip.method: local`, но база отсутствует, определение местоположения завершится ошибкой, но отправка не должна блокироваться. Для проверки временно отключите геолокацию:
```yaml
notify:
  geoip:
    enabled: false
```
Затем выполните `systemctl restart f2b-manager`.

---

## 5. Задержка уведомлений в реальном времени

- **Нормальное поведение**: hook срабатывает за секунды; резервный polling компенсирует пропущенные события раз в 5 минут.
- Если уведомления совсем не приходят и доступны только отчёты, обычно не подключён **action** (см. раздел 4, шаг 4).
- Случайная задержка на несколько минут соответствует окну компенсации резервного polling.

---

## 6. Проблемы с правами конфигурационного файла

Права `config.yaml` должны быть строго `600` (чтение только root); иначе приложение может не запуститься или выдать предупреждение.

```bash
chmod 600 /etc/f2b-manager/config.yaml
chown root:root /etc/f2b-manager/config.yaml
```

---

## 7. Просмотр журналов

```bash
# Журнал демона (systemd)
journalctl -u f2b-manager -f

# Собственный файл журнала приложения
tail -f /var/log/f2b-manager.log

# Журнал fail2ban
tail -f /var/log/fail2ban.log
```

---

## 8. Чистая переустановка

Если окружение находится в неконсистентном состоянии, выполните чистую переустановку:

```bash
# 1. Удаление (с интерактивным подтверждением удаления конфигурации)
sudo bash uninstall.sh -y

# 2. Очистка остатков (при необходимости)
rm -rf /opt/f2b-manager /etc/f2b-manager /var/lib/f2b-manager

# 3. Загрузите актуальный код и установите заново
sudo bash install.sh
sudo vim /etc/f2b-manager/config.yaml   # укажите token / chat_id
systemctl start f2b-manager
```

---

## 9. Справочник диагностических команд

```bash
# Состояние сервисов
systemctl status f2b-manager --no-pager
systemctl status fail2ban --no-pager

# Журналы
journalctl -u f2b-manager -n 100 --no-pager
journalctl -u f2b-manager -f

# Проверка конфигурации
sudo /opt/f2b-manager/venv/bin/python -m f2b_manager run --dry-run

# Состояние fail2ban
f2b-manager status
fail2ban-client status
fail2ban-client banned
fail2ban-client get sshd actions

# Проверка файлов
ls -l /usr/local/bin/f2b-manager /usr/local/bin/f2b-notify.sh
ls -l /etc/f2b-manager/config.yaml
cat /etc/fail2ban/action.d/telegram-notify.conf | grep actionban

# Проверка сети
curl -s https://api.telegram.org/bot<TOKEN>/getMe

# Проверка процессов (предотвращает несколько экземпляров)
ps aux | grep "python -m f2b_manager" | grep -v grep
```

---

## 10. Проблему не удалось устранить?

Соберите и предоставьте следующую информацию:
1. вывод `journalctl -u f2b-manager -n 200 --no-pager`;
2. вывод `systemctl status f2b-manager --no-pager`;
3. `config.yaml` (**сначала удалите bot_token и другие секретные поля**);
4. дистрибутив и версию Python: `cat /etc/os-release | head -n3; python3 --version`.
