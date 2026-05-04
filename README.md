# amnezia-control

Приватная админ-панель для управления **существующим** Amnezia runtime на Ubuntu 24.04 x86_64.

## Целевой сценарий
- На VPS уже работают контейнеры: `amnezia-awg`, `amnezia-awg2`, `amnezia-panel-web`, `amnezia-panel-db`.
- `amnezia-control` запускается отдельно и безопасно: только `127.0.0.1:8090`.
- По умолчанию нет bind на `80/443`.

## Быстрый запуск
```bash
cp .env.example .env
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# вставьте ключ в CONFIG_ENCRYPTION_KEY

docker compose up -d --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

Открыть: `http://127.0.0.1:8090/login/`

## Реальная runtime-интеграция
### Discovery/sync
Кнопка **«Синхронизировать runtime»** делает:
- `docker ps -a` + `docker ps`;
- `docker inspect` для `amnezia-awg` и `amnezia-awg2`;
- `docker exec ... awg/wg show interfaces` + `show dump`;
- чтение live конфигов (`/etc/wireguard/<iface>.conf` / `/etc/amnezia/<iface>.conf`) для извлечения Address/ListenPort;
- для AWG2 дополнительно парсит protocol metadata (`S1/S2/H1/H2/H3/H4/...`) из env/config.

### Endpoint discovery (без placeholder)
Экспорт endpoint выбирается строго в порядке:
1. `Server.public_endpoint_host` (+ `public_endpoint_port`, если задан)
2. `Server.host` (только если это публичный IP/домен)
3. `ServerProtocol.runtime_metadata.public_host` из runtime sync

Порт: `public_endpoint_port` → runtime UDP port.
Если endpoint невалиден/локальный (`localhost`, `127.0.0.1`) — экспорт завершается ошибкой.

### Address pool discovery (без hardcode 10.8.0.0/24)
Подсеть берется из реально найденного `Address=` в live конфиге интерфейса.
Если подсеть не найдена — создание/переиздание клиента завершается явной ошибкой.

### AWG vs AWG2 export
- AWG legacy: отдельный билдер конфига.
- AWG2: отдельный билдер, который **требует полный набор** параметров: `I1-I5`, `S1-S4`, `Jc`, `Jmin`, `Jmax`, `H1-H4`.
- Канонические имена ключей в коде/metadata/export: именно `Jc`, `Jmin`, `Jmax` (без `JC/JMIN/JMAX` в сохраненных данных и экспорте).
- Если любой обязательный AWG2 параметр отсутствует — экспорт AWG2 блокируется явной ошибкой с перечнем недостающих ключей (без фейкового WireGuard fallback).

## Безопасность
- строгая проверка SSH host key (`RejectPolicy` по умолчанию);
- runtime bootstrap `known_hosts` перед SSH-подключением для `Server.host:Server.port` (без ручного копирования `/root/.ssh/known_hosts` после rebuild контейнеров);
- путь runtime `known_hosts` можно переопределить через `SSH_KNOWN_HOSTS_PATH` (по умолчанию `/tmp/amnezia-control/known_hosts`);
- allowlist команд docker/awg/wg/cat/ls;
- конфиги клиента хранятся encrypted-at-rest;
- QR генерируется в памяти на лету.

## Проверка, что клиент реально создан
1. Синхронизируйте runtime на `/servers/<id>/`.
2. Убедитесь, что для протокола заполнены Endpoint/Subnet (и AWG2 metadata ready для AWG2).
3. Создайте клиента в `/clients/new/`.
4. Проверьте `/jobs/` (команды add_peer/reissue должны быть успешны).
5. Скачайте `.conf` и импортируйте в клиент.

## Полезные команды
```bash
make up
make migrate
make superuser
make test
make logs
make down
```


## Email-напоминания администраторам об истечении VPN-клиентов
Администраторы могут получать одно сгруппированное письмо о VPN-клиентах, срок действия которых скоро закончится. Логика выбирает только активных клиентов с заполненным `expires_at`, не включает уже истёкших клиентов и сохраняет факт отправки в базе, чтобы не слать дубли для той же пары клиент/порог/дата истечения. Если клиенту продлили срок и `expires_at` изменился, напоминание для новой даты может быть отправлено снова.

Настройки окружения:
- `EXPIRATION_REMINDER_ENABLED` — включает/выключает отправку, по умолчанию `1`/`true`.
- `EXPIRATION_REMINDER_DAYS` — пороги в днях через запятую, по умолчанию `7,3,1`.
- `ADMIN_EXPIRATION_REMINDER_EMAILS` — получатели через запятую. Если пусто, используется Django `ADMINS`, если он настроен.
- `SITE_URL` или `PUBLIC_BASE_URL` — базовый URL для абсолютных ссылок на карточки клиентов в письме. Не задавайте production-домен в коде; используйте переменные окружения.
- `DEFAULT_FROM_EMAIL` — отправитель писем.
- `EMAIL_BACKEND` — Django email backend.
- `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS` — SMTP-настройки Django, если используется SMTP backend.
- `DJANGO_ADMINS` — опциональный fallback-список email-адресов администраторов через запятую для `ADMINS`.

Запуск вручную:
```bash
cd amnezia_control
python manage.py send_expiration_reminders
```

В `docker compose` уже есть Celery worker/beat, а beat ежедневно запускает `vpn.tasks.send_expiration_reminders_task` (`08:30`). Если проект развёрнут без Celery beat, добавьте cron/systemd timer для команды выше один раз в сутки.

## Автоматическое применение лимитов клиентов
В продакшене лимиты теперь запускаются автоматически через **Celery Beat**:
- `worker` выполняет задачу `vpn.tasks.enforce_client_limits_task`;
- `beat` планирует запуск этой задачи по расписанию из настроек Django.

Расписание задается переменной окружения:
- `LIMITS_ENFORCE_EVERY_MINUTES` (по умолчанию `5` минут).

Для запуска с `docker compose` сервис `beat` уже добавлен в `docker-compose.yml`, отдельный cron/systemd для лимитов не требуется.


### Endpoint readiness flow
Если сервер локальный (`127.0.0.1`/`localhost`) и runtime не дал публичный host, оператор должен один раз заполнить `public_endpoint_host` (и опционально `public_endpoint_port`) в Server через Django Admin. После этого экспорт конфигов выполняется без ручного редактирования endpoint.

## Хранение media (вложения продлений)
- `ClientRenewalRequest.attachment` хранится в `MEDIA_ROOT`.
- Для compose используется `MEDIA_ROOT=/data/media` и named volume `media_data`.
- Это исключает хранение вложений только внутри эфемерного слоя контейнера.

## Бэкап и восстановление (операторские скрипты)
Полный operational backup/restore выполняется скриптами из `scripts/`:

```bash
./scripts/backup_all.sh
./scripts/verify_backup.sh backups/runs/<YYYYMMDD-HHMMSS>
./scripts/restore_all.sh backups/runs/<YYYYMMDD-HHMMSS>
./scripts/restore_all.sh --restore-env backups/runs/<YYYYMMDD-HHMMSS>
./scripts/cleanup_backups.sh
```

Что входит в backup run (`backups/runs/<timestamp>/`):
- `postgres.sql.gz` — дамп PostgreSQL;
- `media.tar.gz` — архив `MEDIA_ROOT`/тома media (включая renewal attachments);
- `.env` — runtime-конфиг;
- `SHA256SUMS` — контрольные суммы;
- `meta.txt` — метаданные бэкапа.

Важно: `CONFIG_ENCRYPTION_KEY` из `.env` должен быть сохранен. Потеря ключа делает зашифрованные данные недешифруемыми.

Полный runbook: `docs/OPERATIONS.md`.

## Минимальная тестовая среда
- Для meaningful интеграционных проверок нужен PostgreSQL (проект настроен на `django.db.backends.postgresql`).
- Локальный быстрый структурный чек без БД: `python manage.py makemigrations --check --dry-run`.

## Post-deploy smoke-check
```bash
./scripts/post_deploy_smoke.sh
```
Скрипт проверяет:
- Django check
- отсутствие дрейфа моделей/миграций
- план миграций
- что endpoint скачивания вложений не отдается анониму напрямую

Подробные операционные заметки: `docs/OPERATIONS.md`.


## Уведомления (MVP, PR #63)
Реализован базовый слой уведомлений с событиями/получателями/каналами.

### Каналы в этом PR
- Реальные каналы: **email** и **telegram** (telegram — только для админов).
- Доставка запускается асинхронно через Celery task `notifications.tasks.deliver_notification_event`.
- Ошибки канала логируются и не ломают основной бизнес-поток.
- Каналы независимы: падение telegram не блокирует email и наоборот.

### События в этом PR
- `renewal_request_created` — новая заявка на продление (в т.ч. пометка о вложении).
- `renewal_request_status_changed` — изменения статуса заявки (для админов и клиентов).
- `client_access_expiring` — доступ клиента скоро истекает.
- `client_access_expired` — доступ клиента уже истёк.
- `background_job_failed` — базовая точка расширения при сбое фоновой задачи.

Для telegram (админы) в этом PR отправляются именно эти операционные события.

### Кто получает уведомления
- Админы: все активные `is_staff` пользователи с непустым `email`.
- Клиент: `VPNClient.contact_email` (если поле заполнено).
- Email можно задать при создании клиента и обновить в карточке клиента (блок «Изменить лимиты»).

### Настройки
- `NOTIFICATIONS_ENABLED` (по умолчанию `1`)
- `NOTIFICATIONS_CHANNELS` (например: `email`, `telegram`, `email,telegram`)
- `NOTIFICATIONS_EMAIL_FROM` (fallback на `DEFAULT_FROM_EMAIL`)
- `NOTIFICATIONS_BASE_URL` (базовый URL для абсолютных ссылок в письмах)
- `NOTIFICATIONS_EXPIRING_DAYS` (по умолчанию `3` дня)
- `NOTIFICATIONS_TELEGRAM_BOT_TOKEN` (токен Telegram бота)
- `NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS` (список chat id админов через запятую)
- `DEFAULT_FROM_EMAIL`, `EMAIL_BACKEND` — стандартные email-настройки Django

Telegram активируется только если одновременно заданы:
- канал `telegram` в `NOTIFICATIONS_CHANNELS`;
- `NOTIFICATIONS_TELEGRAM_BOT_TOKEN`;
- минимум один id в `NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS`.

Если telegram-конфиг отсутствует, telegram-канал тихо пропускается, email продолжает работать.

### Планировщик
- Celery beat запускает `notifications.tasks.notify_client_access_limits_task` ежедневно (`08:15`).
- В задаче есть простая дедупликация напоминаний через cache key, чтобы не рассылать дубли при частом запуске.

### Что остаётся на будущее
- Telegram уведомления клиентам (в этом PR telegram только для админов)
- внутренняя in-app лента уведомлений
- расширение событий backup/smoke по отдельным action/скриптам
