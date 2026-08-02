# XHTTP CDN в amnezia-control

Функция выпускает отдельные Happ JSON-профили VLESS/XHTTP для существующих `VPNClient`. Каждый профиль имеет собственный UUID и управляется независимо через `/xhttp/`.

## Рабочая схема

```text
Happ
→ TLS/HTTP2
→ cdn.vpn.protopopov.pro
→ Yandex Cloud CDN
→ nginx origin.vpn.protopopov.pro
→ Xray 127.0.0.1:8080
→ Интернет
```

Параметры профиля задаются через `.env`:

```env
XHTTP_CDN_DOMAIN=cdn.vpn.protopopov.pro
XHTTP_PATH=/api/ad4f850643d5e660f09d31f9
XHTTP_SC_MAX_EACH_POST_BYTES=2048
XHTTP_SC_MIN_POSTS_INTERVAL_MS=30
XHTTP_UPLINK_CHUNK_SIZE=1800
XHTTP_SERVER_MAX_HEADER_BYTES=65536
```

## Установка helper на Xray VPS

Helper должен находиться на том же сервере, который указан в `Server` для клиента. Он изменяет только управляемый inbound `vless-xhttp-yandex`, проверяет временный конфиг через `xray run -test`, применяет его атомарно и откатывается при ошибке.

На Xray VPS от root:

```bash
install -m 0750 -o root -g root \
  scripts/amnezia-control-xhttp \
  /usr/local/sbin/amnezia-control-xhttp
```

Разрешите SSH-пользователю из `Server.ssh_username` запускать только helper от root. Пример для пользователя `amnezia`:

```bash
cat >/etc/sudoers.d/amnezia-control-xhttp <<'EOF'
amnezia ALL=(root) NOPASSWD: /usr/local/sbin/amnezia-control-xhttp *
EOF

chmod 0440 /etc/sudoers.d/amnezia-control-xhttp
visudo -cf /etc/sudoers.d/amnezia-control-xhttp
```

Helper принадлежит `root:root`, не должен быть доступен на запись SSH-пользователю и валидирует действие, UUID и техническую метку. Дополнительно команда проходит allowlist `SafeSSHExecutor` в приложении.

## Обновление приложения

```bash
docker compose up -d --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py check
```

После миграции откройте:

```text
https://vpn.protopopov.pro/xhttp/
```

## Операции

- **Создать XHTTP** — добавляет UUID в Xray и сохраняет зашифрованный Happ JSON в PostgreSQL.
- **Скачать JSON** — выдаёт расшифрованную конфигурацию только авторизованному staff-пользователю.
- **Проверить** — убеждается, что UUID присутствует в Xray и конфигурация Xray валидна.
- **Отключить** — удаляет только этот UUID из Xray.
- **Включить** — возвращает существующий UUID в Xray.
- **Перевыпустить** — отзывает старый UUID, создаёт новый и обновляет Happ JSON.
- **Удалить** — отзывает UUID и скрывает устройство из рабочего списка.

При отключении или истечении родительского `VPNClient` XHTTP-устройства автоматически согласуются через Celery. Устройства, отключённые вручную, не включаются автоматически при повторной активации клиента.

## Резервные копии и откат

Перед каждым изменением helper сохраняет Xray-конфиг в:

```text
/var/backups/amnezia-control/xray-config-<UTC timestamp>.json
```

Хранятся последние 50 копий. При неуспешной проверке или перезапуске Xray helper автоматически возвращает предыдущий конфиг.

## Ограничения MVP

- XHTTP-трафик пока не добавляется к счётчику AWG/AWG2 `traffic_used_bytes`.
- Импорт выполняется готовым JSON-файлом в Happ; отдельная QR-ссылка не реализована.
- Параметры Yandex CDN и origin по-прежнему администрируются вне Django.
