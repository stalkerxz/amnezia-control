# amnezia-control

Приватная админ-панель для управления **существующим** Amnezia runtime на Ubuntu 24.04 x86_64.

## Целевой сценарий
- На VPS уже работают контейнеры: `amnezia-awg`, `amnezia-awg2`, `amnezia-panel-web`, `amnezia-panel-db`.
- `amnezia-control` запускается отдельно и безопасно: только `127.0.0.1:8090`.
- По умолчанию нет bind на `80/443`.

## Быстрый запуск (без конфликта с существующим nginx/Amnezia)
```bash
cp .env.example .env
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# вставьте ключ в CONFIG_ENCRYPTION_KEY

docker compose up -d --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

Открыть:
- `http://127.0.0.1:8090/login/`

## Режим HTTPS позже
- Первый запуск: `DJANGO_FORCE_SSL=0` (default) — без HTTP→HTTPS редиректа.
- После подключения reverse proxy: `DJANGO_FORCE_SSL=1`.

Пример:
```env
DJANGO_FORCE_SSL=1
DJANGO_ALLOWED_HOSTS=panel.internal.example
```

## Как работает реальная интеграция с runtime
### Обнаружение протоколов
На странице сервера кнопка **«Синхронизировать runtime»**:
- проверяет наличие контейнеров `amnezia-awg` и `amnezia-awg2` через `docker ps -a`;
- отдельно определяет running-состояние через `docker ps`;
- читает `docker inspect`;
- сохраняет статус контейнера, UDP порт, mounts, env, интерфейс и количество peers.

### Поддерживаемые операции
- отдельные адаптеры: AWG legacy (`awg` binary) и AWG2 (`wg` binary);
- импорт существующих peers в БД (`Импорт из runtime`);
- создание нового peer (генерация ключей в контейнере, `wg set peer`);
- disable/delete (remove peer);
- reissue (перегенерация ключей и peer);
- экспорт реального `.conf`;
- QR из расшифрованного активного конфига в памяти.

### Используемые allowlisted команды
- `docker ps --format '{{.Names}}'`
- `docker inspect <container>`
- `docker exec <container> wg show ...`
- `docker exec <container> wg genkey`
- `printf %s '<private_key>' | docker exec -i <container> wg pubkey`
- `docker exec <container> wg set <iface> peer <pubkey> ...`

## Безопасность
- строгая проверка SSH host key (RejectPolicy по умолчанию);
- `SSH_ALLOW_UNKNOWN_HOSTS=1` только для dev;
- конфиги клиента хранятся только encrypted-at-rest;
- plaintext не сохраняется в отдельные поля и не логируется в JobEvent для чувствительных команд.

## Проверка, что клиент реально создан
1. Создайте клиента в UI (`/clients/new/`).
2. Откройте `/jobs/` и убедитесь, что задания `awg.add_peer` / `awg2.add_peer` успешны.
3. Выполните sync runtime на `/servers/<id>/` и проверьте статус.
4. Скачайте `.conf` на `/clients/<id>/` и импортируйте в клиент.

## Полезные команды
```bash
make up
make migrate
make superuser
make test
make logs
make down
```
