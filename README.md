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

## Автоматическое применение лимитов клиентов
В продакшене лимиты теперь запускаются автоматически через **Celery Beat**:
- `worker` выполняет задачу `vpn.tasks.enforce_client_limits_task`;
- `beat` планирует запуск этой задачи по расписанию из настроек Django.

Расписание задается переменной окружения:
- `LIMITS_ENFORCE_EVERY_MINUTES` (по умолчанию `5` минут).

Для запуска с `docker compose` сервис `beat` уже добавлен в `docker-compose.yml`, отдельный cron/systemd для лимитов не требуется.


### Endpoint readiness flow
Если сервер локальный (`127.0.0.1`/`localhost`) и runtime не дал публичный host, оператор должен один раз заполнить `public_endpoint_host` (и опционально `public_endpoint_port`) в Server через Django Admin. После этого экспорт конфигов выполняется без ручного редактирования endpoint.
