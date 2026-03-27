# amnezia-control

Приватная админ-панель для управления существующим Amnezia VPN сервером (AWG + AWG2-ready), безопасная для развертывания на VPS, где уже занят nginx на `80/443`.

## Что важно для существующего VPS
- По умолчанию **не поднимаем reverse-proxy** и **не занимаем 80/443**.
- Web публикуется только на loopback: `127.0.0.1:${APP_PORT:-8090}`.
- PostgreSQL и Redis доступны только внутри docker-сети.
- Это позволяет запустить панель рядом с существующими контейнерами Amnezia без конфликта портов.

## Стек
- Django 5, PostgreSQL, Redis, Celery, Bootstrap 5
- Docker Compose
- (опционально) Caddy в отдельном compose-файле

## Быстрый запуск (без конфликтов с nginx/Amnezia)
```bash
cp .env.example .env
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# вставьте ключ в CONFIG_ENCRYPTION_KEY в .env

docker compose up -d --build
```

Проверка доступности:
- `http://127.0.0.1:8090/login/` (или порт из `APP_PORT`)

## Первый запуск (обязательно вручную)
```bash
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

Демо-данные протоколов/сервера (без создания пользователя):
```bash
docker compose exec web python manage.py seed_demo
```

Создание демонстрационного `admin/admin12345` только по явному запросу (dev only):
```bash
docker compose exec web python manage.py seed_demo --with-demo-admin
```

## Optional proxy
Если нужен Caddy, используйте отдельный файл:
```bash
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d --build
```

## SSH security
`SafeSSHExecutor` использует strict host key verification:
- загружает system/user known_hosts,
- неизвестные хосты отклоняются (RejectPolicy) по умолчанию.

Только для dev можно временно ослабить:
```env
SSH_ALLOW_UNKNOWN_HOSTS=1
```

## AWG / AWG2 и секреты конфигов
- Профили разделены по `protocol_type` (`awg`/`awg2`).
- Ревизии конфигов разделены по протоколу.
- Конфиги хранятся в БД только в зашифрованном виде.
- QR код генерируется в памяти на лету из расшифрованного активного конфига (plaintext не хранится отдельным полем).

## Полезные команды
```bash
make up
make up-proxy
make migrate
make superuser
make seed
make test
make logs
make down
```
