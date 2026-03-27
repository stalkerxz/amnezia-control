# amnezia-control

Приватная production-ready админ-панель для управления существующим Amnezia VPN сервером (AmneziaWG/AWG + AWG2-ready), ориентированная на одного владельца.

## Стек
- Django 5
- PostgreSQL
- Redis
- Celery
- Caddy
- Docker Compose
- Bootstrap 5

## Возможности v1
- `/login` — вход
- `/` — дашборд
- `/servers` и `/servers/<id>` — серверы и их состояние
- `/clients` и `/clients/<id>` — список/карточка VPN-клиентов
- Создание, включение, отключение, удаление клиента
- Переиздание конфигурации
- Скачивание конфигурации
- Показ QR-кода
- `/audit` — аудит действий
- `/jobs` — журнал задач/исполнения команд
- `/health` — health endpoint

## Архитектура приложений
- `core` — dashboard, health, seed-команда
- `accounts` — кастомный пользователь
- `servers` — серверы, протоколы, профили протоколов
- `vpn` — VPN-клиенты, ревизии конфигов, генераторы AWG/AWG2
- `audit` — аудит всех действий
- `jobs` — задания, события, SSH executor, Celery task

## Безопасность
- Только админ-доступ (`is_staff`)
- CSRF включен
- Secure cookie/HTTPS в prod settings
- Конфиги клиентов шифруются в БД (`CONFIG_ENCRYPTION_KEY`, Fernet)
- SSH команды allowlist-only (никакого произвольного shell из UI)
- stdout/stderr/exit code сохраняются в `JobEvent`
- Приватные ключи не пишутся в логи

## Быстрый старт локально
```bash
cp .env.example .env
# Сгенерируйте CONFIG_ENCRYPTION_KEY и вставьте в .env
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

docker compose up -d --build
```

После старта:
```bash
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo
```

Открыть: `http://localhost/login/`

Демо-логин (если `seed_demo` создал):
- user: `admin`
- password: `admin12345`

## Деплой на Ubuntu 24.04 (copy-paste)
```bash
sudo apt update
sudo apt install -y ca-certificates curl git docker.io docker-compose-plugin
sudo systemctl enable --now docker

cd /opt
sudo git clone <YOUR_REPO_URL> amnezia-control
cd amnezia-control
sudo cp .env.example .env

# Вставьте корректные значения в .env
sudo nano .env

# Ключ шифрования
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

sudo docker compose up -d --build
sudo docker compose exec web python manage.py migrate
sudo docker compose exec web python manage.py seed_demo
```

## SSH execution model
- V1 работает с текущим VPS по SSH (включая localhost по SSH).
- Реализован `SafeSSHExecutor` на Paramiko с allowlist-командами.
- `Job` + `JobEvent` сохраняют историю исполнения.
- Архитектура готова к добавлению удалённых серверов.

## AWG / AWG2 стратегия
- `ServerProtocol` + `ProtocolProfile` разделяют профили по `protocol_type`.
- `ClientConfigRevision` хранит ревизии отдельно по протоколу.
- `GeneratorFactory` выбирает генератор (`AWGGenerator`, `AWG2Generator`).
- Низкоуровневые AWG2 шаги можно расширить без ломки legacy AWG.

## Полезные команды
```bash
make up
make migrate
make seed
make test
make logs
make down
```

## Тесты
Покрыты базовые сценарии:
- model tests
- SSH executor test (mock Paramiko)
- client creation flow test

```bash
docker compose exec web python manage.py test
```
