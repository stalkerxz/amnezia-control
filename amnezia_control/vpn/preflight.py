import ipaddress
import os
from pathlib import Path

from celery import current_app
from django.conf import settings
from django.utils import timezone

from jobs.executors import SafeSSHExecutor
from servers.models import ProtocolProfile, Server, ServerProtocol

from .models import VPNClient
from .services import VPNClientService


class ClientCreationPreflightService:
    """Read-only checks used before a new VPN peer is created."""

    AWG2_REQUIRED_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")

    @staticmethod
    def _check(key: str, label: str, ok: bool, detail: str, *, blocking: bool = True) -> dict:
        return {
            "key": key,
            "label": label,
            "ok": bool(ok),
            "detail": detail,
            "blocking": blocking,
        }

    @classmethod
    def _address_pool_state(cls, server: Server, protocol: ServerProtocol) -> tuple[bool, str]:
        subnet_text = str((protocol.runtime_metadata or {}).get("subnet", "")).strip()
        if not subnet_text:
            return False, "Подсеть не определена. Выполните синхронизацию runtime."

        try:
            subnet = ipaddress.ip_network(subnet_text, strict=False)
        except ValueError:
            return False, f"Некорректная подсеть: {subnet_text}"

        if subnet.version != 4:
            return True, f"Пул адресов настроен: {subnet}"

        usable_hosts = max(int(subnet.num_addresses) - 2, 0)
        reserved_ips = set()
        for raw_address in VPNClient.objects.filter(
            server=server,
            protocol_type=protocol.protocol_type,
            status__in=(VPNClient.Status.ACTIVE, VPNClient.Status.DISABLED),
        ).exclude(runtime_address="").values_list("runtime_address", flat=True):
            try:
                value = str(raw_address).strip()
                reserved_ips.add(ipaddress.ip_interface(value if "/" in value else f"{value}/32").ip)
            except ValueError:
                continue

        # One address is normally occupied by the VPN interface itself. Runtime
        # peer_count also protects against under-counting peers not represented
        # in the database without importing or mutating them.
        peer_count = int((protocol.runtime_metadata or {}).get("peer_count") or 0)
        estimated_used = max(len(reserved_ips) + 1, peer_count + 1)
        free_count = max(usable_hosts - estimated_used, 0)
        if free_count <= 0:
            return False, f"В подсети {subnet} нет свободных адресов."
        return True, f"Свободно не менее {free_count} адресов в {subnet}."

    @staticmethod
    def _worker_state() -> tuple[bool, str]:
        try:
            timeout = float(getattr(settings, "CLIENT_PREFLIGHT_WORKER_TIMEOUT", 0.8))
        except (TypeError, ValueError):
            timeout = 0.8
        try:
            inspector = current_app.control.inspect(timeout=max(0.1, timeout))
            replies = inspector.ping() or {}
        except Exception as exc:
            return False, f"Celery worker не ответил: {exc}"
        if not replies:
            return False, "Celery worker не ответил."
        return True, f"Активных worker: {len(replies)}."

    @classmethod
    def check(cls, *, server: Server, protocol_type: str, include_live: bool = True) -> dict:
        checks: list[dict] = []
        add = checks.append

        add(cls._check("server", "Сервер включён", server.is_enabled, "Сервер доступен для операций." if server.is_enabled else "Сервер отключён."))

        protocol = ServerProtocol.objects.filter(
            server=server,
            protocol_type=protocol_type,
            enabled=True,
        ).first()
        add(
            cls._check(
                "protocol",
                "Протокол включён",
                bool(protocol),
                f"{protocol_type.upper()} доступен." if protocol else f"{protocol_type.upper()} отключён или не настроен.",
            )
        )

        profile = None
        metadata = {}
        if protocol:
            metadata = protocol.runtime_metadata or {}
            profile = ProtocolProfile.objects.filter(
                server_protocol=protocol,
                protocol_type=protocol_type,
                status=ProtocolProfile.ProfileStatus.ACTIVE,
            ).first()

        add(cls._check("profile", "Активный профиль", bool(profile), "Профиль найден." if profile else "Нет активного профиля протокола."))

        runtime_synced = bool(server.last_runtime_sync_at)
        runtime_detail = (
            f"Последняя синхронизация: {timezone.localtime(server.last_runtime_sync_at).strftime('%d.%m.%Y %H:%M')}."
            if runtime_synced
            else "Синхронизация runtime ещё не выполнялась."
        )
        add(cls._check("runtime_sync", "Runtime синхронизирован", runtime_synced, runtime_detail))

        container_cached_ok = bool(protocol and (protocol.container_status or "").lower() == "running")
        add(
            cls._check(
                "container_cached",
                "Контейнер запущен",
                container_cached_ok,
                f"{protocol.container_name} отмечен как running." if container_cached_ok else "Контейнер не подтверждён как running.",
            )
        )

        interface_ok = bool(metadata.get("interface"))
        config_path_ok = bool(metadata.get("config_path"))
        add(cls._check("interface", "VPN-интерфейс", interface_ok, f"Интерфейс: {metadata.get('interface')}." if interface_ok else "Интерфейс не обнаружен."))
        add(cls._check("config_path", "Runtime-конфигурация", config_path_ok, "Путь к конфигурации определён." if config_path_ok else "Путь к конфигурации не определён."))

        endpoint_ok = False
        endpoint_detail = "Endpoint не готов."
        if protocol:
            try:
                endpoint_detail = f"Endpoint: {VPNClientService.resolve_endpoint(server, protocol)}."
                endpoint_ok = True
            except Exception as exc:
                endpoint_detail = str(exc)
        add(cls._check("endpoint", "Публичный endpoint", endpoint_ok, endpoint_detail))

        if protocol_type == VPNClient.ProtocolType.AWG2:
            awg2_metadata = metadata.get("awg2_metadata", {}) or {}
            missing = [key for key in cls.AWG2_REQUIRED_KEYS if not awg2_metadata.get(key)]
            add(
                cls._check(
                    "awg2_metadata",
                    "Параметры AWG2",
                    not missing,
                    "Обязательные параметры AWG2 присутствуют." if not missing else f"Не хватает: {', '.join(missing)}.",
                )
            )

        pool_ok, pool_detail = cls._address_pool_state(server, protocol) if protocol else (False, "Протокол не настроен.")
        add(cls._check("address_pool", "Свободный IP-адрес", pool_ok, pool_detail))

        key_path = str(server.ssh_private_key_path or "").strip()
        key_ok = bool(key_path and Path(key_path).is_file() and os.access(key_path, os.R_OK))
        add(cls._check("ssh_key", "SSH-ключ web/worker", key_ok, "Приватный ключ доступен." if key_ok else "Приватный SSH-ключ не найден или недоступен."))

        known_hosts_path = SafeSSHExecutor._known_hosts_path()
        known_hosts_ok = False
        if known_hosts_path.is_file() and os.access(known_hosts_path, os.R_OK):
            try:
                entries = SafeSSHExecutor._parse_known_hosts_entries(known_hosts_path.read_text(encoding="utf-8").splitlines())
                token = SafeSSHExecutor._expected_host_token(server.host, server.port)
                known_hosts_ok = token in entries
            except OSError:
                known_hosts_ok = False
        add(
            cls._check(
                "known_hosts",
                "SSH host key",
                known_hosts_ok,
                "Host key закреплён в known_hosts." if known_hosts_ok else "Host key отсутствует в постоянном known_hosts.",
            )
        )

        if include_live:
            live_ssh_ok = False
            live_ssh_detail = "SSH-проверка не выполнена."
            live_container_ok = False
            try:
                result = SafeSSHExecutor(
                    host=server.host,
                    username=server.ssh_username,
                    port=server.port,
                    key_path=key_path or None,
                ).run("docker ps --format '{{.Names}}'")
                live_ssh_ok = result.exit_code == 0
                running_names = {line.strip() for line in result.stdout.splitlines() if line.strip()}
                live_ssh_detail = "SSH-аутентификация и безопасная команда выполнены." if live_ssh_ok else (result.stderr or "SSH-команда завершилась с ошибкой.")
                live_container_ok = bool(protocol and protocol.container_name in running_names)
            except Exception as exc:
                live_ssh_detail = str(exc)

            add(cls._check("ssh_live", "Живое SSH-подключение", live_ssh_ok, live_ssh_detail))
            add(
                cls._check(
                    "container_live",
                    "Контейнер доступен сейчас",
                    live_container_ok,
                    f"{protocol.container_name} присутствует в docker ps." if live_container_ok and protocol else "Контейнер протокола отсутствует в docker ps.",
                )
            )

            worker_ok, worker_detail = cls._worker_state()
            add(cls._check("worker", "Celery worker", worker_ok, worker_detail, blocking=False))

        ready = all(item["ok"] or not item["blocking"] for item in checks)
        return {
            "ready": ready,
            "server": server.name,
            "protocol_type": protocol_type,
            "checks": checks,
            "checked_at": timezone.localtime().strftime("%d.%m.%Y %H:%M:%S"),
        }
