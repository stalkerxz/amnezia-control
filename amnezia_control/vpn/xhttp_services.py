import hashlib
import json
import re
import uuid
from dataclasses import dataclass

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from audit.services import AuditService
from customers.models import ClientDevice, CustomerAccount
from .models import XHTTPDevice
from .services import ConfigCryptoService, RuntimeCommandService


@dataclass(frozen=True)
class XHTTPClientSettings:
    cdn_domain: str
    xhttp_path: str
    sc_max_each_post_bytes: int
    sc_min_posts_interval_ms: int
    uplink_chunk_size: int
    server_max_header_bytes: int

    @classmethod
    def from_django_settings(cls):
        value = cls(
            cdn_domain=str(getattr(settings, "XHTTP_CDN_DOMAIN", "")).strip(),
            xhttp_path=str(getattr(settings, "XHTTP_PATH", "")).strip(),
            sc_max_each_post_bytes=int(getattr(settings, "XHTTP_SC_MAX_EACH_POST_BYTES", 2048)),
            sc_min_posts_interval_ms=int(getattr(settings, "XHTTP_SC_MIN_POSTS_INTERVAL_MS", 30)),
            uplink_chunk_size=int(getattr(settings, "XHTTP_UPLINK_CHUNK_SIZE", 1800)),
            server_max_header_bytes=int(getattr(settings, "XHTTP_SERVER_MAX_HEADER_BYTES", 65536)),
        )
        value.validate()
        return value

    def validate(self):
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", self.cdn_domain):
            raise RuntimeError("XHTTP_CDN_DOMAIN не настроен или содержит недопустимые символы.")
        if not self.xhttp_path.startswith("/") or ".." in self.xhttp_path:
            raise RuntimeError("XHTTP_PATH должен быть безопасным абсолютным HTTP-путём.")
        if self.sc_max_each_post_bytes < 256:
            raise RuntimeError("XHTTP_SC_MAX_EACH_POST_BYTES слишком мал.")
        if self.sc_min_posts_interval_ms < 1:
            raise RuntimeError("XHTTP_SC_MIN_POSTS_INTERVAL_MS должен быть положительным.")
        if self.uplink_chunk_size < 256:
            raise RuntimeError("XHTTP_UPLINK_CHUNK_SIZE слишком мал.")
        if self.server_max_header_bytes < 8192:
            raise RuntimeError("XHTTP_SERVER_MAX_HEADER_BYTES слишком мал.")


class XHTTPRuntimeAdapter:
    HELPER_PATH = "/usr/local/sbin/amnezia-control-xhttp"

    def __init__(self, server):
        self.server = server

    @staticmethod
    def _validate_identity(client_uuid: uuid.UUID, xray_email: str) -> str:
        uuid_text = str(client_uuid)
        if not re.fullmatch(r"[0-9a-f-]{36}", uuid_text):
            raise ValueError("Некорректный UUID XHTTP-клиента.")
        if not re.fullmatch(r"xhttp-[0-9a-f]{32}", xray_email):
            raise ValueError("Некорректная техническая метка XHTTP-клиента.")
        return uuid_text

    def _run(self, *, action: str, client_uuid: uuid.UUID, xray_email: str, actor):
        if action not in {"add", "remove", "check"}:
            raise ValueError("Недопустимое действие XHTTP runtime.")
        uuid_text = self._validate_identity(client_uuid, xray_email)
        command = f"sudo -n {self.HELPER_PATH} {action} {uuid_text} {xray_email}"
        return RuntimeCommandService.run(
            self.server,
            actor,
            f"xhttp.{action}",
            command,
            sensitive_output=True,
        )

    def add(self, *, client_uuid: uuid.UUID, xray_email: str, actor):
        return self._run(action="add", client_uuid=client_uuid, xray_email=xray_email, actor=actor)

    def remove(self, *, client_uuid: uuid.UUID, xray_email: str, actor):
        return self._run(action="remove", client_uuid=client_uuid, xray_email=xray_email, actor=actor)

    def check(self, *, client_uuid: uuid.UUID, xray_email: str, actor):
        return self._run(action="check", client_uuid=client_uuid, xray_email=xray_email, actor=actor)


class XHTTPDeviceService:
    @staticmethod
    def _xray_email(client_uuid: uuid.UUID) -> str:
        return f"xhttp-{client_uuid.hex}"

    @staticmethod
    def is_device_available(device: ClientDevice) -> bool:
        account = device.account

        if device.status != ClientDevice.Status.ACTIVE:
            return False

        if (
            device.expires_at is not None
            and device.expires_at <= timezone.now()
        ):
            return False

        if account.status != CustomerAccount.Status.ACTIVE:
            return False

        if (
            account.expires_at is not None
            and account.expires_at <= timezone.now()
        ):
            return False

        return True

    @classmethod
    def _assert_device_available(cls, device: ClientDevice):
        if device.status != ClientDevice.Status.ACTIVE:
            raise RuntimeError(
                "XHTTP доступен только для активного устройства."
            )

        if (
            device.expires_at is not None
            and device.expires_at <= timezone.now()
        ):
            raise RuntimeError(
                "XHTTP недоступен: срок устройства истёк."
            )

        account = device.account

        if account.status != CustomerAccount.Status.ACTIVE:
            raise RuntimeError(
                "XHTTP доступен только для активного аккаунта."
            )

        if (
            account.expires_at is not None
            and account.expires_at <= timezone.now()
        ):
            raise RuntimeError(
                "XHTTP недоступен: срок аккаунта истёк."
            )

    @staticmethod
    def _runtime_server(
        device: XHTTPDevice,
    ):
        return device.server

    @classmethod
    def _assert_owner_available(
        cls,
        device: XHTTPDevice,
    ):
        cls._assert_device_available(
            device.device
        )

    @staticmethod
    def build_happ_config(*, client_uuid: uuid.UUID, device_name: str) -> str:
        runtime = XHTTPClientSettings.from_django_settings()
        config = {
            "log": {"loglevel": "info"},
            "inbounds": [
                {
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": True,
                    },
                }
            ],
            "outbounds": [
                {
                    "tag": "xhttp-cdn",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": runtime.cdn_domain,
                                "port": 443,
                                "users": [{"id": str(client_uuid), "encryption": "none"}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": runtime.cdn_domain,
                            "alpn": ["h2"],
                            "fingerprint": "chrome",
                            "allowInsecure": False,
                        },
                        "xhttpSettings": {
                            "host": runtime.cdn_domain,
                            "path": runtime.xhttp_path,
                            "mode": "packet-up",
                            "uplinkHTTPMethod": "GET",
                            "uplinkDataPlacement": "header",
                            "uplinkDataKey": "X-Data",
                            "scMaxEachPostBytes": runtime.sc_max_each_post_bytes,
                            "scMinPostsIntervalMs": runtime.sc_min_posts_interval_ms,
                            "uplinkChunkSize": runtime.uplink_chunk_size,
                            "serverMaxHeaderBytes": runtime.server_max_header_bytes,
                        },
                        "sockopt": {"tcpNoDelay": True},
                    },
                    "mux": {"enabled": False},
                },
                {"tag": "direct", "protocol": "freedom", "settings": {}},
                {"tag": "block", "protocol": "blackhole", "settings": {}},
            ],
            "remarks": f"Yandex CDN XHTTP — {device_name}",
            "meta": {
                "serverDescription": "VLESS/XHTTP packet-up GET через Yandex CDN",
                "managedBy": "amnezia-control",
            },
        }
        return json.dumps(config, ensure_ascii=False, indent=2) + "\n"

    @staticmethod
    def latest_config(device: XHTTPDevice) -> str:
        if not device.config_blob_encrypted:
            raise RuntimeError("Для устройства ещё не создан клиентский конфиг.")
        return ConfigCryptoService.decrypt(device.config_blob_encrypted)

    @classmethod
    def _store_config(cls, *, device: XHTTPDevice, plaintext: str):
        device.config_blob_encrypted = ConfigCryptoService.encrypt(plaintext)
        device.config_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    @classmethod
    def create_device(
        cls,
        *,
        device: ClientDevice,
        server,
        name: str,
        actor,
    ) -> XHTTPDevice:
        normalized_name = name.strip()

        if not normalized_name:
            raise ValueError(
                "Название устройства "
                "не может быть пустым."
            )

        cls._assert_device_available(
            device
        )

        if server is None:
            raise ValueError(
                "Для XHTTP необходимо "
                "выбрать сервер."
            )

        if not server.is_enabled:
            raise RuntimeError(
                "Выбранный XHTTP-сервер отключён."
            )

        if XHTTPDevice.objects.filter(
            device=device,
            name=normalized_name,
        ).exists():
            raise ValueError(
                "У этого устройства уже есть "
                "XHTTP-подключение "
                "с таким названием."
            )

        client_uuid = uuid.uuid4()

        xray_email = cls._xray_email(
            client_uuid
        )

        adapter = XHTTPRuntimeAdapter(
            server
        )

        adapter.add(
            client_uuid=client_uuid,
            xray_email=xray_email,
            actor=actor,
        )

        try:
            plaintext = cls.build_happ_config(
                client_uuid=client_uuid,
                device_name=normalized_name,
            )

            with transaction.atomic():
                xhttp_device = XHTTPDevice(
                    device=device,
                    server=server,
                    name=normalized_name,
                    client_uuid=client_uuid,
                    xray_email=xray_email,
                    status=(
                        XHTTPDevice.Status.ACTIVE
                    ),
                    disable_reason=(
                        XHTTPDevice
                        .DisableReason
                        .NONE
                    ),
                    last_applied_at=(
                        timezone.now()
                    ),
                    last_error="",
                )

                cls._store_config(
                    device=xhttp_device,
                    plaintext=plaintext,
                )

                xhttp_device.save()

                AuditService.log(
                    actor,
                    "xhttp.device.create",
                    "XHTTPDevice",
                    xhttp_device.id,
                    {
                        "device_id": device.pk,
                        "server_id": server.pk,
                    },
                )

                return xhttp_device

        except Exception:
            try:
                adapter.remove(
                    client_uuid=client_uuid,
                    xray_email=xray_email,
                    actor=actor,
                )
            except Exception:
                pass

            raise


    @classmethod
    def rotate(cls, *, device: XHTTPDevice, actor):
        if device.status == XHTTPDevice.Status.DELETED:
            raise RuntimeError("Удалённое устройство нельзя перевыпустить.")
        cls._assert_owner_available(device)

        was_active = device.status == XHTTPDevice.Status.ACTIVE
        old_uuid = device.client_uuid
        old_email = device.xray_email
        old_reason = device.disable_reason
        new_uuid = uuid.uuid4()
        new_email = cls._xray_email(new_uuid)
        adapter = XHTTPRuntimeAdapter(cls._runtime_server(device))

        if was_active:
            adapter.add(client_uuid=new_uuid, xray_email=new_email, actor=actor)
            try:
                adapter.remove(client_uuid=old_uuid, xray_email=old_email, actor=actor)
            except Exception:
                adapter.remove(client_uuid=new_uuid, xray_email=new_email, actor=actor)
                raise

        try:
            plaintext = cls.build_happ_config(client_uuid=new_uuid, device_name=device.name)
            with transaction.atomic():
                device.client_uuid = new_uuid
                device.xray_email = new_email
                device.status = XHTTPDevice.Status.ACTIVE if was_active else XHTTPDevice.Status.DISABLED
                device.disable_reason = XHTTPDevice.DisableReason.NONE if was_active else old_reason
                device.last_applied_at = timezone.now()
                device.last_error = ""
                cls._store_config(device=device, plaintext=plaintext)
                device.save(
                    update_fields=[
                        "client_uuid",
                        "xray_email",
                        "status",
                        "disable_reason",
                        "config_blob_encrypted",
                        "config_hash",
                        "last_applied_at",
                        "last_error",
                        "updated_at",
                    ]
                )
                AuditService.log(actor, "xhttp.device.rotate", "XHTTPDevice", device.id)
        except Exception:
            if was_active:
                try:
                    adapter.remove(client_uuid=new_uuid, xray_email=new_email, actor=actor)
                    adapter.add(client_uuid=old_uuid, xray_email=old_email, actor=actor)
                except Exception:
                    pass
            raise

    @classmethod
    def disable(
        cls,
        *,
        device: XHTTPDevice,
        actor,
        reason: str = XHTTPDevice.DisableReason.MANUAL,
    ):
        if reason not in XHTTPDevice.DisableReason.values:
            raise ValueError("Некорректная причина отключения XHTTP-устройства.")
        if device.status == XHTTPDevice.Status.DELETED:
            raise RuntimeError("Удалённое устройство нельзя отключить повторно.")
        if device.status == XHTTPDevice.Status.DISABLED:
            if reason == XHTTPDevice.DisableReason.MANUAL and device.disable_reason != reason:
                device.disable_reason = reason
                device.save(update_fields=["disable_reason", "updated_at"])
            return

        adapter = XHTTPRuntimeAdapter(cls._runtime_server(device))
        adapter.remove(client_uuid=device.client_uuid, xray_email=device.xray_email, actor=actor)
        try:
            device.status = XHTTPDevice.Status.DISABLED
            device.disable_reason = reason
            device.last_applied_at = timezone.now()
            device.last_error = ""
            device.save(
                update_fields=[
                    "status",
                    "disable_reason",
                    "last_applied_at",
                    "last_error",
                    "updated_at",
                ]
            )
            AuditService.log(actor, "xhttp.device.disable", "XHTTPDevice", device.id, {"reason": reason})
        except Exception:
            try:
                adapter.add(client_uuid=device.client_uuid, xray_email=device.xray_email, actor=actor)
            except Exception:
                pass
            raise

    @classmethod
    def enable(cls, *, device: XHTTPDevice, actor):
        if device.status == XHTTPDevice.Status.ACTIVE:
            return
        if device.status == XHTTPDevice.Status.DELETED:
            raise RuntimeError("Удалённое устройство нельзя включить.")
        cls._assert_owner_available(device)

        adapter = XHTTPRuntimeAdapter(cls._runtime_server(device))
        adapter.add(client_uuid=device.client_uuid, xray_email=device.xray_email, actor=actor)
        try:
            device.status = XHTTPDevice.Status.ACTIVE
            device.disable_reason = XHTTPDevice.DisableReason.NONE
            device.last_applied_at = timezone.now()
            device.last_error = ""
            device.save(
                update_fields=[
                    "status",
                    "disable_reason",
                    "last_applied_at",
                    "last_error",
                    "updated_at",
                ]
            )
            AuditService.log(actor, "xhttp.device.enable", "XHTTPDevice", device.id)
        except Exception:
            try:
                adapter.remove(client_uuid=device.client_uuid, xray_email=device.xray_email, actor=actor)
            except Exception:
                pass
            raise

    @classmethod
    def soft_delete(cls, *, device: XHTTPDevice, actor):
        if device.status == XHTTPDevice.Status.DELETED:
            return

        was_active = device.status == XHTTPDevice.Status.ACTIVE
        adapter = XHTTPRuntimeAdapter(cls._runtime_server(device))
        adapter.remove(client_uuid=device.client_uuid, xray_email=device.xray_email, actor=actor)
        try:
            device.status = XHTTPDevice.Status.DELETED
            device.disable_reason = XHTTPDevice.DisableReason.MANUAL
            device.last_applied_at = timezone.now()
            device.last_error = ""
            device.save(
                update_fields=[
                    "status",
                    "disable_reason",
                    "last_applied_at",
                    "last_error",
                    "updated_at",
                ]
            )
            AuditService.log(actor, "xhttp.device.delete", "XHTTPDevice", device.id)
        except Exception:
            if was_active:
                try:
                    adapter.add(client_uuid=device.client_uuid, xray_email=device.xray_email, actor=actor)
                except Exception:
                    pass
            raise

    @classmethod
    def check_runtime(cls, *, device: XHTTPDevice, actor):
        if device.status != XHTTPDevice.Status.ACTIVE:
            raise RuntimeError("Проверка runtime доступна только для активного XHTTP-устройства.")
        return XHTTPRuntimeAdapter(cls._runtime_server(device)).check(
            client_uuid=device.client_uuid,
            xray_email=device.xray_email,
            actor=actor,
        )

    @classmethod
    def disable_for_device(
        cls,
        *,
        client_device: ClientDevice,
        actor,
    ):
        for xhttp_device in client_device.xhttp_devices.filter(
            status=XHTTPDevice.Status.ACTIVE,
        ):
            cls.disable(
                device=xhttp_device,
                actor=actor,
                reason=XHTTPDevice.DisableReason.CLIENT,
            )

    @classmethod
    def enable_for_device(
        cls,
        *,
        client_device: ClientDevice,
        actor,
    ):
        if not cls.is_device_available(client_device):
            return

        for xhttp_device in client_device.xhttp_devices.filter(
            status=XHTTPDevice.Status.DISABLED,
            disable_reason=XHTTPDevice.DisableReason.CLIENT,
        ):
            cls.enable(
                device=xhttp_device,
                actor=actor,
            )
