from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST

from audit.models import AuditLog
from vpn.models import VPNClient, XHTTPDevice
from vpn.services import VPNClientPolicyService, VPNClientService
from vpn.xhttp_services import XHTTPDeviceService

from .models import ClientDevice, CustomerAccount


class CustomerPortalSelfServicePolicy:
    """Safety policy for customer-triggered configuration rotation."""

    COOLDOWN_HOURS = 12

    @classmethod
    def _cooldown_state(
        cls,
        *,
        user,
        action: str,
        entity_type: str,
        entity_id,
    ):
        last_event = (
            AuditLog.objects
            .filter(
                actor=user,
                action=action,
                entity_type=entity_type,
                entity_id=str(entity_id),
            )
            .order_by("-created_at")
            .first()
        )

        if last_event is None:
            return True, ""

        next_allowed_at = (
            last_event.created_at
            + timedelta(hours=cls.COOLDOWN_HOURS)
        )

        if next_allowed_at <= timezone.now():
            return True, ""

        local_time = timezone.localtime(
            next_allowed_at
        ).strftime("%d.%m.%Y %H:%M")

        return (
            False,
            (
                "Повторный выпуск будет доступен "
                f"после {local_time}."
            ),
        )

    @classmethod
    def can_vpn_reissue(cls, *, user, client):
        reason = VPNClientPolicyService.reissue_block_reason(
            client
        )

        if reason:
            return False, reason

        if (
            client.device_id is None
            or client.device.status
            != ClientDevice.Status.ACTIVE
        ):
            return False, "Устройство сейчас недоступно."

        if (
            client.device.expires_at is not None
            and client.device.expires_at
            <= timezone.now()
        ):
            return False, "Срок действия устройства истёк."

        account = client.device.account

        if (
            account.status
            != CustomerAccount.Status.ACTIVE
        ):
            return False, "Аккаунт сейчас недоступен."

        if (
            account.expires_at is not None
            and account.expires_at <= timezone.now()
        ):
            return False, "Срок действия аккаунта истёк."

        return cls._cooldown_state(
            user=user,
            action="client.reissue",
            entity_type="VPNClient",
            entity_id=client.pk,
        )

    @classmethod
    def can_xhttp_reissue(cls, *, user, xhttp):
        if xhttp.status != XHTTPDevice.Status.ACTIVE:
            return (
                False,
                "Альтернативное подключение отключено.",
            )

        if not XHTTPDeviceService.is_device_available(
            xhttp.device
        ):
            return False, "Устройство или аккаунт недоступны."

        return cls._cooldown_state(
            user=user,
            action="xhttp.device.rotate",
            entity_type="XHTTPDevice",
            entity_id=xhttp.pk,
        )


def _active_customer_account(user):
    if (
        getattr(user, "is_owner", False)
        or user.is_staff
        or user.is_superuser
    ):
        raise PermissionDenied(
            "Операторская учётная запись не используется "
            "в клиентском кабинете."
        )

    account = (
        CustomerAccount.objects
        .filter(user=user)
        .first()
    )

    if (
        account is None
        or account.status
        == CustomerAccount.Status.DELETED
    ):
        raise PermissionDenied(
            "Клиентский аккаунт недоступен."
        )

    if account.status != CustomerAccount.Status.ACTIVE:
        raise PermissionDenied(
            "Работа с конфигурациями отключена для этого аккаунта."
        )

    if (
        account.expires_at is not None
        and account.expires_at <= timezone.now()
    ):
        raise PermissionDenied(
            "Срок клиентского аккаунта истёк."
        )

    return account


def _assert_vpn_available(client):
    if (
        client.device_id is None
        or client.device.status
        != ClientDevice.Status.ACTIVE
    ):
        raise PermissionDenied(
            "Устройство недоступно."
        )

    if (
        client.device.expires_at is not None
        and client.device.expires_at <= timezone.now()
    ):
        raise PermissionDenied(
            "Срок действия устройства истёк."
        )

    if client.status != VPNClient.Status.ACTIVE:
        raise PermissionDenied(
            "VPN-подключение отключено."
        )

    if (
        VPNClientService.get_limit_state(client)
        != VPNClient.LimitState.ACTIVE
    ):
        raise PermissionDenied(
            "VPN-подключение ограничено по сроку или трафику."
        )


def _confirmation_present(request):
    return (
        request.POST.get("confirm_reissue") or ""
    ) == "1"


@login_required(login_url="/cabinet/login/")
@require_POST
def customer_vpn_reissue_view(request, pk):
    account = _active_customer_account(
        request.user
    )

    if not _confirmation_present(request):
        messages.warning(
            request,
            "Подтвердите выпуск конфигурации.",
        )
        return redirect("customer-portal-home")

    try:
        with transaction.atomic():
            client = get_object_or_404(
                VPNClient.objects
                .select_for_update()
                .select_related(
                    "device",
                    "device__account",
                    "server",
                    "profile",
                )
                .prefetch_related("revisions"),
                pk=pk,
                device__account=account,
            )

            _assert_vpn_available(client)

            had_revision = client.revisions.exists()

            allowed, block_message = (
                CustomerPortalSelfServicePolicy
                .can_vpn_reissue(
                    user=request.user,
                    client=client,
                )
            )

            if not allowed:
                messages.warning(
                    request,
                    block_message,
                )
                return redirect(
                    "customer-portal-home"
                )

            VPNClientService.reissue_config(
                client=client,
                actor=request.user,
            )

    except PermissionDenied:
        raise
    except Exception:
        messages.error(
            request,
            (
                "Не удалось выпустить конфигурацию. "
                "Попробуйте позже или обратитесь к оператору."
            ),
        )
        return redirect("customer-portal-home")

    if had_revision:
        messages.success(
            request,
            (
                "Конфигурация перевыпущена. Предыдущая "
                "конфигурация больше не работает — скачайте новую."
            ),
        )
    else:
        messages.success(
            request,
            "Конфигурация выпущена и готова к скачиванию.",
        )

    return redirect("customer-portal-home")


@login_required(login_url="/cabinet/login/")
@require_POST
def customer_xhttp_reissue_view(request, pk):
    account = _active_customer_account(
        request.user
    )

    if not _confirmation_present(request):
        messages.warning(
            request,
            "Подтвердите выпуск конфигурации.",
        )
        return redirect("customer-portal-home")

    try:
        with transaction.atomic():
            xhttp = get_object_or_404(
                XHTTPDevice.objects
                .select_for_update()
                .select_related(
                    "device",
                    "device__account",
                    "server",
                ),
                pk=pk,
                device__account=account,
            )

            allowed, block_message = (
                CustomerPortalSelfServicePolicy
                .can_xhttp_reissue(
                    user=request.user,
                    xhttp=xhttp,
                )
            )

            if not allowed:
                messages.warning(
                    request,
                    block_message,
                )
                return redirect(
                    "customer-portal-home"
                )

            had_config = bool(
                xhttp.config_blob_encrypted
            )

            XHTTPDeviceService.rotate(
                device=xhttp,
                actor=request.user,
            )

    except PermissionDenied:
        raise
    except Exception:
        messages.error(
            request,
            (
                "Не удалось выпустить альтернативную "
                "конфигурацию. Попробуйте позже или "
                "обратитесь к оператору."
            ),
        )
        return redirect("customer-portal-home")

    if had_config:
        messages.success(
            request,
            (
                "Альтернативная конфигурация перевыпущена. "
                "Предыдущая конфигурация больше не работает — "
                "скачайте новую."
            ),
        )
    else:
        messages.success(
            request,
            (
                "Альтернативная конфигурация выпущена "
                "и готова к скачиванию."
            ),
        )

    return redirect("customer-portal-home")
