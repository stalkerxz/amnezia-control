import base64

from django.contrib import messages
from django.contrib.auth import (
    views as auth_views,
)
from django.contrib.auth.decorators import (
    login_required,
)
from django.core.exceptions import PermissionDenied
from django.db.models import Prefetch
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import (
    get_object_or_404,
    redirect,
    render,
)
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.http import (
    require_GET,
    require_POST,
)

from audit.services import AuditService
from portal.forms import PortalRenewalRequestForm
from portal.services import RenewalRequestService
from vpn.models import VPNClient, XHTTPDevice
from vpn.services import VPNClientService
from vpn.xhttp_services import XHTTPDeviceService

from .models import ClientDevice, CustomerAccount
from .workspace import build_customer_workspace


def _customer_account_for_user(user):
    if (
        not user.is_authenticated
        or not user.is_active
    ):
        return None

    if (
        getattr(user, "is_owner", False)
        or user.is_staff
        or user.is_superuser
    ):
        return None

    return (
        CustomerAccount.objects
        .filter(user=user)
        .first()
    )


class CustomerLoginView(auth_views.LoginView):
    template_name = "customer_portal/login.html"

    def form_valid(self, form):
        user = form.get_user()

        account = _customer_account_for_user(
            user
        )

        if (
            account is None
            or account.status
            == CustomerAccount.Status.DELETED
        ):
            form.add_error(
                None,
                (
                    "Эта учётная запись не имеет доступа "
                    "к клиентскому кабинету."
                ),
            )

            return self.form_invalid(form)

        return super().form_valid(form)

    def get_success_url(self):
        return str(
            reverse_lazy(
                "customer-portal-home"
            )
        )


class CustomerLogoutView(auth_views.LogoutView):
    next_page = reverse_lazy(
        "customer-portal-login"
    )


@login_required(
    login_url="/cabinet/login/",
)
def customer_portal_home_view(request):
    if (
        getattr(request.user, "is_owner", False)
        or request.user.is_staff
        or request.user.is_superuser
    ):
        return HttpResponseForbidden(
            "Операторская учётная запись "
            "не используется в клиентском кабинете."
        )

    vpn_clients = (
        VPNClient.objects
        .exclude(
            status=VPNClient.Status.DELETED,
        )
        .select_related(
            "server",
            "profile",
        )
        .prefetch_related(
            "revisions",
        )
        .order_by(
            "protocol_type",
            "name",
            "pk",
        )
    )

    xhttp_devices = (
        XHTTPDevice.objects
        .exclude(
            status=XHTTPDevice.Status.DELETED,
        )
        .select_related(
            "server",
        )
        .order_by(
            "name",
            "pk",
        )
    )

    devices = (
        ClientDevice.objects
        .exclude(
            status=ClientDevice.Status.DELETED,
        )
        .prefetch_related(
            Prefetch(
                "vpn_clients",
                queryset=vpn_clients,
            ),
            Prefetch(
                "xhttp_devices",
                queryset=xhttp_devices,
            ),
        )
        .order_by(
            "name",
            "pk",
        )
    )

    account = (
        CustomerAccount.objects
        .filter(
            user=request.user,
        )
        .prefetch_related(
            Prefetch(
                "devices",
                queryset=devices,
            )
        )
        .first()
    )

    if (
        account is None
        or account.status
        == CustomerAccount.Status.DELETED
    ):
        return HttpResponseForbidden(
            "Клиентский аккаунт недоступен."
        )

    expired = bool(
        account.expires_at
        and account.expires_at <= timezone.now()
    )

    blocked = bool(
        account.status
        != CustomerAccount.Status.ACTIVE
        or expired
    )

    open_renewal_request = (
        RenewalRequestService
        .get_open_for_account(
            account=account,
        )
    )

    latest_renewal_request = (
        RenewalRequestService
        .get_latest_for_account(
            account=account,
        )
    )

    renewal_allowed = bool(
        account.status
        == CustomerAccount.Status.ACTIVE
    )

    for device in account.devices.all():
        for client in device.vpn_clients.all():
            has_revision = bool(
                list(client.revisions.all())
            )

            client.cabinet_download_allowed = bool(
                not blocked
                and device.status
                == ClientDevice.Status.ACTIVE
                and client.status
                == VPNClient.Status.ACTIVE
                and has_revision
                and VPNClientService.get_limit_state(
                    client
                )
                == VPNClient.LimitState.ACTIVE
            )

            client.cabinet_qr_allowed = bool(
                client.cabinet_download_allowed
                and VPNClientService
                .portal_qr_available_for_target(
                    client,
                    "amneziawg",
                )
            )

        for xhttp in device.xhttp_devices.all():
            xhttp.cabinet_download_allowed = bool(
                not blocked
                and device.status
                == ClientDevice.Status.ACTIVE
                and xhttp.status
                == XHTTPDevice.Status.ACTIVE
                and bool(
                    xhttp.config_blob_encrypted
                )
            )

    workspace = build_customer_workspace(account)

    return render(
        request,
        "customer_portal/home.html",
        {
            "account": account,
            "workspace": workspace,
            "expired": expired,
            "blocked": blocked,
            "renewal_allowed": renewal_allowed,
            "open_renewal_request": (
                open_renewal_request
            ),
            "latest_renewal_request": (
                latest_renewal_request
            ),
            "renewal_form": (
                PortalRenewalRequestForm()
            ),
        },
    )

def _customer_secret_account(user):
    account = _customer_account_for_user(
        user
    )

    if account is None:
        raise PermissionDenied(
            "Клиентский аккаунт недоступен."
        )

    if (
        account.status
        != CustomerAccount.Status.ACTIVE
    ):
        raise PermissionDenied(
            "Скачивание конфигураций "
            "для отключённого аккаунта недоступно."
        )

    if (
        account.expires_at is not None
        and account.expires_at <= timezone.now()
    ):
        raise PermissionDenied(
            "Срок клиентского аккаунта истёк."
        )

    return account


def _assert_vpn_secret_available(client):
    if (
        client.device_id is None
        or client.device.status
        != ClientDevice.Status.ACTIVE
    ):
        raise PermissionDenied(
            "Устройство недоступно."
        )

    if (
        client.status
        != VPNClient.Status.ACTIVE
    ):
        raise PermissionDenied(
            "VPN-подключение отключено."
        )

    if (
        VPNClientService.get_limit_state(client)
        != VPNClient.LimitState.ACTIVE
    ):
        raise PermissionDenied(
            "VPN-подключение ограничено "
            "по сроку или трафику."
        )


def _secret_response_headers(response):
    response["Cache-Control"] = (
        "no-store, max-age=0"
    )
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = (
        "nosniff"
    )
    return response


@login_required(
    login_url="/cabinet/login/",
)
@require_GET
def customer_vpn_download_view(
    request,
    pk,
):
    account = _customer_secret_account(
        request.user
    )

    client = get_object_or_404(
        VPNClient.objects
        .select_related(
            "device",
            "device__account",
            "server",
            "profile",
        )
        .prefetch_related(
            "revisions",
        ),
        pk=pk,
        device__account=account,
    )

    _assert_vpn_secret_available(
        client
    )

    if not client.revisions.exists():
        return HttpResponse(
            (
                "Для подключения ещё нет "
                "выпущенной конфигурации."
            ),
            status=404,
            content_type=(
                "text/plain; charset=utf-8"
            ),
        )

    try:
        config = (
            VPNClientService
            .portal_export_config_for_target(
                client,
                "amneziawg",
            )
        )

    except RuntimeError:
        return HttpResponse(
            (
                "Сохранённая конфигурация "
                "не может быть экспортирована."
            ),
            status=409,
            content_type=(
                "text/plain; charset=utf-8"
            ),
        )

    filename_base = (
        slugify(
            (
                f"{client.device.name}-"
                f"{client.profile.name}"
            )
        )
        or f"vpn-{client.pk}"
    )

    response = HttpResponse(
        config,
        content_type=(
            "text/plain; charset=utf-8"
        ),
    )

    response["Content-Disposition"] = (
        "attachment; "
        f'filename="{filename_base}.conf"'
    )

    return _secret_response_headers(
        response
    )


@login_required(
    login_url="/cabinet/login/",
)
@require_GET
def customer_vpn_qr_view(
    request,
    pk,
):
    account = _customer_secret_account(
        request.user
    )

    client = get_object_or_404(
        VPNClient.objects
        .select_related(
            "device",
            "device__account",
            "server",
            "profile",
        )
        .prefetch_related(
            "revisions",
        ),
        pk=pk,
        device__account=account,
    )

    _assert_vpn_secret_available(
        client
    )

    if not client.revisions.exists():
        return HttpResponse(
            "QR-код ещё не выпущен.",
            status=404,
            content_type=(
                "text/plain; charset=utf-8"
            ),
        )

    try:
        encoded = (
            VPNClientService
            .portal_qr_png_base64_for_target(
                client,
                "amneziawg",
            )
        )

        png = base64.b64decode(
            encoded
        )

    except (RuntimeError, ValueError):
        return HttpResponse(
            (
                "QR-код недоступен. "
                "Используйте файл .conf."
            ),
            status=409,
            content_type=(
                "text/plain; charset=utf-8"
            ),
        )

    filename_base = (
        slugify(
            (
                f"{client.device.name}-"
                f"{client.profile.name}"
            )
        )
        or f"vpn-{client.pk}"
    )

    response = HttpResponse(
        png,
        content_type="image/png",
    )

    response["Content-Disposition"] = (
        "inline; "
        f'filename="{filename_base}-qr.png"'
    )

    return _secret_response_headers(
        response
    )


@login_required(
    login_url="/cabinet/login/",
)
@require_GET
def customer_xhttp_download_view(
    request,
    pk,
):
    account = _customer_secret_account(
        request.user
    )

    xhttp = get_object_or_404(
        XHTTPDevice.objects
        .select_related(
            "device",
            "device__account",
            "server",
        ),
        pk=pk,
        device__account=account,
    )

    if (
        xhttp.device_id is None
        or xhttp.status
        != XHTTPDevice.Status.ACTIVE
        or not XHTTPDeviceService
        .is_device_available(
            xhttp.device
        )
    ):
        raise PermissionDenied(
            "Альтернативное подключение недоступно."
        )

    try:
        config = (
            XHTTPDeviceService.latest_config(
                xhttp
            )
        )

    except RuntimeError:
        return HttpResponse(
            (
                "Для подключения ещё нет "
                "сохранённой конфигурации."
            ),
            status=404,
            content_type=(
                "text/plain; charset=utf-8"
            ),
        )

    filename_base = (
        slugify(
            (
                f"{xhttp.device.name}-"
                f"{xhttp.name}"
            )
        )
        or f"xhttp-{xhttp.pk}"
    )

    response = HttpResponse(
        config,
        content_type=(
            "application/json; charset=utf-8"
        ),
    )

    response["Content-Disposition"] = (
        "attachment; "
        f'filename="{filename_base}.json"'
    )

    return _secret_response_headers(
        response
    )


@login_required(
    login_url="/cabinet/login/",
)
@require_POST
def customer_renewal_request_view(
    request,
):
    account = _customer_account_for_user(
        request.user
    )

    if account is None:
        raise PermissionDenied(
            "Клиентский аккаунт недоступен."
        )

    if (
        account.status
        != CustomerAccount.Status.ACTIVE
    ):
        raise PermissionDenied(
            "Заявка на продление "
            "для отключённого аккаунта недоступна."
        )

    form = PortalRenewalRequestForm(
        request.POST,
        request.FILES,
    )

    if not form.is_valid():
        for errors in form.errors.values():
            for error in errors:
                messages.error(
                    request,
                    error,
                )

        return redirect(
            "customer-portal-home"
        )

    request_obj, created = (
        RenewalRequestService
        .create_or_get_open_for_account(
            account=account,
            attachment=(
                form.cleaned_data.get(
                    "attachment"
                )
            ),
        )
    )

    if created:
        AuditService.log(
            request.user,
            "customer.renewal.request",
            "CustomerAccount",
            account.pk,
            {
                "renewal_request_id": (
                    request_obj.pk
                ),
                "requested_at": (
                    timezone.now().isoformat()
                ),
                "ip": (
                    request.META.get(
                        "REMOTE_ADDR",
                        "",
                    )
                ),
                "user_agent": (
                    request.META.get(
                        "HTTP_USER_AGENT",
                        "",
                    )[:255]
                ),
            },
        )

        messages.success(
            request,
            (
                "Заявка на продление отправлена. "
                "Она относится ко всему аккаунту "
                "и всем его устройствам."
            ),
        )

    else:
        messages.info(
            request,
            (
                "Открытая заявка уже существует. "
                "Новая заявка не создана."
            ),
        )

    return redirect(
        "customer-portal-home"
    )
