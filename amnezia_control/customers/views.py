from datetime import timedelta
from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import (
    Case,
    CharField,
    Count,
    F,
    Prefetch,
    Q,
    Value,
    When,
)
from django.http import (
    HttpResponseBadRequest,
    HttpResponseForbidden,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import (
    require_GET,
    require_POST,
    require_http_methods,
)

from portal.models import ClientRenewalRequest
from servers.models import Server
from vpn.forms import VPNClientCreateForm
from vpn.models import VPNClient, XHTTPDevice
from vpn.services import VPNClientService
from vpn.server_selection import (
    resolve_vpn_server_choice,
    vpn_server_candidate_rows,
)
from vpn.xhttp_forms import XHTTPDeviceCreateForm
from vpn.xhttp_services import XHTTPDeviceService

from .forms import (
    ClientDeviceCreateForm,
    ClientDeviceEditForm,
    DeviceAccessUpdateForm,
    CustomerAccountCreateForm,
    CustomerAccountEditForm,
    CustomerOnboardingForm,
)
from .models import ClientDevice, CustomerAccount
from .edit_services import (
    CustomerMetadataEditError,
    update_customer_account_metadata,
    update_customer_device_access,
    update_customer_device_metadata,
)
from .status_services import (
    CustomerStatusOperationError,
    set_customer_account_status,
    set_customer_device_status,
)
from .onboarding_services import (
    CustomerOnboardingError,
    create_customer_onboarding,
)
from .workspace import build_customer_workspace


def operator_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if not getattr(request.user, "is_owner", False):
            return HttpResponseForbidden(
                "Доступ разрешён только оператору."
            )
        return view_func(request, *args, **kwargs)

    return wrapped


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_create_view(request):
    if request.method == "POST":
        form = CustomerAccountCreateForm(request.POST)

        if form.is_valid():
            account = form.save(commit=False)
            account.created_by = request.user
            account.status = CustomerAccount.Status.ACTIVE
            account.save()

            return redirect(
                "customers-detail",
                pk=account.pk,
            )
    else:
        form = CustomerAccountCreateForm()

    return render(
        request,
        "customers/customer_form.html",
        {
            "form": form,
        },
    )


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_onboarding_view(request):
    if request.method == "POST":
        form = CustomerOnboardingForm(
            request.POST
        )

        if form.is_valid():
            try:
                result = create_customer_onboarding(
                    display_name=(
                        form.cleaned_data[
                            "display_name"
                        ]
                    ),
                    email=(
                        form.cleaned_data[
                            "email"
                        ]
                    ),
                    expires_at=(
                        form.cleaned_data[
                            "expires_at"
                        ]
                    ),
                    device_name=(
                        form.cleaned_data[
                            "device_name"
                        ]
                    ),
                    device_platform=(
                        form.cleaned_data[
                            "device_platform"
                        ]
                    ),
                    device_notes=(
                        form.cleaned_data[
                            "device_notes"
                        ]
                    ),
                    create_login=bool(
                        form.cleaned_data[
                            "create_login"
                        ]
                    ),
                    username=(
                        form.cleaned_data.get(
                            "username"
                        )
                        or ""
                    ),
                    password=(
                        form.cleaned_data.get(
                            "password1"
                        )
                        or ""
                    ),
                    actor=request.user,
                )

            except CustomerOnboardingError as exc:
                form.add_error(
                    None,
                    str(exc),
                )

            else:
                account = result[
                    "account"
                ]

                messages.success(
                    request,
                    (
                        "Клиент создан. "
                        "Теперь добавьте нужные "
                        "подключения для первого "
                        "устройства."
                    ),
                )

                return redirect(
                    "customers-detail",
                    pk=account.pk,
                )

    else:
        form = CustomerOnboardingForm()

    return render(
        request,
        "customers/customer_onboarding_form.html",
        {
            "form": form,
        },
    )


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_edit_view(request, pk):
    account = get_object_or_404(
        CustomerAccount,
        pk=pk,
    )

    if (
        account.status
        == CustomerAccount.Status.DELETED
    ):
        return HttpResponseForbidden(
            "Удалённый аккаунт нельзя редактировать."
        )

    if request.method == "POST":
        form = CustomerAccountEditForm(
            request.POST,
            instance=account,
        )

        if form.is_valid():
            try:
                account = (
                    update_customer_account_metadata(
                        account_id=account.pk,
                        display_name=(
                            form.cleaned_data[
                                "display_name"
                            ]
                        ),
                        email=(
                            form.cleaned_data[
                                "email"
                            ]
                        ),
                        expires_at=(
                            form.cleaned_data[
                                "expires_at"
                            ]
                        ),
                        actor=request.user,
                    )
                )

                return redirect(
                    "customers-detail",
                    pk=account.pk,
                )

            except CustomerMetadataEditError as exc:
                form.add_error(
                    None,
                    str(exc),
                )

    else:
        form = CustomerAccountEditForm(
            instance=account,
        )

    return render(
        request,
        "customers/customer_edit_form.html",
        {
            "account": account,
            "form": form,
        },
    )


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_device_edit_view(
    request,
    device_id,
):
    device = get_object_or_404(
        ClientDevice.objects.select_related(
            "account"
        ),
        pk=device_id,
    )

    if (
        device.status
        == ClientDevice.Status.DELETED
        or device.account.status
        == CustomerAccount.Status.DELETED
    ):
        return HttpResponseForbidden(
            "Удалённое устройство нельзя редактировать."
        )

    if request.method == "POST":
        form = ClientDeviceEditForm(
            request.POST,
            instance=device,
        )

        if form.is_valid():
            try:
                device = (
                    update_customer_device_metadata(
                        device_id=device.pk,
                        name=(
                            form.cleaned_data[
                                "name"
                            ]
                        ),
                        platform=(
                            form.cleaned_data[
                                "platform"
                            ]
                        ),
                        notes=(
                            form.cleaned_data[
                                "notes"
                            ]
                        ),
                        actor=request.user,
                    )
                )

                return redirect(
                    "customers-detail",
                    pk=device.account_id,
                )

            except CustomerMetadataEditError as exc:
                form.add_error(
                    None,
                    str(exc),
                )

    else:
        form = ClientDeviceEditForm(
            instance=device,
        )

    return render(
        request,
        "customers/device_edit_form.html",
        {
            "account": device.account,
            "device": device,
            "form": form,
        },
    )


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_device_create_view(request, pk):
    account = get_object_or_404(
        CustomerAccount,
        pk=pk,
    )

    if account.status == CustomerAccount.Status.DELETED:
        return HttpResponseForbidden(
            "Нельзя добавлять устройство "
            "в удалённый аккаунт."
        )

    if request.method == "POST":
        form = ClientDeviceCreateForm(request.POST)

        if form.is_valid():
            device = form.save(commit=False)
            device.account = account
            device.status = ClientDevice.Status.ACTIVE
            device.save()

            return redirect(
                "customers-detail",
                pk=account.pk,
            )
    else:
        form = ClientDeviceCreateForm()

    return render(
        request,
        "customers/device_form.html",
        {
            "account": account,
            "form": form,
        },
    )


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_device_xhttp_create_view(
    request,
    device_id,
):
    device = get_object_or_404(
        ClientDevice.objects.select_related(
            "account"
        ),
        pk=device_id,
    )

    account = device.account

    if (
        account.status
        != CustomerAccount.Status.ACTIVE
    ):
        return HttpResponseForbidden(
            "Альтернативное подключение можно создавать "
            "только для активного аккаунта."
        )

    if (
        device.status
        != ClientDevice.Status.ACTIVE
    ):
        return HttpResponseForbidden(
            "Альтернативное подключение можно создавать "
            "только для активного устройства."
        )

    if (
        account.expires_at
        and account.expires_at
        <= timezone.now()
    ):
        return HttpResponseForbidden(
            "Срок действия аккаунта истёк."
        )

    if (
        device.expires_at
        and device.expires_at
        <= timezone.now()
    ):
        return HttpResponseForbidden(
            "Срок действия устройства истёк."
        )

    default_server = (
        Server.objects
        .filter(is_enabled=True)
        .order_by("pk")
        .first()
    )

    if default_server is None:
        return HttpResponseBadRequest(
            "Сервер для альтернативного подключения "
            "не настроен."
        )

    if request.method == "POST":
        data = request.POST.copy()

        # Device ownership comes exclusively
        # from URL context, never from user input.
        data["device"] = str(
            device.pk
        )

        form = XHTTPDeviceCreateForm(
            data
        )

        if form.is_valid():
            try:
                xhttp = (
                    XHTTPDeviceService
                    .create_device(
                        device=device,
                        server=(
                            form.cleaned_data[
                                "server"
                            ]
                        ),
                        name=(
                            form.cleaned_data[
                                "name"
                            ]
                        ),
                        actor=request.user,
                    )
                )

                messages.success(
                    request,
                    (
                        "Альтернативное подключение "
                        f"«{xhttp.name}» создано."
                    ),
                )

                return redirect(
                    "customers-detail",
                    pk=account.pk,
                )

            except Exception as exc:
                form.add_error(
                    None,
                    (
                        "Не удалось создать "
                        "альтернативное подключение: "
                        f"{exc}"
                    ),
                )

    else:
        form = XHTTPDeviceCreateForm(
            initial={
                "device": device.pk,
                "server": (
                    default_server.pk
                ),
            }
        )

    return render(
        request,
        "customers/xhttp_connection_form.html",
        {
            "account": account,
            "device": device,
            "form": form,
        },
    )


@login_required
@operator_required
@require_POST
def customer_xhttp_action_view(
    request,
    pk,
    action,
):
    xhttp = get_object_or_404(
        XHTTPDevice.objects
        .select_related(
            "device",
            "device__account",
            "server",
        ),
        pk=pk,
    )

    account_id = (
        xhttp.device.account_id
    )

    actions = {
        "check": (
            XHTTPDeviceService
            .check_runtime,
            "Состояние альтернативного подключения "
            "проверено.",
        ),
        "disable": (
            XHTTPDeviceService.disable,
            "Альтернативное подключение отключено.",
        ),
        "enable": (
            XHTTPDeviceService.enable,
            "Альтернативное подключение включено.",
        ),
        "rotate": (
            XHTTPDeviceService.rotate,
            (
                "Параметры альтернативного подключения "
                "обновлены. Нужно скачать новую конфигурацию."
            ),
        ),
        "delete": (
            XHTTPDeviceService.soft_delete,
            "Альтернативное подключение удалено.",
        ),
    }

    handler = actions.get(
        action
    )

    if handler is None:
        return HttpResponseBadRequest(
            "Неизвестное действие "
            "с альтернативным подключением."
        )

    callback, success_message = (
        handler
    )

    try:
        callback(
            device=xhttp,
            actor=request.user,
        )

        xhttp.refresh_from_db()

        if xhttp.last_error:
            xhttp.last_error = ""

            xhttp.save(
                update_fields=[
                    "last_error",
                    "updated_at",
                ]
            )

        messages.success(
            request,
            success_message,
        )

    except Exception as exc:
        xhttp.refresh_from_db()

        xhttp.last_error = str(
            exc
        )[:255]

        xhttp.save(
            update_fields=[
                "last_error",
                "updated_at",
            ]
        )

        messages.error(
            request,
            (
                "Операция с альтернативным "
                "подключением не выполнена: "
                f"{exc}"
            ),
        )

    return redirect(
        "customers-detail",
        pk=account_id,
    )


def _device_vpn_client_name(
    *,
    device,
    server,
    routing_mode,
):
    mode_label = (
        "SELECT"
        if routing_mode
        == VPNClientCreateForm.ROUTING_MODE_SELECTIVE
        else "FULL"
    )

    prefix = (
        f"{device.account.display_name}-{device.name}"
        .strip(" -")
        or f"Device-{device.pk}"
    )

    suffix = f"-D{device.pk}-{mode_label}"

    candidate = (
        prefix[: 120 - len(suffix)]
        + suffix
    )

    counter = 2

    while VPNClient.objects.filter(
        server=server,
        name=candidate,
        protocol_type=VPNClient.ProtocolType.AWG2,
    ).exists():
        extra = f"-{counter}"

        candidate = (
            prefix[
                : 120
                - len(suffix)
                - len(extra)
            ]
            + suffix
            + extra
        )

        counter += 1

    return candidate


@login_required
@operator_required
@require_GET
def customer_device_connection_create_view(
    request,
    device_id,
):
    device = get_object_or_404(
        ClientDevice.objects.select_related(
            "account"
        ),
        pk=device_id,
    )

    account = device.account

    if (
        account.status
        != CustomerAccount.Status.ACTIVE
    ):
        return HttpResponseForbidden(
            "Подключения можно создавать "
            "только для активного аккаунта."
        )

    if (
        device.status
        != ClientDevice.Status.ACTIVE
    ):
        return HttpResponseForbidden(
            "Подключения можно создавать "
            "только для активного устройства."
        )

    if (
        account.expires_at
        and account.expires_at
        <= timezone.now()
    ):
        return HttpResponseForbidden(
            "Срок действия аккаунта истёк."
        )

    if (
        device.expires_at
        and device.expires_at
        <= timezone.now()
    ):
        return HttpResponseForbidden(
            "Срок действия устройства истёк."
        )

    existing_awg2 = (
        device.vpn_clients
        .filter(
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
        )
        .exclude(
            status=VPNClient.Status.DELETED,
        )
        .select_related("profile")
    )

    has_full = False
    has_selective = False

    for client in existing_awg2:
        if (
            VPNClientService
            ._profile_is_selective(
                client.profile
            )
        ):
            has_selective = True
        else:
            has_full = True

    xhttp_total = (
        device.xhttp_devices
        .exclude(
            status=XHTTPDevice.Status.DELETED,
        )
        .count()
    )

    full_pool = vpn_server_candidate_rows(
        routing_mode=(
            VPNClientCreateForm
            .ROUTING_MODE_FULL
        ),
    )

    selective_pool = (
        vpn_server_candidate_rows(
            routing_mode=(
                VPNClientCreateForm
                .ROUTING_MODE_SELECTIVE
            ),
        )
    )

    return render(
        request,
        (
            "customers/"
            "connection_product_select.html"
        ),
        {
            "account": account,
            "device": device,
            "has_full": has_full,
            "has_selective": (
                has_selective
            ),
            "xhttp_total": xhttp_total,
            "full_available": bool(
                full_pool
            ),
            "selective_available": bool(
                selective_pool
            ),
        },
    )


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_device_vpn_create_view(request, device_id):
    device = get_object_or_404(
        ClientDevice.objects.select_related("account"),
        pk=device_id,
    )

    account = device.account

    if account.status != CustomerAccount.Status.ACTIVE:
        return HttpResponseForbidden(
            "VPN-подключение можно создавать "
            "только для активного аккаунта."
        )

    if device.status != ClientDevice.Status.ACTIVE:
        return HttpResponseForbidden(
            "VPN-подключение можно создавать "
            "только для активного устройства."
        )

    if (
        account.expires_at
        and account.expires_at <= timezone.now()
    ):
        return HttpResponseForbidden(
            "Срок действия аккаунта истёк."
        )

    if (
        device.expires_at
        and device.expires_at
        <= timezone.now()
    ):
        return HttpResponseForbidden(
            "Срок действия устройства истёк."
        )

    requested_routing_mode = (
        (
            request.POST.get("routing_mode")
            if request.method == "POST"
            else request.GET.get("routing_mode")
        )
        or VPNClientCreateForm.ROUTING_MODE_FULL
    ).strip()

    if requested_routing_mode not in {
        VPNClientCreateForm.ROUTING_MODE_FULL,
        VPNClientCreateForm.ROUTING_MODE_SELECTIVE,
    }:
        requested_routing_mode = (
            VPNClientCreateForm
            .ROUTING_MODE_FULL
        )

    server_rows = (
        vpn_server_candidate_rows(
            routing_mode=(
                requested_routing_mode
            ),
        )
    )

    server_choice = (
        (
            request.POST.get(
                "server_choice"
            )
            if request.method == "POST"
            else request.GET.get(
                "server_choice"
            )
        )
        or "auto"
    ).strip()

    try:
        server = (
            resolve_vpn_server_choice(
                choice=server_choice,
                routing_mode=(
                    requested_routing_mode
                ),
            )
        )
    except ValueError as exc:
        return HttpResponseBadRequest(
            str(exc)
        )

    if server is None:
        return HttpResponseBadRequest(
            (
                "Нет доступного VPN-сервера "
                "для выбранного режима."
            )
        )

    if request.method == "POST":
        data = request.POST.copy()

        routing_mode = (
            requested_routing_mode
        )

        data["server"] = str(
            server.pk
        )

        technical_name = _device_vpn_client_name(
            device=device,
            server=server,
            routing_mode=routing_mode,
        )

        # Эти поля не вводятся повторно оператором.
        # Они наследуются из account/device-контекста.
        data["name"] = technical_name
        data["contact_email"] = account.email
        data["protocol_type"] = VPNClient.ProtocolType.AWG2

        # Срок берём непосредственно из CustomerAccount.
        # Поля старой формы заполняем только для её валидации.
        data["expires_preset"] = (
            VPNClientCreateForm.EXPIRATION_PRESET_UNLIMITED
        )
        data["expires_at"] = ""

        # Пока лимит аккаунта ещё не перенесён на CustomerAccount,
        # новые подключения создаём без отдельного лимита трафика.
        data["traffic_limit_preset"] = (
            VPNClientCreateForm.TRAFFIC_PRESET_UNLIMITED
        )
        data["traffic_custom_value"] = ""
        data["traffic_custom_unit"] = (
            VPNClientCreateForm.TRAFFIC_UNIT_GB
        )

        form = VPNClientCreateForm(
            data,
            server=server,
        )

        if form.is_valid():
            routing_mode = (
                form.cleaned_data.get("routing_mode")
                or VPNClientCreateForm.ROUTING_MODE_FULL
            )

            wants_selective = (
                routing_mode
                == VPNClientCreateForm.ROUTING_MODE_SELECTIVE
            )

            existing_clients = (
                device.vpn_clients
                .filter(
                    protocol_type=VPNClient.ProtocolType.AWG2,
                )
                .exclude(
                    status=VPNClient.Status.DELETED,
                )
                .select_related("profile")
            )

            duplicate_mode = any(
                VPNClientService._profile_is_selective(
                    existing.profile
                )
                == wants_selective
                for existing in existing_clients
            )

            if duplicate_mode:
                form.add_error(
                    "routing_mode",
                    (
                        "У этого устройства уже есть активное "
                        f"подключение "
                        f"{'«Только выбранные сервисы»' if wants_selective else '«Весь интернет через VPN»'}."
                    ),
                )
            else:
                try:
                    client = VPNClientService.create_client(
                        server=server,
                        name=technical_name,
                        protocol_type=VPNClient.ProtocolType.AWG2,
                        routing_mode=routing_mode,
                        expires_at=(
                            device.effective_expires_at
                        ),
                        traffic_limit_bytes=(
                            device.vpn_traffic_limit_bytes
                        ),
                        contact_email=account.email,
                        actor=request.user,
                        device=device,
                    )

                    return redirect(
                        "clients-detail",
                        pk=client.pk,
                    )

                except Exception as exc:
                    form.add_error(
                        None,
                        "Ошибка создания VPN-подключения: "
                        f"{exc}",
                    )

    else:
        form = VPNClientCreateForm(
            initial={
                "protocol_type": VPNClient.ProtocolType.AWG2,
                "routing_mode": requested_routing_mode,
            },
            server=server,
        )

    form.fields["routing_mode"].widget.attrs.update(
        {
            "class": "form-select",
        }
    )

    return render(
        request,
        "customers/vpn_connection_form.html",
        {
            "account": account,
            "device": device,
            "form": form,
            "server": server,
            "server_rows": server_rows,
            "server_choice": server_choice,
        },
    )


@login_required
@operator_required
@require_GET
def customers_list_view(request):
    renewal_filter = (
        request.GET.get("renewal")
        or ""
    ).strip()

    search_query = (
        request.GET.get("q")
        or ""
    ).strip()

    status_filter = (
        request.GET.get("status")
        or ""
    ).strip()

    readiness_filter = (
        request.GET.get("readiness")
        or ""
    ).strip()

    sort_filter = (
        request.GET.get("sort")
        or "name"
    ).strip()

    valid_statuses = {
        "",
        CustomerAccount.Status.ACTIVE,
        CustomerAccount.Status.DISABLED,
    }

    if status_filter not in valid_statuses:
        status_filter = ""

    valid_readiness = {
        "",
        "attention",
        "ready",
        "no_cabinet",
        "no_devices",
        "no_connections",
        "renewal",
        "expired",
        "expiring",
    }

    if readiness_filter not in valid_readiness:
        readiness_filter = ""

    valid_sorts = {
        "name",
        "expires",
        "devices",
        "connections",
        "updated",
    }

    if sort_filter not in valid_sorts:
        sort_filter = "name"

    now = timezone.now()

    expires_soon_at = (
        now
        + timedelta(days=7)
    )

    open_statuses = (
        ClientRenewalRequest.Status.NEW,
        ClientRenewalRequest.Status.IN_PROGRESS,
    )

    accounts = (
        CustomerAccount.objects
        .annotate(
            device_count=Count(
                "devices",
                filter=~Q(
                    devices__status=(
                        ClientDevice.Status.DELETED
                    )
                ),
                distinct=True,
            ),

            vpn_config_count=Count(
                "devices__vpn_clients",
                filter=(
                    ~Q(
                        devices__status=(
                            ClientDevice.Status.DELETED
                        )
                    )
                    & ~Q(
                        devices__vpn_clients__status=(
                            VPNClient.Status.DELETED
                        )
                    )
                ),
                distinct=True,
            ),

            xhttp_config_count=Count(
                "devices__xhttp_devices",
                filter=(
                    ~Q(
                        devices__status=(
                            ClientDevice.Status.DELETED
                        )
                    )
                    & ~Q(
                        devices__xhttp_devices__status=(
                            XHTTPDevice.Status.DELETED
                        )
                    )
                ),
                distinct=True,
            ),

            open_renewal_count=Count(
                "renewal_requests",
                filter=Q(
                    renewal_requests__status__in=(
                        open_statuses
                    )
                ),
                distinct=True,
            ),
        )
        .annotate(
            connection_count=(
                F("vpn_config_count")
                + F("xhttp_config_count")
            ),
        )
        .annotate(
            expiry_state=Case(
                When(
                    expires_at__isnull=True,
                    then=Value("none"),
                ),
                When(
                    expires_at__lte=now,
                    then=Value("expired"),
                ),
                When(
                    expires_at__lte=expires_soon_at,
                    then=Value("soon"),
                ),
                default=Value("normal"),
                output_field=CharField(),
            ),

            readiness_code=Case(
                When(
                    status=CustomerAccount.Status.DELETED,
                    then=Value("deleted"),
                ),
                When(
                    status=CustomerAccount.Status.DISABLED,
                    then=Value("disabled"),
                ),
                When(
                    expires_at__lte=now,
                    then=Value("expired"),
                ),
                When(
                    open_renewal_count__gt=0,
                    then=Value("renewal"),
                ),
                When(
                    expires_at__gt=now,
                    expires_at__lte=expires_soon_at,
                    then=Value("expiring"),
                ),
                When(
                    device_count=0,
                    then=Value("no_devices"),
                ),
                When(
                    connection_count=0,
                    then=Value("no_connections"),
                ),
                default=Value("ready"),
                output_field=CharField(),
            ),
        )
    )

    deleted_count = (
        accounts
        .filter(
            status=CustomerAccount.Status.DELETED
        )
        .count()
    )

    accounts = accounts.exclude(
        status=CustomerAccount.Status.DELETED
    )

    metrics = {
        "total": accounts.count(),

        "active": (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE
            )
            .filter(
                Q(expires_at__isnull=True)
                | Q(expires_at__gt=now)
            )
            .count()
        ),

        "disabled": accounts.filter(
            status=CustomerAccount.Status.DISABLED
        ).count(),

        "deleted": deleted_count,

        "attention": (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE
            )
            .exclude(
                readiness_code="ready"
            )
            .count()
        ),

        "cabinet_missing": (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE,
                user_id__isnull=True,
            )
            .count()
        ),

        "cabinet_enabled": (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE,
                user_id__isnull=False,
            )
            .count()
        ),

        "no_devices": (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE,
                device_count=0,
            )
            .count()
        ),

        "no_connections": (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE,
                connection_count=0,
            )
            .count()
        ),

        "expires_soon": (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE,
                expires_at__gt=now,
                expires_at__lte=expires_soon_at,
            )
            .count()
        ),

        "expired": (
            accounts
            .filter(
                expires_at__lte=now,
            )
            .count()
        ),

        "open_renewals": (
            accounts
            .filter(
                open_renewal_count__gt=0
            )
            .count()
        ),
    }

    if search_query:
        accounts = (
            accounts
            .filter(
                Q(
                    display_name__icontains=(
                        search_query
                    )
                )
                | Q(
                    email__icontains=(
                        search_query
                    )
                )
                | Q(
                    devices__name__icontains=(
                        search_query
                    )
                )
            )
            .distinct()
        )

    if (
        status_filter
        == CustomerAccount.Status.ACTIVE
    ):
        accounts = (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE
            )
            .filter(
                Q(expires_at__isnull=True)
                | Q(expires_at__gt=now)
            )
        )

    elif status_filter:
        accounts = accounts.filter(
            status=status_filter
        )

    if renewal_filter == "open":
        accounts = accounts.filter(
            open_renewal_count__gt=0
        )

    if readiness_filter == "attention":
        accounts = (
            accounts
            .filter(
                status=CustomerAccount.Status.ACTIVE
            )
            .exclude(
                readiness_code="ready"
            )
        )

    elif readiness_filter == "ready":
        accounts = accounts.filter(
            readiness_code="ready"
        )

    elif readiness_filter == "no_cabinet":
        accounts = accounts.filter(
            status=CustomerAccount.Status.ACTIVE,
            user_id__isnull=True,
        )

    elif readiness_filter == "no_devices":
        accounts = accounts.filter(
            status=CustomerAccount.Status.ACTIVE,
            device_count=0,
        )

    elif readiness_filter == "no_connections":
        accounts = accounts.filter(
            status=CustomerAccount.Status.ACTIVE,
            connection_count=0,
        )

    elif readiness_filter == "renewal":
        accounts = accounts.filter(
            open_renewal_count__gt=0
        )

    elif readiness_filter == "expired":
        accounts = accounts.filter(
            expires_at__lte=now,
        )

    elif readiness_filter == "expiring":
        accounts = accounts.filter(
            status=CustomerAccount.Status.ACTIVE,
            expires_at__gt=now,
            expires_at__lte=expires_soon_at,
        )

    sort_map = {
        "name": (
            "display_name",
            "id",
        ),

        "expires": (
            "expires_at",
            "display_name",
            "id",
        ),

        "devices": (
            "-device_count",
            "display_name",
            "id",
        ),

        "connections": (
            "-connection_count",
            "display_name",
            "id",
        ),

        "updated": (
            "-updated_at",
            "display_name",
            "id",
        ),
    }

    accounts = accounts.order_by(
        *sort_map[sort_filter]
    )

    paginator = Paginator(
        accounts,
        25,
    )

    page_obj = paginator.get_page(
        request.GET.get("page")
    )

    page_start = max(
        1,
        page_obj.number - 2,
    )

    page_end = min(
        paginator.num_pages,
        page_obj.number + 2,
    )

    page_numbers = list(
        range(
            page_start,
            page_end + 1,
        )
    )

    query_params = request.GET.copy()
    query_params.pop(
        "page",
        None,
    )

    query_without_page = (
        query_params.urlencode()
    )

    return render(
        request,
        "customers/customers_list.html",
        {
            "accounts": accounts,
            "page_obj": page_obj,
            "paginator": paginator,
            "page_numbers": page_numbers,
            "result_count": paginator.count,
            "query_without_page": query_without_page,
            "metrics": metrics,
            "renewal_filter": renewal_filter,
            "search_query": search_query,
            "status_filter": status_filter,
            "readiness_filter": readiness_filter,
            "sort_filter": sort_filter,
        },
    )


@login_required
@operator_required
@require_GET
def customer_detail_view(request, pk):
    vpn_clients = (
        VPNClient.objects
        .select_related(
            "server",
            "profile",
        )
        .order_by(
            "protocol_type",
            "name",
            "id",
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
            "id",
        )
    )

    devices = (
        ClientDevice.objects
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
        .order_by("name", "id")
    )

    account = get_object_or_404(
        CustomerAccount.objects.prefetch_related(
            Prefetch(
                "devices",
                queryset=devices,
            )
        ),
        pk=pk,
    )

    open_renewal_request = (
        account.renewal_requests
        .filter(
            status__in=[
                ClientRenewalRequest.Status.NEW,
                ClientRenewalRequest.Status.IN_PROGRESS,
            ],
        )
        .order_by("-created_at")
        .first()
    )

    latest_renewal_request = (
        account.renewal_requests
        .order_by("-created_at")
        .first()
    )

    candidate_accounts = (
        CustomerAccount.objects
        .exclude(pk=account.pk)
        .exclude(status=CustomerAccount.Status.DELETED)
        .order_by("display_name", "id")
    )

    workspace = build_customer_workspace(account)

    for row in workspace["devices"]:
        row["access_form"] = (
            DeviceAccessUpdateForm(
                device=row["device"],
                prefix=(
                    f"device-{row['device'].pk}"
                ),
            )
        )

    return render(
        request,
        "customers/customer_detail.html",
        {
            "account": account,
            "workspace": workspace,
            "candidate_accounts": candidate_accounts,
            "open_renewal_request": (
                open_renewal_request
            ),
            "latest_renewal_request": (
                latest_renewal_request
            ),
        },
    )


@login_required
@operator_required
@require_POST
def move_device_view(request, device_id):
    from django.http import Http404, HttpResponseBadRequest
    from django.shortcuts import redirect

    from .services import (
        CustomerAccountOperationError,
        move_device_to_account,
    )

    raw_target_id = request.POST.get("target_account_id", "").strip()

    try:
        target_account_id = int(raw_target_id)
    except (TypeError, ValueError):
        return HttpResponseBadRequest(
            "Некорректный target_account_id."
        )

    try:
        device = move_device_to_account(
            device_id=device_id,
            target_account_id=target_account_id,
        )
    except ClientDevice.DoesNotExist as exc:
        raise Http404("Устройство не найдено.") from exc
    except CustomerAccount.DoesNotExist as exc:
        raise Http404("Целевой аккаунт не найден.") from exc
    except CustomerAccountOperationError as exc:
        return HttpResponseBadRequest(str(exc))

    return redirect(
        "customers-detail",
        pk=device.account_id,
    )


@login_required
@operator_required
@require_POST
def merge_customer_view(request, pk):
    from django.http import Http404, HttpResponseBadRequest
    from django.shortcuts import redirect

    from .services import (
        CustomerAccountOperationError,
        merge_customer_accounts,
    )

    raw_target_id = request.POST.get("target_account_id", "").strip()

    try:
        target_account_id = int(raw_target_id)
    except (TypeError, ValueError):
        return HttpResponseBadRequest(
            "Некорректный target_account_id."
        )

    try:
        merge_customer_accounts(
            source_account_id=pk,
            target_account_id=target_account_id,
        )
    except CustomerAccount.DoesNotExist as exc:
        raise Http404("Аккаунт не найден.") from exc
    except CustomerAccountOperationError as exc:
        return HttpResponseBadRequest(str(exc))

    return redirect(
        "customers-detail",
        pk=target_account_id,
    )


@login_required
@operator_required
@require_POST
def customer_device_access_update_view(
    request,
    device_id,
):
    device = get_object_or_404(
        ClientDevice.objects.select_related(
            "account"
        ),
        pk=device_id,
    )

    if (
        device.status
        == ClientDevice.Status.DELETED
        or device.account.status
        == CustomerAccount.Status.DELETED
    ):
        return HttpResponseForbidden(
            "Удалённое устройство нельзя изменять."
        )

    form = DeviceAccessUpdateForm(
        request.POST,
        device=device,
        prefix=f"device-{device.pk}",
    )

    if not form.is_valid():
        first_error = next(
            iter(form.errors.values()),
            [
                "Проверьте параметры устройства."
            ],
        )[0]

        messages.error(
            request,
            str(first_error),
        )

        return redirect(
            "customers-detail",
            pk=device.account_id,
        )

    try:
        device = (
            update_customer_device_access(
                device_id=device.pk,
                expires_at=(
                    form.cleaned_data[
                        "expires_at"
                    ]
                ),
                apply_traffic=(
                    form.cleaned_data[
                        "apply_traffic"
                    ]
                ),
                traffic_limit_bytes=(
                    form.cleaned_data.get(
                        "resolved_traffic_limit_bytes"
                    )
                ),
                actor=request.user,
            )
        )

    except CustomerMetadataEditError as exc:
        messages.error(
            request,
            str(exc),
        )

    else:
        messages.success(
            request,
            (
                "Срок и VPN-лимиты устройства "
                "обновлены без перевыпуска "
                "конфигураций."
            ),
        )

    return redirect(
        "customers-detail",
        pk=device.account_id,
    )


@login_required
@operator_required
@require_POST
def customer_status_view(
    request,
    pk,
):
    target_status = (
        request.POST.get(
            "status",
            "",
        )
        .strip()
    )

    try:
        set_customer_account_status(
            account_id=pk,
            target_status=(
                target_status
            ),
            actor=request.user,
        )

    except CustomerAccount.DoesNotExist:
        from django.http import Http404

        raise Http404(
            "Аккаунт не найден."
        )

    except CustomerStatusOperationError as exc:
        return HttpResponseBadRequest(
            str(exc)
        )

    return redirect(
        "customers-detail",
        pk=pk,
    )


@login_required
@operator_required
@require_POST
def customer_device_status_view(
    request,
    device_id,
):
    target_status = (
        request.POST.get(
            "status",
            "",
        )
        .strip()
    )

    try:
        result = (
            set_customer_device_status(
                device_id=device_id,
                target_status=(
                    target_status
                ),
                actor=request.user,
            )
        )

    except ClientDevice.DoesNotExist:
        from django.http import Http404

        raise Http404(
            "Устройство не найдено."
        )

    except CustomerStatusOperationError as exc:
        return HttpResponseBadRequest(
            str(exc)
        )

    return redirect(
        "customers-detail",
        pk=(
            result[
                "device"
            ].account_id
        ),
    )
