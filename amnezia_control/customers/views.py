from functools import wraps

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Prefetch, Q
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

from .forms import (
    ClientDeviceCreateForm,
    CustomerAccountCreateForm,
)
from .models import ClientDevice, CustomerAccount


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

    server = (
        Server.objects
        .filter(is_enabled=True)
        .order_by("pk")
        .first()
    )

    if server is None:
        return HttpResponseBadRequest(
            "Активный VPN-сервер не настроен."
        )

    if request.method == "POST":
        data = request.POST.copy()

        routing_mode = (
            data.get("routing_mode")
            or VPNClientCreateForm.ROUTING_MODE_FULL
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
                        f"AWG2-подключение режима "
                        f"{'SELECTIVE' if wants_selective else 'FULL'}."
                    ),
                )
            else:
                try:
                    client = VPNClientService.create_client(
                        server=server,
                        name=technical_name,
                        protocol_type=VPNClient.ProtocolType.AWG2,
                        routing_mode=routing_mode,
                        expires_at=account.expires_at,
                        traffic_limit_bytes=None,
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
                "routing_mode": (
                    VPNClientCreateForm.ROUTING_MODE_FULL
                ),
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

    open_statuses = [
        ClientRenewalRequest.Status.NEW,
        ClientRenewalRequest.Status.IN_PROGRESS,
    ]

    accounts = (
        CustomerAccount.objects
        .annotate(
            device_count=Count(
                "devices",
                distinct=True,
            ),
            vpn_config_count=Count(
                "devices__vpn_clients",
                distinct=True,
            ),
            open_renewal_count=Count(
                "renewal_requests",
                filter=Q(
                    renewal_requests__status__in=(
                        open_statuses
                    ),
                ),
                distinct=True,
            ),
        )
        .order_by(
            "display_name",
            "id",
        )
    )

    if renewal_filter == "open":
        accounts = accounts.filter(
            open_renewal_count__gt=0,
        )

    return render(
        request,
        "customers/customers_list.html",
        {
            "accounts": accounts,
            "renewal_filter": renewal_filter,
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
            "client",
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

    return render(
        request,
        "customers/customer_detail.html",
        {
            "account": account,
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
