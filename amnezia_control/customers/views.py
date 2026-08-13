from functools import wraps

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Prefetch
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_GET, require_POST

from vpn.models import VPNClient

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
@require_GET
def customers_list_view(request):
    accounts = (
        CustomerAccount.objects
        .annotate(
            device_count=Count("devices", distinct=True),
            vpn_config_count=Count(
                "devices__vpn_clients",
                distinct=True,
            ),
        )
        .order_by("display_name", "id")
    )

    return render(
        request,
        "customers/customers_list.html",
        {
            "accounts": accounts,
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

    devices = (
        ClientDevice.objects
        .prefetch_related(
            Prefetch(
                "vpn_clients",
                queryset=vpn_clients,
            )
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

    return render(
        request,
        "customers/customer_detail.html",
        {
            "account": account,
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
