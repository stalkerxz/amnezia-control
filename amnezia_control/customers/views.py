from django.contrib.auth.decorators import login_required
from django.db.models import Count, Prefetch
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_GET

from vpn.models import VPNClient

from .models import ClientDevice, CustomerAccount


@login_required
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
