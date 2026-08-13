from django.contrib.auth import (
    views as auth_views,
)
from django.contrib.auth.decorators import (
    login_required,
)
from django.db.models import Prefetch
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils import timezone

from vpn.models import VPNClient, XHTTPDevice

from .models import ClientDevice, CustomerAccount


def _customer_account_for_user(user):
    if not user.is_authenticated:
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

    return render(
        request,
        "customer_portal/home.html",
        {
            "account": account,
            "expired": expired,
            "blocked": blocked,
        },
    )
