from django.contrib import messages
from django.contrib.auth.decorators import (
    login_required,
)
from django.http import (
    HttpResponseBadRequest,
    HttpResponseForbidden,
)
from django.shortcuts import (
    get_object_or_404,
    redirect,
    render,
)
from django.views.decorators.http import (
    require_http_methods,
)

from .access_forms import (
    CustomerAccessCreateForm,
    CustomerPasswordResetForm,
)
from .access_services import (
    CustomerAccessError,
    change_customer_password,
    create_customer_login,
    detach_customer_login,
    set_customer_login_enabled,
)
from .models import CustomerAccount


def _operator_allowed(user):
    return bool(
        user.is_authenticated
        and getattr(user, "is_owner", False)
    )


@login_required
@require_http_methods(["GET", "POST"])
def customer_access_create_view(request, pk):
    if not _operator_allowed(request.user):
        return HttpResponseForbidden(
            "Доступ разрешён только оператору."
        )

    account = get_object_or_404(
        CustomerAccount.objects.select_related(
            "user",
        ),
        pk=pk,
    )

    if account.status == CustomerAccount.Status.DELETED:
        return HttpResponseForbidden(
            "Удалённому аккаунту нельзя выдать логин."
        )

    if account.user_id is not None:
        return HttpResponseBadRequest(
            "У этого аккаунта уже есть клиентский логин."
        )

    if request.method == "POST":
        form = CustomerAccessCreateForm(
            request.POST,
            account=account,
        )

        if form.is_valid():
            try:
                create_customer_login(
                    account_id=account.pk,
                    username=form.cleaned_data[
                        "username"
                    ],
                    password=form.cleaned_data[
                        "password1"
                    ],
                    actor=request.user,
                )

                return redirect(
                    "customers-detail",
                    pk=account.pk,
                )

            except CustomerAccessError as exc:
                form.add_error(
                    None,
                    str(exc),
                )

    else:
        form = CustomerAccessCreateForm(
            account=account,
        )

    return render(
        request,
        "customers/access_form.html",
        {
            "account": account,
            "form": form,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def customer_access_manage_view(
    request,
    pk,
):
    if not _operator_allowed(
        request.user
    ):
        return HttpResponseForbidden(
            "Доступ разрешён только оператору."
        )

    account = get_object_or_404(
        CustomerAccount.objects
        .select_related(
            "user",
        ),
        pk=pk,
    )

    if (
        account.status
        == CustomerAccount.Status.DELETED
    ):
        return HttpResponseForbidden(
            "Удалённым аккаунтом "
            "управлять нельзя."
        )

    if account.user_id is None:
        return HttpResponseBadRequest(
            "У этого аккаунта нет "
            "клиентского логина."
        )

    form = CustomerPasswordResetForm(
        request.POST or None,
        user=account.user,
    )

    if request.method == "POST":
        action = (
            request.POST.get("action")
            or ""
        ).strip()

        try:
            if action == "password":
                if form.is_valid():
                    change_customer_password(
                        account_id=account.pk,
                        password=(
                            form.cleaned_data[
                                "password1"
                            ]
                        ),
                        actor=request.user,
                    )

                    messages.success(
                        request,
                        "Пароль клиента изменён.",
                    )

                    return redirect(
                        "customers-access-manage",
                        pk=account.pk,
                    )

            elif action == "disable":
                set_customer_login_enabled(
                    account_id=account.pk,
                    enabled=False,
                    actor=request.user,
                )

                messages.success(
                    request,
                    "Вход в клиентский кабинет отключён.",
                )

                return redirect(
                    "customers-access-manage",
                    pk=account.pk,
                )

            elif action == "enable":
                set_customer_login_enabled(
                    account_id=account.pk,
                    enabled=True,
                    actor=request.user,
                )

                messages.success(
                    request,
                    "Вход в клиентский кабинет включён.",
                )

                return redirect(
                    "customers-access-manage",
                    pk=account.pk,
                )

            elif action == "detach":
                detach_customer_login(
                    account_id=account.pk,
                    actor=request.user,
                )

                messages.success(
                    request,
                    (
                        "Клиентский логин отвязан. "
                        "VPN-конфигурации и устройства "
                        "не изменены."
                    ),
                )

                return redirect(
                    "customers-detail",
                    pk=account.pk,
                )

            else:
                return HttpResponseBadRequest(
                    "Неизвестное действие."
                )

        except CustomerAccessError as exc:
            form.add_error(
                None,
                str(exc),
            )

    return render(
        request,
        "customers/access_manage.html",
        {
            "account": account,
            "customer_user": account.user,
            "form": form,
        },
    )
