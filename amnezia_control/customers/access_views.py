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

from .access_forms import CustomerAccessCreateForm
from .access_services import (
    CustomerAccessError,
    create_customer_login,
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
