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
)
from django.views.decorators.http import (
    require_POST,
)

from portal.models import ClientRenewalRequest

from .models import CustomerAccount
from .subscription_services import (
    CustomerRenewalError,
    extend_account_from_renewal,
    set_account_renewal_status,
)


def _operator_allowed(user):
    return bool(
        user.is_authenticated
        and getattr(
            user,
            "is_owner",
            False,
        )
    )


@login_required
@require_POST
def customer_renewal_action_view(
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
        CustomerAccount,
        pk=pk,
    )

    raw_request_id = (
        request.POST.get(
            "renewal_request_id"
        )
        or ""
    ).strip()

    try:
        renewal_request_id = int(
            raw_request_id
        )
    except (TypeError, ValueError):
        return HttpResponseBadRequest(
            "Некорректный renewal_request_id."
        )

    action = (
        request.POST.get("action")
        or ""
    ).strip()

    operator_note = (
        request.POST.get(
            "operator_note"
        )
        or ""
    ).strip()

    try:
        if action == "in_progress":
            set_account_renewal_status(
                account_id=account.pk,
                renewal_request_id=(
                    renewal_request_id
                ),
                target_status=(
                    ClientRenewalRequest
                    .Status.IN_PROGRESS
                ),
                operator_note=operator_note,
                actor=request.user,
            )

            messages.success(
                request,
                "Заявка взята в работу.",
            )

        elif action == "dismiss":
            set_account_renewal_status(
                account_id=account.pk,
                renewal_request_id=(
                    renewal_request_id
                ),
                target_status=(
                    ClientRenewalRequest
                    .Status.DISMISSED
                ),
                operator_note=operator_note,
                actor=request.user,
            )

            messages.success(
                request,
                "Заявка отклонена.",
            )

        elif action == "extend":
            extension_days = (
                request.POST.get(
                    "extension_days"
                )
                or ""
            ).strip()

            account, request_obj = (
                extend_account_from_renewal(
                    account_id=account.pk,
                    renewal_request_id=(
                        renewal_request_id
                    ),
                    extension_days=(
                        extension_days
                    ),
                    operator_note=(
                        operator_note
                    ),
                    actor=request.user,
                )
            )

            messages.success(
                request,
                (
                    "Аккаунт продлён до "
                    f"{account.expires_at:%d.%m.%Y}. "
                    "Срок зеркально обновлён "
                    "у VPN-подключений без "
                    "перевыпуска конфигураций."
                ),
            )

        else:
            return HttpResponseBadRequest(
                "Неизвестное действие."
            )

    except (
        CustomerRenewalError,
        ClientRenewalRequest.DoesNotExist,
    ) as exc:
        return HttpResponseBadRequest(
            str(exc)
        )

    return redirect(
        "customers-detail",
        pk=account.pk,
    )
