from django.db import transaction

from .access_services import (
    CustomerAccessError,
    create_customer_login,
)
from .models import (
    ClientDevice,
    CustomerAccount,
)


class CustomerOnboardingError(ValueError):
    pass


@transaction.atomic
def create_customer_onboarding(
    *,
    display_name,
    email,
    expires_at,
    device_name,
    device_platform,
    device_notes,
    create_login,
    username,
    password,
    actor,
):
    account = CustomerAccount.objects.create(
        display_name=display_name,
        email=email,
        expires_at=expires_at,
        status=CustomerAccount.Status.ACTIVE,
        created_by=actor,
    )

    device = ClientDevice.objects.create(
        account=account,
        name=device_name,
        platform=device_platform,
        notes=device_notes,
        status=ClientDevice.Status.ACTIVE,
    )

    user = None

    if create_login:
        try:
            user = create_customer_login(
                account_id=account.pk,
                username=username,
                password=password,
                actor=actor,
            )

        except CustomerAccessError as exc:
            raise CustomerOnboardingError(
                str(exc)
            ) from exc

    return {
        "account": account,
        "device": device,
        "user": user,
    }
