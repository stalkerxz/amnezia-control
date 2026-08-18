from django.utils import timezone

from vpn.models import VPNClient
from vpn.services import VPNClientService

from .models import (
    ClientDevice,
    CustomerAccount,
)


class CustomerConnectionLifecycleService:
    """
    Reconciles device-owned VPNClient state with CustomerAccount/ClientDevice.

    Important:
    - no config reissue;
    - no key rotation;
    - manual disables are preserved;
    - traffic disables are preserved;
    - only OWNER / EXPIRED automatic disables may be restored.
    """

    AUTOMATIC_RESTORE_REASONS = {
        VPNClient.DisableReason.OWNER,
        VPNClient.DisableReason.EXPIRED,
    }

    @staticmethod
    def _account_expired(
        account: CustomerAccount,
        now,
    ) -> bool:
        return bool(
            account.expires_at
            and account.expires_at <= now
        )

    @staticmethod
    def _device_expired(
        device: ClientDevice,
        now,
    ) -> bool:
        return bool(
            device.expires_at
            and device.expires_at <= now
        )

    @classmethod
    def owner_available(
        cls,
        device: ClientDevice,
        *,
        now=None,
    ) -> bool:
        current_time = (
            now
            or timezone.now()
        )

        if (
            device.status
            != ClientDevice.Status.ACTIVE
        ):
            return False

        if cls._device_expired(
            device,
            current_time,
        ):
            return False

        account = device.account

        if (
            account.status
            != CustomerAccount.Status.ACTIVE
        ):
            return False

        if cls._account_expired(
            account,
            current_time,
        ):
            return False

        return True

    @classmethod
    def desired_disable_reason(
        cls,
        *,
        device: ClientDevice,
        client: VPNClient,
        now=None,
    ):
        current_time = (
            now
            or timezone.now()
        )

        limit_state = (
            VPNClientService.get_limit_state(
                client,
                now=current_time,
            )
        )

        # Traffic exhaustion must remain an independent hard block.
        # It must never be accidentally restored merely because an
        # account/device becomes active again.
        if (
            limit_state
            == VPNClient.LimitState.TRAFFIC_EXCEEDED
        ):
            return (
                VPNClient.DisableReason.TRAFFIC_EXCEEDED
            )

        account = device.account

        if (
            cls._account_expired(
                account,
                current_time,
            )
            or cls._device_expired(
                device,
                current_time,
            )
            or limit_state
            == VPNClient.LimitState.EXPIRED
        ):
            return (
                VPNClient.DisableReason.EXPIRED
            )

        if (
            account.status
            != CustomerAccount.Status.ACTIVE
            or device.status
            != ClientDevice.Status.ACTIVE
        ):
            return (
                VPNClient.DisableReason.OWNER
            )

        return None

    @classmethod
    def reconcile_vpn_device(
        cls,
        *,
        device: ClientDevice,
        actor=None,
        now=None,
    ) -> dict:
        current_time = (
            now
            or timezone.now()
        )

        # Always reconcile against fresh persisted owner state.
        #
        # A caller may hold a ClientDevice whose ForeignKey cache still
        # contains an older CustomerAccount instance. This is especially
        # important immediately after subscription renewal, when expires_at
        # has just changed in another transaction/service call.
        #
        # Refresh both ClientDevice.status and CustomerAccount status/expiry
        # before making any runtime decision.
        device = (
            ClientDevice.objects
            .select_related("account")
            .get(pk=device.pk)
        )

        account = device.account

        owner_available = (
            cls.owner_available(
                device,
                now=current_time,
            )
        )

        clients = list(
            device.vpn_clients
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
            .order_by("pk")
        )

        result = {
            "device_id": device.pk,
            "account_id": account.pk,
            "processed": 0,
            "enabled": 0,
            "disabled": 0,
            "unchanged": 0,
            "errors": [],
        }

        for client in clients:
            result["processed"] += 1

            desired_reason = (
                cls.desired_disable_reason(
                    device=device,
                    client=client,
                    now=current_time,
                )
            )

            try:
                if (
                    client.status
                    == VPNClient.Status.ACTIVE
                ):
                    if desired_reason is not None:
                        VPNClientService.set_status(
                            client=client,
                            status=(
                                VPNClient.Status.DISABLED
                            ),
                            actor=actor,
                            disable_reason=(
                                desired_reason
                            ),
                        )

                        result["disabled"] += 1

                    else:
                        # Keep cached state coherent without touching runtime.
                        if (
                            client.limit_state
                            != VPNClient.LimitState.ACTIVE
                        ):
                            client.limit_state = (
                                VPNClient.LimitState.ACTIVE
                            )

                            client.save(
                                update_fields=[
                                    "limit_state",
                                ]
                            )

                        result["unchanged"] += 1

                    continue

                if (
                    client.status
                    != VPNClient.Status.DISABLED
                ):
                    result["unchanged"] += 1
                    continue

                # Never auto-restore manual or traffic disables.
                if (
                    client.disable_reason
                    not in cls.AUTOMATIC_RESTORE_REASONS
                ):
                    result["unchanged"] += 1
                    continue

                # Account/device must be healthy again.
                if not owner_available:
                    result["unchanged"] += 1
                    continue

                # Per-client expiry/traffic still has final veto.
                limit_state = (
                    VPNClientService.get_limit_state(
                        client,
                        now=current_time,
                    )
                )

                if (
                    limit_state
                    != VPNClient.LimitState.ACTIVE
                ):
                    result["unchanged"] += 1
                    continue

                # set_status(ACTIVE) restores the already existing peer
                # from the saved revision/runtime identity.
                # It restores the existing peer without issuing new credentials.
                VPNClientService.set_status(
                    client=client,
                    status=VPNClient.Status.ACTIVE,
                    actor=actor,
                )

                result["enabled"] += 1

            except Exception as exc:
                result["errors"].append(
                    {
                        "client_id": client.pk,
                        "error": str(exc)[:300],
                    }
                )

        return result
