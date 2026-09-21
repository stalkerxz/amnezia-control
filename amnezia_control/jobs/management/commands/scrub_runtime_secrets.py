from cryptography.fernet import InvalidToken
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from jobs.models import JobEvent
from jobs.services import (
    SENSITIVE_OUTPUT_PLACEHOLDER,
    contains_sensitive_output,
)
from servers.models import ServerProtocol
from vpn.services import ConfigCryptoService


class Command(BaseCommand):
    help = (
        "Remove historical sensitive runtime output from JobEvent "
        "and move AWG HeaderProtectionKey from plaintext runtime "
        "metadata into encrypted metadata. Dry-run by default."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Apply changes. Without this flag only counts are shown.",
        )

    @staticmethod
    def _protocol_change(protocol):
        metadata = dict(protocol.runtime_metadata or {})
        awg_metadata = dict(
            metadata.get("awg2_metadata", {})
            or {}
        )
        plaintext = str(
            awg_metadata.get(
                "HeaderProtectionKey",
                "",
            )
            or ""
        )

        if not plaintext:
            return None

        secret_metadata = dict(
            metadata.get(
                "awg2_secret_metadata",
                {},
            )
            or {}
        )
        existing = str(
            secret_metadata.get(
                "HeaderProtectionKey",
                "",
            )
            or ""
        )

        if existing:
            try:
                decrypted = (
                    ConfigCryptoService.decrypt(
                        existing
                    )
                )
            except (InvalidToken, ValueError) as exc:
                raise CommandError(
                    "Existing encrypted HeaderProtectionKey "
                    f"cannot be decrypted for protocol {protocol.pk}."
                ) from exc

            if decrypted != plaintext:
                raise CommandError(
                    "Plaintext/encrypted HeaderProtectionKey mismatch "
                    f"for protocol {protocol.pk}."
                )
        else:
            secret_metadata[
                "HeaderProtectionKey"
            ] = ConfigCryptoService.encrypt(
                plaintext
            )

        awg_metadata.pop(
            "HeaderProtectionKey",
            None,
        )
        metadata[
            "awg2_metadata"
        ] = awg_metadata
        metadata[
            "awg2_secret_metadata"
        ] = secret_metadata
        metadata[
            "awg2_active_keys"
        ] = sorted(
            set(awg_metadata)
            | set(secret_metadata)
        )
        return metadata

    def handle(self, *args, **options):
        apply_changes = bool(
            options["apply"]
        )

        protocol_changes = []
        for protocol in (
            ServerProtocol.objects.filter(
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                )
            )
            .only(
                "id",
                "runtime_metadata",
            )
            .iterator()
        ):
            updated_metadata = (
                self._protocol_change(
                    protocol
                )
            )
            if updated_metadata is not None:
                protocol.runtime_metadata = (
                    updated_metadata
                )
                protocol_changes.append(
                    protocol
                )

        event_changes = []
        for event in (
            JobEvent.objects.only(
                "id",
                "stdout",
                "stderr",
            )
            .iterator(
                chunk_size=500
            )
        ):
            changed = False

            if contains_sensitive_output(
                event.stdout
            ):
                event.stdout = (
                    SENSITIVE_OUTPUT_PLACEHOLDER
                )
                changed = True

            if contains_sensitive_output(
                event.stderr
            ):
                event.stderr = (
                    SENSITIVE_OUTPUT_PLACEHOLDER
                )
                changed = True

            if changed:
                event_changes.append(
                    event
                )

        self.stdout.write(
            "AWG plaintext runtime secrets: "
            f"{len(protocol_changes)}"
        )
        self.stdout.write(
            "Sensitive JobEvents: "
            f"{len(event_changes)}"
        )

        if not apply_changes:
            self.stdout.write(
                "DRY RUN — no data changed"
            )
            return

        with transaction.atomic():
            if protocol_changes:
                ServerProtocol.objects.bulk_update(
                    protocol_changes,
                    ["runtime_metadata"],
                    batch_size=100,
                )

            if event_changes:
                JobEvent.objects.bulk_update(
                    event_changes,
                    ["stdout", "stderr"],
                    batch_size=500,
                )

        self.stdout.write(
            self.style.SUCCESS(
                "Sensitive runtime state scrubbed."
            )
        )
