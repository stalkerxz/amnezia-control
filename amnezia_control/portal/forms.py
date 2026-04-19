import imghdr
import os

from django import forms
from django.core.exceptions import ValidationError


class PortalRenewalRequestForm(forms.Form):
    MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024
    ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".pdf"}
    ALLOWED_CONTENT_TYPES = {
        "image/jpeg",
        "image/pjpeg",
        "application/pdf",
        "application/x-pdf",
        "application/octet-stream",
    }

    attachment = forms.FileField(
        required=False,
        label="Файл",
        help_text="Форматы: JPG/JPEG/PDF. Максимальный размер файла: 5 МБ.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["attachment"].widget.attrs.update(
            {"class": "form-control form-control-sm", "accept": ".jpg,.jpeg,.pdf"}
        )

    def clean_attachment(self):
        attachment = self.cleaned_data.get("attachment")
        if not attachment:
            return None

        extension = os.path.splitext(attachment.name or "")[1].lower()
        if extension not in self.ALLOWED_EXTENSIONS:
            raise ValidationError("Допустимы только файлы JPG, JPEG или PDF.")

        if attachment.size > self.MAX_ATTACHMENT_SIZE:
            raise ValidationError("Файл слишком большой. Максимальный размер — 5 МБ.")

        content_type = (getattr(attachment, "content_type", "") or "").lower()
        # Некоторые браузеры/прокси для неизвестного файла отдают общий тип
        # application/octet-stream — в этом случае полагаемся на расширение
        # и сигнатуру файла ниже.
        if content_type and content_type not in self.ALLOWED_CONTENT_TYPES:
            raise ValidationError("Неверный тип файла. Допустимы только JPG/JPEG или PDF.")

        header = attachment.read(1024)
        attachment.seek(0)
        if extension in {".jpg", ".jpeg"}:
            if imghdr.what(None, header) != "jpeg":
                raise ValidationError("Загруженный файл не похож на корректное изображение JPG/JPEG.")
        elif extension == ".pdf":
            if not header.startswith(b"%PDF-"):
                raise ValidationError("Загруженный файл не похож на корректный PDF.")

        return attachment
