from django import forms
from .models import VPNClient


class VPNClientCreateForm(forms.Form):
    name = forms.CharField(label="Имя клиента", max_length=120)
    protocol_type = forms.ChoiceField(label="Протокол", choices=VPNClient.ProtocolType.choices)
