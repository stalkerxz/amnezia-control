from django import forms
from vpn.models import VPNClient


class ClientCreateForm(forms.Form):
    name = forms.CharField(max_length=120, label="Имя клиента")
    protocol_type = forms.ChoiceField(choices=VPNClient.ProtocolType.choices, label="Протокол")
