from django.contrib import admin
from .models import ClientConfigRevision, VPNClient

admin.site.register(VPNClient)
admin.site.register(ClientConfigRevision)
