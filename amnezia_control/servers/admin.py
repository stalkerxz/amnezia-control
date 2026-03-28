from django.contrib import admin
from .models import ProtocolProfile, Server, ServerProtocol

admin.site.register(Server)
admin.site.register(ServerProtocol)
admin.site.register(ProtocolProfile)
