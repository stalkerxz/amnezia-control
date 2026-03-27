from django.urls import path
from .views import (
    client_action_view,
    client_download_config_view,
    clients_create_view,
    clients_detail_view,
    clients_list_view,
)

urlpatterns = [
    path("", clients_list_view, name="clients-list"),
    path("new/", clients_create_view, name="clients-create"),
    path("<int:pk>/", clients_detail_view, name="clients-detail"),
    path("<int:pk>/download/", client_download_config_view, name="clients-download"),
    path("<int:pk>/action/<str:action>/", client_action_view, name="clients-action"),
]
