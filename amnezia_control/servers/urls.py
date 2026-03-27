from django.urls import path
from .views import server_detail_view, server_list_view

urlpatterns = [
    path("", server_list_view, name="servers-list"),
    path("<int:pk>/", server_detail_view, name="servers-detail"),
]
