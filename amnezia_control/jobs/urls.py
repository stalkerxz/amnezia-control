from django.urls import path
from .views import jobs_detail_view, jobs_list_view

urlpatterns = [
    path("", jobs_list_view, name="jobs-list"),
    path("<int:pk>/", jobs_detail_view, name="jobs-detail"),
]
