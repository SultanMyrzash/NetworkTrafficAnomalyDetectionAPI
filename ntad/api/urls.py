from django.urls import path
from .views import get_last_packets, get_system_status, stream_status

urlpatterns = [
    path("packets/", get_last_packets, name="get_last_packets"),
    path("status/", get_system_status, name="get_system_status"),
    path("stream/", stream_status, name="stream_status"),
]

