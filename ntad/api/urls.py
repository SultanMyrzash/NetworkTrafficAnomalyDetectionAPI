from django.urls import path
from api.views import index, get_last_packets, get_traffic_analysis, stream_traffic_status

urlpatterns = [
    path('', index, name='index'),
    path('api/get-last-packets/', get_last_packets, name='get_last_packets'),
    path('api/get-traffic-analysis/', get_traffic_analysis, name='get_traffic_analysis'),
    path('api/stream-traffic-status/', stream_traffic_status, name='stream_traffic_status'),
]
