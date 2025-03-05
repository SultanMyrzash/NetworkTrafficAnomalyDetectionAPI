from django.http import JsonResponse
from api.packetCapturing import last_packets
from api.ml.fakeml import system_status
import time
from django.http import StreamingHttpResponse


# Server-Sent Event Stream (Auto Sends Status Every 3 Sec)
def stream_status(request):
    def event_stream():
        while True:
            yield f"data: {system_status}\n\n"  # SSE format
            time.sleep(3)  # Wait 3 seconds before sending next update

    return StreamingHttpResponse(event_stream(), content_type="text/event-stream")

# API Endpoint: Get last 10 analyzed packets
def get_last_packets(request):
    return JsonResponse({"last_packets": last_packets})

# API Endpoint: Get System Status (updated every 3 sec)
def get_system_status(request):
    return JsonResponse({"status": system_status})
