from django.http import JsonResponse, HttpResponse, HttpResponseNotAllowed
from django.shortcuts import render
from api.packetCapturing import last_packets
from api.ml.fakeml import system_status, analyze_packet
import time
from django.http import StreamingHttpResponse
import json

# Server-Sent Event Stream (Auto Sends Status Every 3 Sec)
def stream_status(request):
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    def event_stream():
        while True:
            yield f"data: {system_status}\n\n"  # SSE format
            time.sleep(3)  # Wait 3 seconds before sending next update

    return StreamingHttpResponse(event_stream(), content_type="text/event-stream")

# API Endpoint: Get last 10 analyzed packets
def get_last_packets(request):
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    return JsonResponse({"last_packets": last_packets})

# API Endpoint: Get System Status (updated every 3 sec)
def get_system_status(request):
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    return JsonResponse({"status": system_status})

# Serve the frontend
def index(request):
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    return render(request, 'index.html')

# API Endpoint: Analyze user-provided packet
def test_packet(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    data = json.loads(request.body)
    packet = data.get('packet', '')
    status = analyze_packet({"raw_data": packet})
    return JsonResponse({"status": status})