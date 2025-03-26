from django.shortcuts import render
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import time
import logging

from .packet_capturing import traffic_buffer, buffer_lock
from .ml.dl_model import anomaly_detector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def index(request):
    """Render the main page"""
    return render(request, 'index.html')

@require_http_methods(["GET"])
def get_last_packets(request):
    """Return all captured packets from the buffer"""
    try:
        with buffer_lock:
            packets = [
                {
                    'timestamp': packet['timestamp'],
                    'src': packet['src'],
                    'dst': packet['dst'],
                    'dst_port': packet['dst_port'],
                    'proto': packet['proto'],
                    'length': packet['length'],
                    'raw_data': packet['raw_data']
                }
                for packet in traffic_buffer  # Get all packets
            ]
        
        return JsonResponse({
            'status': 'success',
            'packets': packets,
            'total_packets': len(packets)
        })
    except Exception as e:
        logger.error(f"Error in get_last_packets: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST", "GET"])
def get_traffic_analysis(request):
    """Analyze traffic data for anomalies"""
    try:
        if request.method == "POST":
            data = json.loads(request.body)
            packets = data.get('packets', [])
            
            if not packets:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No packets provided'
                }, status=400)
        else:
            with buffer_lock:
                packets = traffic_buffer  # Get all packets
        
        # Process packets in batches of 1000
        batch_size = 1000
        all_results = []
        total_anomalies = 0
        
        for i in range(0, len(packets), batch_size):
            batch = packets[i:i + batch_size]
            result = anomaly_detector.analyze_batch(batch)
            all_results.append(result)
            if 'anomaly_count' in result:
                total_anomalies += result['anomaly_count']
        
        # Aggregate results
        total_packets = len(packets)
        overall_anomaly_rate = total_anomalies / total_packets if total_packets > 0 else 0
        
        return JsonResponse({
            'status': 'success',
            'analysis': {
                'total_packets': total_packets,
                'total_anomalies': total_anomalies,
                'overall_anomaly_rate': overall_anomaly_rate,
                'status': 'alert' if overall_anomaly_rate > 0.3 else 'normal',
                'batch_results': all_results
            }
        })
        
    except Exception as e:
        logger.error(f"Error in get_traffic_analysis: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

def stream_traffic_status(request):
    """Stream real-time traffic analysis results"""
    def event_stream():
        last_processed_index = 0
        batch_size = 1000
        
        while True:
            try:
                with buffer_lock:
                    current_packets = traffic_buffer[last_processed_index:]
                    
                if current_packets:
                    total_anomalies = 0
                    batch_results = []
                    
                    # Process new packets in batches
                    for i in range(0, len(current_packets), batch_size):
                        batch = current_packets[i:i + batch_size]
                        result = anomaly_detector.analyze_batch(batch)
                        batch_results.append(result)
                        if 'anomaly_count' in result:
                            total_anomalies += result['anomaly_count']
                    
                    # Update processed count
                    last_processed_index += len(current_packets)
                    total_packets = len(current_packets)
                    overall_anomaly_rate = total_anomalies / total_packets if total_packets > 0 else 0
                    
                    event_data = {
                        'timestamp': time.time(),
                        'total_packets_processed': last_processed_index,
                        'new_packets_analyzed': total_packets,
                        'total_anomalies': total_anomalies,
                        'overall_anomaly_rate': overall_anomaly_rate,
                        'status': 'alert' if overall_anomaly_rate > 0.3 else 'normal',
                        'batch_results': batch_results
                    }
                    
                    yield f"data: {json.dumps(event_data)}\n\n"
                
                time.sleep(5)  # Wait 5 seconds between updates
                
            except Exception as e:
                logger.error(f"Error in stream_traffic_status: {str(e)}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(5)
    
    return StreamingHttpResponse(
        event_stream(),
        content_type='text/event-stream'
    )