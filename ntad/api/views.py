import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
import tensorflow as tf
import joblib
from django.http import JsonResponse, StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import time
import threading

# Constants
CSV_PATH = os.path.join(settings.BASE_DIR, 'captured_network_data.csv')
MODEL_PATH = os.path.join(settings.BASE_DIR, 'ddos_detection_model.keras')
SCALER_PATH = os.path.join(settings.BASE_DIR, 'scaler.joblib')
ENCODERS_PATH = os.path.join(settings.BASE_DIR, 'label_encoders.joblib')
RESULTS_PATH = os.path.join(settings.BASE_DIR, 'detection_results')

# Create results directory if it doesn't exist
os.makedirs(RESULTS_PATH, exist_ok=True)

# Global cache to avoid reloading model repeatedly
_model_cache = None
_scaler_cache = None
_encoders_cache = None
_last_analysis_time = 0
_last_analysis_result = None
_cache_lock = threading.Lock()

def index(request):
    """Render the main dashboard page"""
    return render(request, 'index.html')

def load_model_and_preprocessing():
    """Load model and preprocessing objects with caching"""
    global _model_cache, _scaler_cache, _encoders_cache
    
    with _cache_lock:
        if _model_cache is None:
            try:
                print(f"Loading model from {MODEL_PATH}")
                _model_cache = tf.keras.models.load_model(MODEL_PATH)
                
                print(f"Loading scaler from {SCALER_PATH}")
                _scaler_cache = joblib.load(SCALER_PATH)
                
                print(f"Loading encoders from {ENCODERS_PATH}")
                _encoders_cache = joblib.load(ENCODERS_PATH)
                
            except Exception as e:
                print(f"Error loading model or preprocessing: {e}")
                return None, None, None
                
    return _model_cache, _scaler_cache, _encoders_cache

@csrf_exempt
def get_last_packets(request):
    """API endpoint to get the most recent captured network packets"""
    try:
        # Check if file exists
        if not os.path.exists(CSV_PATH):
            return JsonResponse({
                'status': 'error',
                'message': 'No captured network data found',
                'data': []
            })
            
        # Get rows limit from request or default to 100
        limit = request.GET.get('limit', 100)
        try:
            limit = int(limit)
        except ValueError:
            limit = 100
            
        # Read the CSV file
        df = pd.read_csv(CSV_PATH)
        
        # Check if data is empty
        if len(df) == 0:
            return JsonResponse({
                'status': 'success',
                'message': 'No packets available',
                'data': [],
                'total_rows': 0
            })
            
        # Get the most recent packets (last rows)
        last_packets = df.tail(limit)
        
        # Convert to list of dictionaries for JSON response
        packets_data = last_packets.to_dict(orient='records')
        
        return JsonResponse({
            'status': 'success',
            'message': f'Retrieved last {len(packets_data)} packets',
            'data': packets_data,
            'total_rows': len(df),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
    except Exception as e:
        print(f"Error in get_last_packets: {e}")
        return JsonResponse({
            'status': 'error',
            'message': f'Failed to retrieve packets: {str(e)}',
            'data': []
        }, status=500)

@csrf_exempt
def get_traffic_analysis(request):
    """API endpoint to analyze captured traffic and detect DDoS attacks"""
    global _last_analysis_time, _last_analysis_result
    
    try:
        # Check for cache timeout - only analyze every 5 seconds
        current_time = time.time()
        with _cache_lock:
            if _last_analysis_result and current_time - _last_analysis_time < 5:
                return JsonResponse(_last_analysis_result)
        
        # Check if file exists
        if not os.path.exists(CSV_PATH):
            return JsonResponse({
                'status': 'error',
                'message': 'No captured network data found'
            })
            
        # Read the CSV file
        df = pd.read_csv(CSV_PATH)
        
        # Check if data is empty
        if len(df) == 0:
            return JsonResponse({
                'status': 'success',
                'message': 'No traffic data available for analysis',
                'flows_analyzed': 0,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
        # Load model and preprocessing objects
        model, scaler, encoders = load_model_and_preprocessing()
        if not all([model, scaler, encoders]):
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to load model or preprocessing objects'
            }, status=500)
            
        # Scale the features
        X_scaled = scaler.transform(df)
        
        # Make predictions
        raw_predictions = model.predict(X_scaled)
        
        # Get attack type and binary class predictions
        attack_type_probs = raw_predictions[0]
        binary_class_probs = raw_predictions[1]
        
        # Convert to labels
        attack_type_indices = np.argmax(attack_type_probs, axis=1)
        binary_class_indices = np.argmax(binary_class_probs, axis=1)
        
        attack_types = encoders['label_encoder_type'].inverse_transform(attack_type_indices)
        binary_classes = encoders['label_encoder_binary'].inverse_transform(binary_class_indices)
        
        # Get confidence scores
        attack_type_confidence = np.max(attack_type_probs, axis=1)
        binary_class_confidence = np.max(binary_class_probs, axis=1)
        
        # Generate summary statistics
        total_flows = len(df)
        attack_flows = sum(binary_classes == 'Attack')
        benign_flows = total_flows - attack_flows
        attack_percentage = (attack_flows / total_flows * 100) if total_flows > 0 else 0
        
        # Count attack types
        attack_type_counts = {}
        for attack_type in set(attack_types[binary_classes == 'Attack']):
            attack_type_counts[attack_type] = sum((attack_types == attack_type) & (binary_classes == 'Attack'))
            
        # High confidence attacks (confidence > 0.8)
        threshold = 0.8
        high_conf_attacks = sum((binary_classes == 'Attack') & (binary_class_confidence >= threshold))
        
        # Create results dictionary
        results = {
            'status': 'success',
            'message': 'Traffic analysis complete',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'flows_analyzed': total_flows,
            'detection_summary': {
                'benign_flows': int(benign_flows),
                'attack_flows': int(attack_flows),
                'attack_percentage': round(attack_percentage, 2),
                'high_confidence_attacks': int(high_conf_attacks)
            },
            'attack_types': {k: int(v) for k, v in attack_type_counts.items()},
        }
        
        # Get top 5 most likely attack flows
        if attack_flows > 0:
            attack_indices = np.where(binary_classes == 'Attack')[0]
            top_indices = attack_indices[np.argsort(binary_class_confidence[attack_indices])[-5:]]
            
            top_attacks = []
            for idx in top_indices:
                flow_data = df.iloc[idx].to_dict()
                # Limit the data to key fields
                flow_summary = {
                    'protocol': int(flow_data.get('Protocol', 0)),
                    'flow_duration': flow_data.get('Flow Duration', 0),
                    'total_packets': int(flow_data.get('Total Fwd Packets', 0) + flow_data.get('Total Backward Packets', 0)),
                    'bytes_per_sec': flow_data.get('Flow Bytes/s', 0),
                    'packets_per_sec': flow_data.get('Flow Packets/s', 0),
                    'attack_type': attack_types[idx],
                    'confidence': float(binary_class_confidence[idx])
                }
                top_attacks.append(flow_summary)
                
            results['top_attacks'] = top_attacks
        
        # Save the result in cache
        with _cache_lock:
            _last_analysis_result = results
            _last_analysis_time = current_time
            
        return JsonResponse(results)
        
    except Exception as e:
        print(f"Error in get_traffic_analysis: {e}")
        return JsonResponse({
            'status': 'error',
            'message': f'Failed to analyze traffic: {str(e)}'
        }, status=500)

def generate_status_updates():
    """Generator function for SSE streaming updates"""
    while True:
        try:
            # Get latest traffic analysis
            df = pd.read_csv(CSV_PATH)
            
            # Get analysis
            model, scaler, encoders = load_model_and_preprocessing()
            if not all([model, scaler, encoders]):
                yield f"data: {json.dumps({'status': 'error', 'message': 'Model loading failed'})}\n\n"
                time.sleep(5)
                continue
            
            # Scale the features
            X_scaled = scaler.transform(df)
            
            # Make predictions
            raw_predictions = model.predict(X_scaled)
            
            # Get binary class predictions
            binary_class_probs = raw_predictions[1]
            binary_class_indices = np.argmax(binary_class_probs, axis=1)
            binary_classes = encoders['label_encoder_binary'].inverse_transform(binary_class_indices)
            
            # Get attack type predictions
            attack_type_probs = raw_predictions[0]
            attack_type_indices = np.argmax(attack_type_probs, axis=1)
            attack_types = encoders['label_encoder_type'].inverse_transform(attack_type_indices)
            
            # Calculate summary stats
            total_flows = len(df)
            attack_flows = sum(binary_classes == 'Attack')
            attack_percentage = (attack_flows / total_flows * 100) if total_flows > 0 else 0
            
            # Create an update for streaming
            update = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_flows': total_flows,
                'attack_flows': int(attack_flows),
                'attack_percentage': round(attack_percentage, 2),
                'recent_traffic': len(df.tail(10)),
                'attack_types': {},
            }
            
            # Add attack types
            for attack_type in set(attack_types[binary_classes == 'Attack']):
                update['attack_types'][attack_type] = int(sum((attack_types == attack_type) & (binary_classes == 'Attack')))
            
            # Format as SSE event
            yield f"data: {json.dumps(update)}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'status': 'error', 'message': str(e)})}\n\n"
            
        time.sleep(5)  # Update every 5 seconds

@csrf_exempt
def stream_traffic_status(request):
    """Stream real-time traffic status updates using SSE"""
    response = StreamingHttpResponse(
        generate_status_updates(),
        content_type='text/event-stream'
    )
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'  # Disable buffering for Nginx
    return response