import pytest
import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
import time
from django.test import RequestFactory, override_settings
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from unittest.mock import patch, MagicMock, Mock
from django.test import RequestFactory, override_settings

# Import the views module - adjust the import path to match your project structure
from api.views import (
    index, load_model_and_preprocessing, get_last_packets,
    get_traffic_analysis, generate_status_updates, stream_traffic_status
)

# Test data paths
TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')
TEST_CSV_PATH = os.path.join(TEST_DATA_DIR, 'test_network_data.csv')
TEST_EMPTY_CSV_PATH = os.path.join(TEST_DATA_DIR, 'empty_network_data.csv')

@pytest.fixture
def request_factory():
    return RequestFactory()

@pytest.fixture
def reset_global_caches():
    """Reset all global caches before each test"""
    global _model_cache, _scaler_cache, _encoders_cache, _last_analysis_time, _last_analysis_result
    _model_cache = None
    _scaler_cache = None
    _encoders_cache = None
    _last_analysis_time = 0
    _last_analysis_result = None
    yield
    _model_cache = None
    _scaler_cache = None
    _encoders_cache = None
    _last_analysis_time = 0
    _last_analysis_result = None

@pytest.fixture
def mock_model():
    """Create a mock TensorFlow model"""
    model = Mock()
    model.predict.return_value = [
        np.array([[0.1, 0.8, 0.1], [0.2, 0.7, 0.1]]),  # Attack type probs
        np.array([[0.3, 0.7], [0.8, 0.2]])              # Binary class probs
    ]
    return model

@pytest.fixture
def mock_scaler():
    """Create a mock scaler"""
    scaler = Mock()
    scaler.transform.return_value = np.array([[1, 2, 3], [4, 5, 6]])
    return scaler

@pytest.fixture
def mock_encoders():
    """Create mock label encoders"""
    label_encoder_type = Mock()
    label_encoder_type.inverse_transform.return_value = np.array(['DDoS', 'Normal'])
    
    label_encoder_binary = Mock()
    label_encoder_binary.inverse_transform.return_value = np.array(['Attack', 'Benign'])
    
    encoders = {
        'label_encoder_type': label_encoder_type,
        'label_encoder_binary': label_encoder_binary
    }
    return encoders

@pytest.fixture
def sample_network_data():
    """Create a sample DataFrame for network data"""
    data = {
        'Protocol': [6, 17, 6],
        'Flow Duration': [100, 200, 300],
        'Total Fwd Packets': [10, 20, 30],
        'Total Backward Packets': [5, 10, 15],
        'Flow Bytes/s': [1000, 2000, 3000],
        'Flow Packets/s': [100, 200, 300]
    }
    return pd.DataFrame(data)

@pytest.fixture
def create_test_csv(sample_network_data):
    """Create a test CSV file with sample data"""
    os.makedirs(TEST_DATA_DIR, exist_ok=True)
    sample_network_data.to_csv(TEST_CSV_PATH, index=False)
    
    # Also create an empty CSV file
    pd.DataFrame().to_csv(TEST_EMPTY_CSV_PATH, index=False)
    
    yield
    
    # Clean up after test
    if os.path.exists(TEST_CSV_PATH):
        os.remove(TEST_CSV_PATH)
    if os.path.exists(TEST_EMPTY_CSV_PATH):
        os.remove(TEST_EMPTY_CSV_PATH)

# Tests for index view
class TestIndexView:
    
    def test_index_view(self, request_factory):
        """Test 1: Test index view renders template"""
        request = request_factory.get('/')
        with patch('api.views.render') as mock_render:
            mock_render.return_value = HttpResponse('rendered template')
            response = index(request)
            assert mock_render.called
            assert mock_render.call_args[0][0] == request
            assert mock_render.call_args[0][1] == 'index.html'

# Tests for load_model_and_preprocessing function
class TestLoadModelAndPreprocessing:
    
    @patch('tensorflow.keras.models.load_model')
    @patch('joblib.load')
    def test_successful_model_loading(self, mock_joblib_load, mock_tf_load_model, reset_global_caches):
        """Test 2: Test successful loading of model and preprocessing objects"""
        # Setup mock returns
        mock_model = Mock()
        mock_scaler = Mock()
        mock_encoders = Mock()
        
        mock_tf_load_model.return_value = mock_model
        mock_joblib_load.side_effect = [mock_scaler, mock_encoders]
        
        # Call the function
        model, scaler, encoders = load_model_and_preprocessing()
        
        # Assertions
        assert model == mock_model
        assert scaler == mock_scaler
        assert encoders == mock_encoders
        assert mock_tf_load_model.call_count == 1
        assert mock_joblib_load.call_count == 2
    
    @patch('tensorflow.keras.models.load_model')
    @patch('joblib.load')
    def test_model_caching(self, mock_joblib_load, mock_tf_load_model, reset_global_caches):
        """Test 3: Test caching behavior"""
        # Setup mock returns
        mock_model = Mock()
        mock_scaler = Mock()
        mock_encoders = Mock()
        
        mock_tf_load_model.return_value = mock_model
        mock_joblib_load.side_effect = [mock_scaler, mock_encoders]
        
        # First call
        load_model_and_preprocessing()
        
        # Clear the mock call counts
        mock_tf_load_model.reset_mock()
        mock_joblib_load.reset_mock()
        
        # Second call should use cache
        load_model_and_preprocessing()
        
        # Should not call load functions again
        mock_tf_load_model.assert_not_called()
        mock_joblib_load.assert_not_called()   
         
    @patch('tensorflow.keras.models.load_model')
    @patch('joblib.load')
    def test_model_loading_failure(self, mock_joblib_load, mock_tf_load_model, reset_global_caches):
        """Test 4: Test handling of model loading failure"""
        # Setup mock to raise an exception
        mock_tf_load_model.side_effect = Exception("Model file not found")
        mock_joblib_load.side_effect = Exception("Preprocessing file not found")
        
        try:
            # Call the function
            model, scaler, encoders = load_model_and_preprocessing()
            
            # If we get here, all values should be None
            assert model is None
            assert scaler is None
            assert encoders is None
        except Exception:
            pytest.fail("Function should handle exceptions gracefully")

# Tests for get_last_packets view
class TestGetLastPackets:
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_get_last_packets_success(self, mock_read_csv, mock_path_exists, request_factory, sample_network_data):
        """Test 5: Test successful retrieval of packets"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        
        request = request_factory.get('/api/get-last-packets/')
        
        # Execute
        response = get_last_packets(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert len(content['data']) == 3
        assert content['total_rows'] == 3
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_get_last_packets_with_limit(self, mock_read_csv, mock_path_exists, request_factory, sample_network_data):
        """Test 6: Test packets retrieval with limit parameter"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        
        request = request_factory.get('/api/get-last-packets/', {'limit': '2'})
        
        # Execute
        response = get_last_packets(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert len(content['data']) == 2  # Should return only 2 packets
        assert content['total_rows'] == 3
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_get_last_packets_invalid_limit(self, mock_read_csv, mock_path_exists, request_factory, sample_network_data):
        """Test 7: Test behavior with invalid limit parameter"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        
        request = request_factory.get('/api/get-last-packets/', {'limit': 'invalid'})
        
        # Execute
        response = get_last_packets(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert len(content['data']) == 3  # Should return all 3 packets (default limit)
        assert content['total_rows'] == 3
    
    @patch('os.path.exists')
    def test_get_last_packets_file_not_found(self, mock_path_exists, request_factory):
        """Test 8: Test behavior when CSV file doesn't exist"""
        # Setup
        mock_path_exists.return_value = False
        
        request = request_factory.get('/api/get-last-packets/')
        
        # Execute
        response = get_last_packets(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'error'
        assert 'No captured network data found' in content['message']
        assert content['data'] == []
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_get_last_packets_empty_csv(self, mock_read_csv, mock_path_exists, request_factory):
        """Test 9: Test behavior with empty CSV file"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = pd.DataFrame()  # Empty DataFrame
        
        request = request_factory.get('/api/get-last-packets/')
        
        # Execute
        response = get_last_packets(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert 'No packets available' in content['message']
        assert content['data'] == []
        assert content['total_rows'] == 0
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_get_last_packets_exception(self, mock_read_csv, mock_path_exists, request_factory):
        """Test 10: Test exception handling in get_last_packets"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.side_effect = Exception("CSV parsing error")
        
        request = request_factory.get('/api/get-last-packets/')
        
        # Execute
        response = get_last_packets(request)
        
        # Assertions
        assert response.status_code == 500
        content = json.loads(response.content)
        assert content['status'] == 'error'
        assert 'Failed to retrieve packets' in content['message']
        assert content['data'] == []

# Tests for get_traffic_analysis view
class TestGetTrafficAnalysis:
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_traffic_analysis_success(self, mock_load_model, mock_read_csv, mock_path_exists, 
                                      request_factory, sample_network_data, mock_model, mock_scaler, mock_encoders,
                                      reset_global_caches):
        """Test 11: Test successful traffic analysis"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        mock_load_model.return_value = (mock_model, mock_scaler, mock_encoders)
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert content['flows_analyzed'] == 3
        assert 'detection_summary' in content
        assert 'attack_types' in content
        assert 'timestamp' in content
    
    @patch('time.time')
    @patch('os.path.exists')
    def test_traffic_analysis_caching(self, mock_path_exists, mock_time, request_factory, reset_global_caches):
        """Test 12: Test caching behavior in traffic analysis"""
        # Setup
        global _last_analysis_time, _last_analysis_result
        mock_path_exists.return_value = True
        mock_time.return_value = 100  # Mock current time
        
        # Set cache values
        _last_analysis_time = 98  # 2 seconds ago
        _last_analysis_result = {
            'status': 'success',
            'cached': True,
            'timestamp': datetime.now().isoformat()
        }
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert 'timestamp' in content
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_traffic_analysis_attack_detection(self, mock_load_model, mock_read_csv, mock_path_exists, 
                                              request_factory, sample_network_data, mock_model, mock_scaler, mock_encoders,
                                              reset_global_caches):
        """Test 13: Test detection of attack patterns"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        
        # Modify mock encoders to return attack classifications
        encoders = mock_encoders.copy()
        encoders['label_encoder_binary'].inverse_transform.return_value = np.array(['Attack', 'Attack'])
        encoders['label_encoder_type'].inverse_transform.return_value = np.array(['DDoS', 'DDoS'])
        mock_load_model.return_value = (mock_model, mock_scaler, encoders)
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert content['detection_summary']['attack_flows'] > 0
        assert 'DDoS' in content['attack_types']
        assert 'top_attacks' in content
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_traffic_analysis_benign_traffic(self, mock_load_model, mock_read_csv, mock_path_exists,
                                            request_factory, sample_network_data, mock_model, mock_scaler, mock_encoders,
                                            reset_global_caches):
        """Test 14: Test classification of benign traffic"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        
        # Create a new mock model specifically for benign predictions
        benign_model = Mock()
        benign_model.predict.return_value = [
            np.array([[0.95, 0.05], [0.90, 0.10]]),  # Very high probabilities for benign
            np.array([[0.02, 0.98], [0.03, 0.97]])   # Very low probabilities for attack
        ]
        
        # Configure mock encoders for benign predictions
        benign_encoders = mock_encoders.copy()
        benign_encoders['label_encoder_binary'].inverse_transform.return_value = np.array(['Benign', 'Benign'])
        benign_encoders['label_encoder_type'].inverse_transform.return_value = np.array(['Normal', 'Normal'])
        
        mock_load_model.return_value = (benign_model, mock_scaler, benign_encoders)
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert content['detection_summary']['attack_flows'] == 0
        assert content['detection_summary']['benign_flows'] > 0
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_traffic_analysis_model_loading_failure(self, mock_load_model, mock_read_csv, mock_path_exists,
                                                request_factory, sample_network_data, reset_global_caches):
        """Test 15: Test behavior when model loading fails"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        mock_load_model.side_effect = Exception("Model loading failed")
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 500
        content = json.loads(response.content)
        assert content['status'] == 'error'
        assert 'Failed to load model' in content['message']
        assert 'error_details' in content
        

    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_traffic_analysis_empty_csv(self, mock_read_csv, mock_path_exists, request_factory, reset_global_caches):
        """Test 16: Test behavior with empty CSV file"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = pd.DataFrame()  # Empty DataFrame
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'success'
        assert content['flows_analyzed'] == 0
        assert 'No flows to analyze' in content['message']
        assert content.get('detection_summary', {}).get('total_flows', 0) == 0

# Tests for generate_status_updates and stream_traffic_status
class TestStreamingUpdates:
    
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_generate_status_updates_success(self, mock_load_model, mock_read_csv, 
                                            sample_network_data, mock_model, mock_scaler, mock_encoders):
        """Test 17: Test successful generation of streaming updates"""
        # Setup
        mock_read_csv.return_value = sample_network_data
        mock_load_model.return_value = (mock_model, mock_scaler, mock_encoders)
        
        # Execute - get the first yielded event
        generator = generate_status_updates()
        event = next(generator)
        
        # Assertions
        assert event.startswith("data: ")
        data = json.loads(event.replace("data: ", "").strip())
        assert 'timestamp' in data
        assert 'total_flows' in data
        assert 'attack_flows' in data
        assert 'attack_percentage' in data
        assert 'attack_types' in data
    
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_generate_status_updates_model_loading_failure(self, mock_load_model, mock_read_csv, sample_network_data):
        """Test 18: Test error handling in streaming updates"""
        # Setup
        mock_read_csv.return_value = sample_network_data
        mock_load_model.return_value = (None, None, None)  # Model loading failed
        
        # Execute - get the first yielded event
        generator = generate_status_updates()
        event = next(generator)
        
        # Assertions
        assert event.startswith("data: ")
        data = json.loads(event.replace("data: ", "").strip())
        assert 'status' in data
        assert data['status'] == 'error'
        assert 'message' in data
    
    @patch('api.views.generate_status_updates')
    def test_stream_traffic_status_response(self, mock_generate_updates, request_factory):
        """Test 19: Test streaming response format"""
        # Setup
        mock_generate_updates.return_value = iter(["data: {}\n\n"])
        request = request_factory.get('/api/stream-traffic-status/')
        
        # Execute
        response = stream_traffic_status(request)
        
        # Assertions
        assert isinstance(response, StreamingHttpResponse)
        assert response['Content-Type'] == 'text/event-stream'
        assert response['Cache-Control'] == 'no-cache'
        assert response['X-Accel-Buffering'] == 'no'
    
    @patch('pandas.read_csv')
    def test_generate_status_updates_csv_exception(self, mock_read_csv):
        """Test 20: Test error handling when CSV reading fails"""
        # Setup
        mock_read_csv.side_effect = Exception("CSV reading error")
        
        # Execute - get the first yielded event
        generator = generate_status_updates()
        event = next(generator)
        
        # Assertions
        assert event.startswith("data: ")
        data = json.loads(event.replace("data: ", "").strip())
        assert 'status' in data
        assert data['status'] == 'error'
        assert 'message' in data