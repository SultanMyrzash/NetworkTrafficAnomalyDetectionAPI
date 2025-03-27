import pytest
import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
import time
from django.test import RequestFactory
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from unittest.mock import patch, MagicMock, Mock

# Import the views module - adjust the import path to match your project structure
from api.views import (
    index, load_model_and_preprocessing, get_last_packets,
    get_traffic_analysis, generate_status_updates, stream_traffic_status,
    _model_cache, _scaler_cache, _encoders_cache, _last_analysis_time, _last_analysis_result
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
    import api.views
    api.views._model_cache = None
    api.views._scaler_cache = None
    api.views._encoders_cache = None
    api.views._last_analysis_time = 0
    api.views._last_analysis_result = None
    yield
    api.views._model_cache = None
    api.views._scaler_cache = None
    api.views._encoders_cache = None
    api.views._last_analysis_time = 0
    api.views._last_analysis_result = None

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
        assert content['message'] == 'Traffic analysis complete'
        assert content['flows_analyzed'] == 3
        assert 'detection_summary' in content
        assert 'attack_types' in content
        assert content['detection_summary']['attack_flows'] == 1  # Based on our mock data
    
    @patch('api.views._last_analysis_result')
    @patch('api.views._last_analysis_time')
    @patch('time.time')
    def test_traffic_analysis_cache(self, mock_time, mock_last_time, mock_last_result, 
                                   request_factory, reset_global_caches):
        """Test 12: Test caching behavior in traffic analysis"""
        # Setup
        mock_time.return_value = 100  # Current time
        mock_last_time.value = 98     # Last analysis was 2 seconds ago
        
        cached_result = {
            'status': 'success',
            'message': 'Cached result',
            'timestamp': '2025-03-27 10:00:00'
        }
        import api.views
        api.views._last_analysis_time = 98
        api.views._last_analysis_result = cached_result
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content == cached_result  # Should return cached result
    
    @patch('os.path.exists')
    def test_traffic_analysis_file_not_found(self, mock_path_exists, request_factory, reset_global_caches):
        """Test 13: Test behavior when CSV file doesn't exist"""
        # Setup
        mock_path_exists.return_value = False
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 200
        content = json.loads(response.content)
        assert content['status'] == 'error'
        assert 'No captured network data found' in content['message']
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_traffic_analysis_empty_csv(self, mock_read_csv, mock_path_exists, 
                                      request_factory, reset_global_caches):
        """Test 14: Test behavior with empty CSV file"""
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
        assert 'No traffic data available for analysis' in content['message']
        assert content['flows_analyzed'] == 0
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_traffic_analysis_model_loading_failure(self, mock_load_model, mock_read_csv, 
                                                  mock_path_exists, request_factory, 
                                                  sample_network_data, reset_global_caches):
        """Test 15: Test behavior when model loading fails"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.return_value = sample_network_data
        mock_load_model.return_value = (None, None, None)  # Model loading failed
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 500
        content = json.loads(response.content)
        assert content['status'] == 'error'
        assert 'Failed to load model' in content['message']
    
    @patch('os.path.exists')
    @patch('pandas.read_csv')
    def test_traffic_analysis_exception(self, mock_read_csv, mock_path_exists, 
                                      request_factory, reset_global_caches):
        """Test 16: Test exception handling in traffic analysis"""
        # Setup
        mock_path_exists.return_value = True
        mock_read_csv.side_effect = Exception("CSV parsing error")
        
        request = request_factory.get('/api/get-traffic-analysis/')
        
        # Execute
        response = get_traffic_analysis(request)
        
        # Assertions
        assert response.status_code == 500
        content = json.loads(response.content)
        assert content['status'] == 'error'
        assert 'Failed to analyze traffic' in content['message']

# Tests for SSE streaming functions
class TestStreamingFunctions:
    
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_generate_status_updates(self, mock_load_model, mock_read_csv, 
                                   sample_network_data, mock_model, mock_scaler, mock_encoders):
        """Test 17: Test generate_status_updates function"""
        # Setup
        mock_read_csv.return_value = sample_network_data
        mock_load_model.return_value = (mock_model, mock_scaler, mock_encoders)
        
        # Execute - get first item from generator
        generator = generate_status_updates()
        update = next(generator)
        
        # Assertions
        assert isinstance(update, str)
        assert update.startswith('data: ')
        
        # Parse the JSON from the SSE format
        json_str = update.replace('data: ', '').strip()
        data = json.loads(json_str)
        
        assert 'timestamp' in data
        assert 'total_flows' in data
        assert data['total_flows'] == 3
        assert 'attack_flows' in data
        assert 'attack_percentage' in data
        assert 'attack_types' in data
    
    @patch('pandas.read_csv')
    @patch('api.views.load_model_and_preprocessing')
    def test_generate_status_updates_model_failure(self, mock_load_model, mock_read_csv, sample_network_data):
        """Test 18: Test error handling in generate_status_updates"""
        # Setup
        mock_read_csv.return_value = sample_network_data
        mock_load_model.return_value = (None, None, None)  # Model loading failed
        
        # Execute - get first item from generator
        generator = generate_status_updates()
        update = next(generator)
        
        # Assertions
        assert isinstance(update, str)
        assert update.startswith('data: ')
        
        # Parse the JSON from the SSE format
        json_str = update.replace('data: ', '').strip()
        data = json.loads(json_str)
        
        assert 'status' in data
        assert data['status'] == 'error'
        assert 'Model loading failed' in data['message']
    
    @patch('pandas.read_csv')
    def test_generate_status_updates_exception(self, mock_read_csv):
        """Test 19: Test exception handling in generate_status_updates"""
        # Setup
        mock_read_csv.side_effect = Exception("CSV parsing error")
        
        # Execute - get first item from generator
        generator = generate_status_updates()
        update = next(generator)
        
        # Assertions
        assert isinstance(update, str)
        assert update.startswith('data: ')
        
        # Parse the JSON from the SSE format
        json_str = update.replace('data: ', '').strip()
        data = json.loads(json_str)
        
        assert 'status' in data
        assert data['status'] == 'error'
        assert 'CSV parsing error' in data['message']
    
    def test_stream_traffic_status(self, request_factory):
        """Test 20: Test stream_traffic_status view"""
        # Setup
        request = request_factory.get('/api/stream-traffic-status/')
        
        # Mock the generate_status_updates function to avoid infinite loop
        with patch('api.views.generate_status_updates') as mock_generator:
            mock_generator.return_value = iter(['data: {"test": true}\n\n'])
            
            # Execute
            response = stream_traffic_status(request)
            
            # Assertions
            assert isinstance(response, StreamingHttpResponse)
            assert response['Content-Type'] == 'text/event-stream'
            assert response['Cache-Control'] == 'no-cache'
            assert response['X-Accel-Buffering'] == 'no'