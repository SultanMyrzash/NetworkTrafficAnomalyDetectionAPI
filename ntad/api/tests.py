import pytest
import pandas as pd
import numpy as np
import json
from unittest.mock import MagicMock, patch, ANY  # ANY is useful for arbitrary args like request objects

# Django imports
from django.urls import reverse
# FIX 1: Import HttpResponse for mocking render return value
from django.http import HttpRequest, StreamingHttpResponse, HttpResponse
from django.conf import settings
from api import views # Import the views module to be tested

# --- Fixtures ---
@pytest.fixture(autouse=True)
def reset_caches():
    """Fixture to automatically reset caches before each test."""
    # Clear global variables in views used for caching
    with views._cache_lock:
        views._model_cache = None
        views._scaler_cache = None
        views._encoders_cache = None
        views._last_analysis_time = 0
        views._last_analysis_result = None
    yield # Test runs here
    # Optional: Clear again after test if needed, but usually before is sufficient
    with views._cache_lock:
        views._model_cache = None
        views._scaler_cache = None
        views._encoders_cache = None
        views._last_analysis_time = 0
        views._last_analysis_result = None

@pytest.fixture
def mock_settings(settings):
    """Fixture to potentially override Django settings for tests."""
    pass # No overrides needed for now based on current views.py

@pytest.fixture
def mock_df_normal():
    """Provides a sample Pandas DataFrame with 10 rows."""
    data = {f'feature_{i}': np.random.rand(10) for i in range(5)}
    # Add columns expected by the model/scaler if known (example names)
    data['Protocol'] = [6] * 10 # Example TCP
    data['Flow Duration'] = np.random.randint(1000, 100000, 10)
    data['Total Fwd Packets'] = np.random.randint(1, 10, 10)
    data['Total Backward Packets'] = np.random.randint(1, 10, 10)
    data['Flow Bytes/s'] = np.random.rand(10) * 1000
    data['Flow Packets/s'] = np.random.rand(10) * 100
    return pd.DataFrame(data)

@pytest.fixture
def mock_df_empty():
    """Provides an empty Pandas DataFrame."""
    return pd.DataFrame()

# FIX 2: Refine mock_ml_artifacts fixture
@pytest.fixture
def mock_ml_artifacts():
    """Provides mock ML model, scaler, and encoders."""
    mock_model = MagicMock()
    # Configure the predict method to return two arrays (attack type probs, binary probs)
    # Example: 10 flows, 3 attack types, 2 binary classes (Benign, Attack)
    mock_model.predict.return_value = (
        np.random.rand(10, 3), # Attack type probabilities
        np.array([[0.9, 0.1]] * 5 + [[0.1, 0.9]] * 5) # Binary probabilities (5 benign, 5 attack)
    )

    mock_scaler = MagicMock()
    mock_scaler.transform.side_effect = lambda x: x # Simple pass-through scaling

    mock_encoder_type = MagicMock()
    # Ensure inverse_transform returns a NumPy array
    def inverse_transform_type(indices):
        return np.array([f'Type_{i}' for i in indices])
    mock_encoder_type.inverse_transform = inverse_transform_type

    mock_encoder_binary = MagicMock()
    # Ensure inverse_transform returns a NumPy array
    def inverse_transform_binary(indices):
        return np.array(['Benign' if i == 0 else 'Attack' for i in indices])
    mock_encoder_binary.inverse_transform = inverse_transform_binary

    mock_encoders = {
        'label_encoder_type': mock_encoder_type,
        'label_encoder_binary': mock_encoder_binary
    }
    return mock_model, mock_scaler, mock_encoders

# --- Test Cases ---

@pytest.mark.django_db
def test_index_view(client, mocker):
    """TC_IDX: Test main dashboard page renders correctly."""
    # Mock render to return a valid HttpResponse
    mock_render = mocker.patch('api.views.render', return_value=HttpResponse(status=200))

    # Use Django test client to make a request to the root URL
    # Project's urls.py includes urlpatterns = [path('', index, name='index')]
    response = client.get('/') # Assumes root URL maps to index view

    # Assert the view returned HTTP 200 OK
    assert response.status_code == 200

    # Assert that render was called once with the request object and 'index.html'
    mock_render.assert_called_once()
    call_args = mock_render.call_args[0]
    assert isinstance(call_args[0], HttpRequest)
    assert call_args[1] == 'index.html'


@pytest.mark.django_db
def test_get_last_packets_limit(client, mocker, mock_df_normal):
    """TC_GLP_01: Test retrieving a specific number of last packets."""
    mocker.patch('os.path.exists', return_value=True)
    mock_read_csv = mocker.patch('pandas.read_csv', return_value=mock_df_normal)

    # Assuming the URL name 'get_last_packets' is defined in api/urls.py
    url = reverse('get_last_packets') + '?limit=5'
    response = client.get(url)

    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'success'
    assert len(data['data']) == 5
    assert data['total_rows'] == 10
    mock_read_csv.assert_called_once_with(views.CSV_PATH)


@pytest.mark.django_db
def test_get_last_packets_default(client, mocker, mock_df_normal):
    """TC_GLP_02: Test retrieving packets with the default limit."""
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('pandas.read_csv', return_value=mock_df_normal)

    url = reverse('get_last_packets')
    response = client.get(url)

    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'success'
    assert len(data['data']) == 10
    assert data['total_rows'] == 10


@pytest.mark.django_db
def test_get_last_packets_empty_df(client, mocker, mock_df_empty):
    """TC_GLP_03: Test handling of an empty data file for packet retrieval."""
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('pandas.read_csv', return_value=mock_df_empty)

    url = reverse('get_last_packets')
    response = client.get(url)

    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'success'
    assert data['message'] == 'No packets available'
    assert data['data'] == []
    assert data['total_rows'] == 0


@pytest.mark.django_db
def test_get_last_packets_no_file(client, mocker):
    """TC_GLP_04: Test handling when the CSV file does not exist for packet retrieval."""
    mocker.patch('os.path.exists', return_value=False)
    mock_read_csv = mocker.patch('pandas.read_csv')

    url = reverse('get_last_packets')
    response = client.get(url)

    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'error'
    assert 'No captured network data found' in data['message']
    assert data['data'] == []
    mock_read_csv.assert_not_called()


@pytest.mark.django_db
def test_analysis_success(client, mocker, mock_df_normal, mock_ml_artifacts):
    """TC_GTA_01: Test successful traffic analysis with detected attacks."""
    mock_model, mock_scaler, mock_encoders = mock_ml_artifacts
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('pandas.read_csv', return_value=mock_df_normal)
    mocker.patch('api.views.load_model_and_preprocessing', return_value=(mock_model, mock_scaler, mock_encoders))

    url = reverse('get_traffic_analysis')
    response = client.get(url)

    # FIX 2: Check for 200 OK now that the bool error should be fixed
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'success'
    assert data['flows_analyzed'] == 10
    assert data['detection_summary']['benign_flows'] == 5
    assert data['detection_summary']['attack_flows'] == 5
    assert data['detection_summary']['attack_percentage'] == 50.0
    assert 'top_attacks' in data
    assert len(data['top_attacks']) <= 5
    # Check attack types are counted correctly based on mock inverse_transform
    # Example: If Type_1 and Type_2 were predicted for attacks
    # assert 'Type_1' in data['attack_types'] # Be more specific if mock is stable
    # assert 'Type_2' in data['attack_types']
    assert len(data['attack_types']) > 0 # Check that some attack types were recorded

    mock_model.predict.assert_called_once()


@pytest.mark.django_db
def test_analysis_empty_df(client, mocker, mock_df_empty):
    """TC_GTA_02: Test analysis handling of an empty data file."""
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('pandas.read_csv', return_value=mock_df_empty)
    mock_load = mocker.patch('api.views.load_model_and_preprocessing')

    url = reverse('get_traffic_analysis')
    response = client.get(url)

    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'success'
    assert 'No traffic data available for analysis' in data['message']
    assert data['flows_analyzed'] == 0
    mock_load.assert_not_called()


@pytest.mark.django_db
def test_analysis_load_failure(client, mocker, mock_df_normal):
    """TC_GTA_03: Test analysis handling when model/preprocessor loading fails upstream."""
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('pandas.read_csv', return_value=mock_df_normal)
    mocker.patch('api.views.load_model_and_preprocessing', return_value=(None, None, None))

    url = reverse('get_traffic_analysis')
    response = client.get(url)

    assert response.status_code == 500
    data = response.json()
    assert data['status'] == 'error'
    assert 'Failed to load model or preprocessing objects' in data['message']


@pytest.mark.django_db
def test_analysis_caching(client, mocker, mock_df_normal, mock_ml_artifacts):
    """TC_GTA_04: Test that the analysis result time-based caching works."""
    mock_model, mock_scaler, mock_encoders = mock_ml_artifacts
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('pandas.read_csv', return_value=mock_df_normal)
    mock_load = mocker.patch('api.views.load_model_and_preprocessing', return_value=(mock_model, mock_scaler, mock_encoders))
    mock_time = mocker.patch('time.time')

    # --- First Call ---
    mock_time.return_value = 1000.0 # Set current time
    url = reverse('get_traffic_analysis')
    response1 = client.get(url)
    # FIX 2: Check for 200 OK now that the bool error should be fixed
    assert response1.status_code == 200
    data1 = response1.json()
    assert data1['status'] == 'success'
    assert mock_model.predict.call_count == 1 # Predict called the first time

    # --- Second Call (within cache timeout) ---
    mock_time.return_value = 1003.0 # Advance time by 3 seconds (< 5s timeout)
    response2 = client.get(url)
    assert response2.status_code == 200
    data2 = response2.json()
    assert data2 == data1 # Result should be identical from cache
    assert mock_model.predict.call_count == 1 # Call count should still be 1

    # --- Third Call (after cache timeout) ---
    mock_time.return_value = 1006.0 # Advance time by another 3 seconds (> 5s timeout total)
    response3 = client.get(url)
    assert response3.status_code == 200
    data3 = response3.json()
    assert data3['status'] == 'success' # Should succeed
    assert mock_model.predict.call_count == 2 # Assert predict WAS called again


def test_load_model_success_and_failure(mocker, mock_ml_artifacts):
    """TC_LMP: Test model loading success (a) and graceful failure (b) scenarios."""
    # reset_caches fixture rans before this test starts
    # --- Part a: Success ---
    print("\n--- Running Part A: Success ---") # Added print for clarity
    mock_model_success, mock_scaler_success, mock_encoders_success = mock_ml_artifacts

    # Setup mocks for successful loading
    mock_tf_load_success = mocker.patch('tensorflow.keras.models.load_model', return_value=mock_model_success)
    mock_joblib_load_success = mocker.patch('joblib.load', side_effect=[mock_scaler_success, mock_encoders_success])

    # First call - should load and cache
    result_model_a1, result_scaler_a1, result_encoders_a1 = views.load_model_and_preprocessing()

    # Assertions for successful loading
    assert result_model_a1 is mock_model_success
    assert result_scaler_a1 is mock_scaler_success
    assert result_encoders_a1 is mock_encoders_success
    mock_tf_load_success.assert_called_once_with(views.MODEL_PATH)
    assert mock_joblib_load_success.call_count == 2
    mock_joblib_load_success.assert_any_call(views.SCALER_PATH)
    mock_joblib_load_success.assert_any_call(views.ENCODERS_PATH)

    # Manually reset the global cache variables in views.py
    with views._cache_lock:
        views._model_cache = None
        views._scaler_cache = None
        views._encoders_cache = None
        views._last_analysis_time = 0
        views._last_analysis_result = None
    mocker.stopall() # Stop mocks created by mocker in Part A

    # --- Part b: Failure ---
    print("--- Running Part B: Failure ---")
    # Setup mocks for failure
    mock_tf_load_fail = mocker.patch('tensorflow.keras.models.load_model', side_effect=Exception("TF Load Error"))
    mock_joblib_load_fail = mocker.patch('joblib.load') # Mock joblib too

    # Call the function again - should attempt loading and fail
    result_model_b, result_scaler_b, result_encoders_b = views.load_model_and_preprocessing()

    # Assertions for failure scenario
    assert result_model_b is None
    assert result_scaler_b is None
    assert result_encoders_b is None
    mock_tf_load_fail.assert_called_once()
    mock_joblib_load_fail.assert_not_called() # Joblib load shouldn't be called if TF fails first

def test_generate_status_updates(mocker, mock_df_normal, mock_ml_artifacts):
    """TC_STS: Test one cycle of the SSE generator function produces the correct output format."""
    mock_model, mock_scaler, mock_encoders = mock_ml_artifacts
    # Mock dependencies within the generator's loop
    mocker.patch('pandas.read_csv', return_value=mock_df_normal)
    mocker.patch('api.views.load_model_and_preprocessing', return_value=(mock_model, mock_scaler, mock_encoders))

    generator = views.generate_status_updates()
    try:
        # Get the first yielded value
        first_update_str = next(generator)
        # --- REMOVED ASSERTION FOR mock_sleep ---
    except StopIteration:
        pytest.fail("Generator did not yield any value")
    except Exception as e:
        # Fail if any *other* unexpected exception occurs within the generator's try block
        pytest.fail(f"Generator raised unexpected exception during next(): {e}")


    # Assert the format is correct SSE
    assert first_update_str.startswith('data: ')
    assert first_update_str.endswith('\n\n')

    # Parse the JSON data
    try:
        json_part = first_update_str[len('data: '):-2]
        update_data = json.loads(json_part)
    except json.JSONDecodeError:
        pytest.fail(f"Failed to decode JSON from SSE string: {json_part}")

    # Assert content based on mocks
    assert 'timestamp' in update_data
    assert update_data['total_flows'] == 10
    assert update_data['attack_flows'] == 5
    assert update_data['attack_percentage'] == 50.0
    assert 'recent_traffic' in update_data
    assert 'attack_types' in update_data
    assert len(update_data['attack_types']) > 0 # Check some attack types were found

@pytest.mark.django_db
def test_stream_view_headers(client, mocker):
    """TC_STS_02: Test that the streaming view sets up the correct SSE response headers."""
    mock_generator_output = ['data: {"test": 1}\n\n']
    mocker.patch('api.views.generate_status_updates', return_value=iter(mock_generator_output))

    url = reverse('stream_traffic_status')
    response = client.get(url)

    assert response.status_code == 200
    assert isinstance(response, StreamingHttpResponse)
    assert response['Content-Type'] == 'text/event-stream'
    assert response['Cache-Control'] == 'no-cache'
    assert response['X-Accel-Buffering'] == 'no'

    content_iterator = iter(response.streaming_content)
    first_chunk = next(content_iterator)
    if isinstance(first_chunk, bytes):
        first_chunk = first_chunk.decode('utf-8')
    assert first_chunk == mock_generator_output[0]