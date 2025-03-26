from django.test import TestCase, Client
from django.urls import reverse
import json

# Test case for the get_last_packets endpoint
class TestGetLastPackets(TestCase):
    def setUp(self):
        # Set up the test client and URL for the get_last_packets endpoint
        self.client = Client()
        self.url = reverse('get_last_packets')

    def test_get_last_packets(self):
        # Test that a GET request to the get_last_packets endpoint returns a 200 status code
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        # Test that the response contains the 'last_packets' key
        self.assertIn('last_packets', response.json())

    def test_invalid_method(self):
        # Test that a POST request to the get_last_packets endpoint returns a 405 status code
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)

# Test case for the get_system_status endpoint
class TestGetSystemStatus(TestCase):
    def setUp(self):
        # Set up the test client and URL for the get_system_status endpoint
        self.client = Client()
        self.url = reverse('get_system_status')

    def test_get_system_status(self):
        # Test that a GET request to the get_system_status endpoint returns a 200 status code
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        # Test that the response contains the 'status' key
        self.assertIn('status', response.json())

    def test_invalid_method(self):
        # Test that a POST request to the get_system_status endpoint returns a 405 status code
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)

# Test case for the stream_status endpoint
class TestStreamStatus(TestCase):
    def setUp(self):
        # Set up the test client and URL for the stream_status endpoint
        self.client = Client()
        self.url = reverse('stream_status')

    def test_stream_status(self):
        # Test that a GET request to the stream_status endpoint returns a 200 status code
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        # Test that the response has the 'Content-Type' header set to 'text/event-stream'
        self.assertEqual(response['Content-Type'], 'text/event-stream')

    def test_invalid_method(self):
        # Test that a POST request to the stream_status endpoint returns a 405 status code
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)

# Test case for the test_packet endpoint
class TestPacketAnalysis(TestCase):
    def setUp(self):
        # Set up the test client and URL for the test_packet endpoint
        self.client = Client()
        self.url = reverse('test_packet')

    def test_valid_packet(self):
        # Test that a POST request with valid packet data to the test_packet endpoint returns a 200 status code
        response = self.client.post(self.url, json.dumps({'packet': 'valid_packet_data'}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        # Test that the response contains the 'status' key
        self.assertIn('status', response.json())

    def test_invalid_packet(self):
        # Test that a POST request with invalid (empty) packet data to the test_packet endpoint returns a 200 status code
        response = self.client.post(self.url, json.dumps({'packet': ''}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        # Test that the response contains the 'status' key
        self.assertIn('status', response.json())

    def test_missing_packet_field(self):
        # Test that a POST request with missing packet field to the test_packet endpoint returns a 200 status code
        response = self.client.post(self.url, json.dumps({}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        # Test that the response contains the 'status' key
        self.assertIn('status', response.json())

    def test_invalid_method(self):
        # Test that a GET request to the test_packet endpoint returns a 405 status code
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)