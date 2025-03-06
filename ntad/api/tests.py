from django.test import TestCase, Client
from django.urls import reverse
import json

class TestGetLastPackets(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('get_last_packets')

    def test_get_last_packets(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('last_packets', response.json())

    def test_invalid_method(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)

class TestGetSystemStatus(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('get_system_status')

    def test_get_system_status(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', response.json())

    def test_invalid_method(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)
    
class TestStreamStatus(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('stream_status')

    def test_stream_status(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/event-stream')

    def test_invalid_method(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)


class TestPacketAnalysis(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('test_packet')

    def test_valid_packet(self):
        response = self.client.post(self.url, json.dumps({'packet': 'valid_packet_data'}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', response.json())

    def test_invalid_packet(self):
        response = self.client.post(self.url, json.dumps({'packet': ''}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', response.json())

    def test_missing_packet_field(self):
        response = self.client.post(self.url, json.dumps({}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', response.json())

    def test_invalid_method(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)
