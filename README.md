# NetworkTrafficAnomalyDetectionAPI

The goal of this project is to develop an API that detects anomalies in network traffic using machine learning techniques. This API will help organizations enhance their network security by identifying suspicious activities, reducing response time to potential threats, and mitigating cyberattacks. Our objectives include:

Developing a RESTful API that receives network traffic data and analyzes it for anomalies.

Implementing machine learning models to detect unusual network patterns.

Providing alerts and insights to network administrators for threat mitigation.

Ensuring scalability and ease of integration with existing network security tools.

Project by Sultan, Adilet, Tazhaddin, *


PS C:\Users\SultanMyrzash\Desktop\NTAD API project> cd .\ntad
PS C:\Users\SultanMyrzash\Desktop\NTAD API project\ntad> python .\manage.py runserver


PS C:\Users\SultanMyrzash\Desktop\NTAD API project\ntad> cd .\api          
PS C:\Users\SultanMyrzash\Desktop\NTAD API project\ntad\api> pytest -v tests.py

# Get all captured packets
curl http://localhost:8000/api/get-last-packets/

# Analyze traffic (POST with custom packets)
curl -X POST http://localhost:8000/api/get-traffic-analysis/ \
  -H "Content-Type: application/json" \
  -d '{
    "packets": [
        {
            "timestamp": "2024-03-11 12:34:56",
            "src": "45.142.120.12",
            "dst": "192.168.1.1",
            "dst_port": 445,
            "proto": "TCP",
            "length": 1500,
            "raw_data": "base64_encoded_data"
        },
        {
            "timestamp": "2024-03-11 12:34:57",
            "src": "45.142.120.12",
            "dst": "192.168.1.1",
            "dst_port": 3389,
            "proto": "TCP",
            "length": 1500,
            "raw_data": "base64_encoded_data"
        },
        {
            "timestamp": "2024-03-11 12:34:58",
            "src": "45.142.120.12",
            "dst": "192.168.1.1",
            "dst_port": 22,
            "proto": "TCP",
            "length": 1500,
            "raw_data": "base64_encoded_data"
        }
    ]
}' 

# Analyze current traffic (GET)
curl http://localhost:8000/api/get-traffic-analysis/

# Stream analysis (in browser JavaScript)
const eventSource = new EventSource('/api/stream-traffic-status/');
eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(data);
};
