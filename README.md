# NetworkTrafficAnomalyDetectionAPI

The goal of this project is to develop an API that detects anomalies in network traffic using machine learning techniques. This API will help organizations enhance their network security by identifying suspicious activities, reducing response time to potential threats, and mitigating cyberattacks. Our objectives include:

Developing a RESTful API that receives network traffic data and analyzes it for anomalies.

Implementing machine learning models to detect unusual network patterns.

Providing alerts and insights to network administrators for threat mitigation.

Ensuring scalability and ease of integration with existing network security tools.

Project by Sultan, Adilet, Tazhaddin, *



while ($true) { Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/status/" ; Start-Sleep -Seconds 3 }

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/status/" -Method GET | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/packets/" -Method GET | ConvertTo-Json -Depth 10