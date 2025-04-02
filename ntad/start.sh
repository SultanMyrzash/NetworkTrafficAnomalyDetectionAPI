#!/bin/bash
# Start packet capturing in background
python packet_capturing.py -o data/captured_network_data.csv &
CAPTURE_PID=$!

# Start Django server
python manage.py runserver 0.0.0.0:8000 &
DJANGO_PID=$!

# Handle shutdown
shutdown() {
    echo "Shutting down..."
    kill $DJANGO_PID
    kill $CAPTURE_PID
    exit 0
}

# Set up signal trapping
trap shutdown SIGTERM SIGINT

# Keep the container running
wait