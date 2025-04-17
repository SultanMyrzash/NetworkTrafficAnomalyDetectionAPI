#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting NTAD API Server..."

# Apply database migrations (good practice, even if models are simple)
# Uses the 'ntad.ntad.settings' path relative to the WORKDIR
echo "Applying database migrations..."
python manage.py migrate --noinput

# Start Gunicorn server
# Binds to 0.0.0.0 to be accessible from outside the container
# Uses 4 worker processes (adjust based on your server resources)
# Points to the WSGI application object in your project
echo "Starting Gunicorn..."
gunicorn ntad.ntad.wsgi:application --bind 0.0.0.0:8000 --workers 4

# IMPORTANT NOTE:
# This script currently ONLY starts the Django application via Gunicorn.
# Running 'python packet_capturing.py' simultaneously requires
# a process manager like 'supervisor' within the container,
# or running it as a separate container/process during deployment.
# For simplicity in CI/CD build/test, we focus on the Django app here.