#!/bin/bash
# start.sh (Place in C:\Users\SultanMyrzash\Desktop\NTAD API project\ntad\)

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Applying database migrations..."
# Use the path inside the container where manage.py lives relative to wsgi.py
python manage.py migrate --noinput

echo "Starting Gunicorn..."
# Adjust --workers based on server resources (e.g., 2 * CPU cores + 1)
# ntad.wsgi:application points to the wsgi.py file inside the inner ntad directory
gunicorn ntad.wsgi:application --bind 0.0.0.0:8000 --workers 4