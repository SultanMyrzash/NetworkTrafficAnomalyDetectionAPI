# Use an official Python runtime as a parent image matching your project's version
FROM python:3.12.3-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies required by Scapy (libpcap) and potentially other libraries
# NOTE: Using apt-get assumes a Debian/Ubuntu-based image (like python:3.12-slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    # Add any other system dependencies your project might need here
    # Example: gcc build-essential if compiling C extensions is needed
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Upgrade pip and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
# Copy the Django project directory first
COPY ./ntad /app/ntad
# Copy manage.py, packet_capturing.py, start script
COPY manage.py .
COPY packet_capturing.py .
COPY start.sh .
# Copy ML models and preprocessing files needed at runtime
# Adjust if these paths are different or managed via volumes later
COPY ddos_detection_model.keras .
COPY scaler.joblib .
COPY label_encoders.joblib .

# Make the start script executable
RUN chmod +x /app/start.sh

# Expose the port the app runs on
EXPOSE 8000

# Define the command to run the application using the start script
# This script will initially ONLY run Django via Gunicorn.
# Running packet_capturing.py requires a different approach (see notes).
CMD ["/app/start.sh"]