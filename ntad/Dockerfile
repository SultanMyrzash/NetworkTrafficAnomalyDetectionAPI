# Image: Start from an official Python slim image matching our project's version.
#    'slim' variants are smaller than the full images.
FROM python:3.12.3-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make startup script executable
RUN chmod +x start.sh

# Create volume for persistent data
VOLUME /app/data

# Expose Django port
EXPOSE 8000

# Run startup script
CMD ["./start.sh"]