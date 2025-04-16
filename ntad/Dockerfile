# ntad/Dockerfile (Modified COPY paths)

# 1. Base Image
FROM python:3.12.3-slim

# 2. Env Vars
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# 3. Working Dir
WORKDIR /app

# 4. System Deps (Keep if needed)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# 5. Copy requirements.txt FROM the build context root (which is now 'ntad/')
COPY requirements.txt . # This is now correct, as requirements.txt is at the root of the 'ntad' context

# 6. Install Deps
RUN pip install --no-cache-dir -r requirements.txt

# 7. Copy necessary files/dirs FROM the build context root ('ntad/')
COPY manage.py .       # Copy manage.py from 'ntad/' context root
COPY start.sh .        # Copy start.sh from 'ntad/' context root
COPY ./ntad /app/ntad  # Copy the inner 'ntad' dir (with settings.py, wsgi.py)
COPY ./api /app/api    # Copy the 'api' app directory

# 8. Make executable
RUN chmod +x /app/start.sh

# 9. Expose Port
EXPOSE 8000

# 10. Start Command
CMD ["/app/start.sh"]