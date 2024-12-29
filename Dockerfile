# Use an official Python runtime as a parent image
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    coreutils \
    libpq-dev \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables to prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies (if any)
# RUN apt-get update && apt-get install -y <dependencies> && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy source code
COPY auth-api/src/ ./src

# Create directory for keys
RUN mkdir /app/keys

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose port (change if your app uses a different port)
EXPOSE 8000

# Define the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]