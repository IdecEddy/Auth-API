#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Set file permissions for SSL certificates and JWT keys
chmod 600 /etc/ssl/certs/tls.key /etc/ssl/certs/tls.crt /app/keys/private.key /app/keys/public.key

# Start the Uvicorn server with SSL
uvicorn src.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --ssl-keyfile=/etc/ssl/certs/tls.key \
    --ssl-certfile=/etc/ssl/certs/tls.crt \
    --reload