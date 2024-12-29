#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to decode base64 environment variables and write to files
decode_env_var() {
    local env_var=$1
    local file_path=$2
    if [ -z "${!env_var}" ]; then
        echo "Error: Environment variable $env_var is not set."
        exit 1
    fi
    echo "Decoding and writing $env_var to $file_path."
    echo "${!env_var}" | base64 -d > "$file_path"
}

# Decode and write SSL keys
decode_env_var "SSL_KEY_BASE64" "/app/keys/key.pem"
decode_env_var "SSL_CERT_BASE64" "/app/keys/cert.crt"

# Decode and write JWT keys
decode_env_var "JWT_PRIVATE_KEY_BASE64" "/app/keys/private.key"
decode_env_var "JWT_PUBLIC_KEY_BASE64" "/app/keys/public.key"

# Optionally, set permissions for key files
chmod 600 /app/keys/key.pem /app/keys/cert.crt /app/keys/private.key /app/keys/public.key

# Start the Uvicorn server
cd /app/src
uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --ssl-keyfile=/app/keys/key.pem \
    --ssl-certfile=/app/keys/cert.crt \
    --reload