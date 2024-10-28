#!/bin/bash

echo "Resetting permissions for development environment..."

# Get container ID
CONTAINER_ID=$(docker ps -qf "name=redirector-dev")

if [ -z "$CONTAINER_ID" ]; then
    echo "Container not found. Starting services..."
    docker-compose up -d
    CONTAINER_ID=$(docker ps -qf "name=redirector-dev")
fi

echo "Fixing permissions inside container..."
docker exec -u root $CONTAINER_ID chown -R developer:developer /app/target
docker exec -u root $CONTAINER_ID chown -R developer:developer /usr/local/cargo

echo "Done! You may need to rebuild your project:"
echo "cargo clean && cargo build"