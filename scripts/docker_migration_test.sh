#!/usr/bin/env bash

set -euo pipefail

IMAGE_NAME="labca-test"
CONTAINER_NAME="labca-migration-test"

echo ">>> Cleaning up any existing containers"
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

echo ">>> Building image"
docker build -t "$IMAGE_NAME" .

echo ">>> Running migrations inside container"
docker run --rm \
  --name "$CONTAINER_NAME" \
  -e DATABASE_URL="sqlite:///./labca.db" \
  "$IMAGE_NAME" \
  alembic upgrade head

echo ">>> Starting container"
docker run -d \
  --name "$CONTAINER_NAME" \
  -p 8000:8000 \
  -e DATABASE_URL="sqlite:///./labca.db" \
  "$IMAGE_NAME"

sleep 5

echo ">>> Checking /health"
curl -sSf http://localhost:8000/health

echo ">>> Cleaning up"
docker stop "$CONTAINER_NAME"
docker rm "$CONTAINER_NAME" || true

