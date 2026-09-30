#!/usr/bin/env bash
# ==============================================================================
# SecureMailScope — Automated Deployment Startup Script
# Initializes environment, checks Docker prerequisites, starts services,
# and verifies container health probes.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "================================================================================"
echo "🚀 SecureMailScope — Deployment Startup & Container Orchestration"
echo "================================================================================"

# Check Docker installation
if ! command -v docker >/dev/null 2>&1; then
    echo "❌ Error: Docker is not installed or not available in PATH."
    exit 1
fi

# Check Docker Compose (plugin or standalone)
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    echo "❌ Error: Docker Compose is not installed."
    exit 1
fi

echo "✅ Docker runtime & Compose detected: $(${DOCKER_COMPOSE_CMD} version)"

# Initialize .env file if missing
if [ ! -f ".env" ]; then
    echo "📋 .env configuration file not found. Copying from .env.example..."
    cp .env.example .env
    echo "✅ .env initialized."
fi

# Build and start services in detached mode
echo "📦 Building and launching SecureMailScope containers..."
${DOCKER_COMPOSE_CMD} up -d --build

echo "⌛ Waiting for container health checks to pass..."
MAX_RETRIES=30
RETRY_COUNT=0

until ${DOCKER_COMPOSE_CMD} ps | grep -q "healthy" || [ ${RETRY_COUNT} -eq ${MAX_RETRIES} ]; do
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "   ...waiting for health probes (${RETRY_COUNT}/${MAX_RETRIES})"
done

echo "================================================================================"
echo "🎉 SecureMailScope Deployment Ready!"
echo "================================================================================"
echo "🌐 Frontend Dashboard: http://localhost:3000  (or http://localhost:5173)"
echo "⚙️ Backend OpenAPI Docs: http://localhost:8000/docs"
echo "🏥 Health Endpoint:    http://localhost:8000/api/v1/health"
echo "================================================================================"
