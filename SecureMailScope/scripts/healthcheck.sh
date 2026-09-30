#!/usr/bin/env bash
# ==============================================================================
# SecureMailScope — System Health Probe & Readiness Inspector
# Probes backend health, readiness, system info, and frontend endpoints.
# ==============================================================================

set -e

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"

echo "================================================================================"
echo "🏥 SecureMailScope System Health Inspection"
echo "================================================================================"

# 1. Probe Backend Liveness (/api/v1/health)
echo -n "Checking Backend Liveness... "
HEALTH_RES=$(curl -s -f "${BACKEND_URL}/api/v1/health" || echo "FAILED")
if [ "${HEALTH_RES}" != "FAILED" ]; then
    echo "✅ PASS (Liveness OK)"
else
    echo "❌ FAIL (Unable to connect to ${BACKEND_URL}/api/v1/health)"
fi

# 2. Probe Backend Readiness & PostgreSQL (/api/v1/health/ready)
echo -n "Checking Database Connectivity & Readiness... "
READY_RES=$(curl -s -f "${BACKEND_URL}/api/v1/health/ready" || echo "FAILED")
if [ "${READY_RES}" != "FAILED" ]; then
    echo "✅ PASS (Database Ready)"
else
    echo "❌ FAIL (Database or readiness probe failed)"
fi

# 3. Probe System Info (/api/v1/health/info)
echo -n "Checking System Info & Metadata... "
INFO_RES=$(curl -s -f "${BACKEND_URL}/api/v1/health/info" || echo "FAILED")
if [ "${INFO_RES}" != "FAILED" ]; then
    echo "✅ PASS (System Info OK)"
else
    echo "❌ FAIL"
fi

# 4. Probe Frontend App Server
echo -n "Checking Frontend Nginx Server... "
FRONT_RES=$(curl -s -f "${FRONTEND_URL}" || echo "FAILED")
if [ "${FRONT_RES}" != "FAILED" ]; then
    echo "✅ PASS (Frontend Operational)"
else
    echo "⚠️ Warning: Frontend on ${FRONTEND_URL} not reachable (check port 3000/5173)"
fi

echo "================================================================================"
echo "Health Probe Complete."
echo "================================================================================"
