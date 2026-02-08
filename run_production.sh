#!/bin/bash
# ============================================================
# TSUNAMI v6.0 - Production Launcher (Gunicorn + Eventlet)
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  TSUNAMI v6.0 - Production Server${NC}"
echo -e "${GREEN}============================================${NC}"

# Defaults
WORKERS=${GUNICORN_WORKERS:-4}
BIND=${GUNICORN_BIND:-"0.0.0.0:8080"}
TIMEOUT=${GUNICORN_TIMEOUT:-120}
LOG_LEVEL=${GUNICORN_LOG_LEVEL:-"info"}
MAX_REQUESTS=${GUNICORN_MAX_REQUESTS:-1000}
MAX_REQUESTS_JITTER=${GUNICORN_MAX_REQUESTS_JITTER:-50}

# Set production env
export FLASK_ENV=production

# Check .env file
if [ -f .env ]; then
    echo -e "${GREEN}[+] Loading .env file${NC}"
    set -a
    source .env
    set +a
fi

# Check required env vars
if [ -z "$SECRET_KEY" ]; then
    echo -e "${RED}[!] WARNING: SECRET_KEY not set. Generating random key.${NC}"
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

echo -e "${YELLOW}[*] Workers: ${WORKERS}${NC}"
echo -e "${YELLOW}[*] Bind: ${BIND}${NC}"
echo -e "${YELLOW}[*] Timeout: ${TIMEOUT}s${NC}"
echo -e "${YELLOW}[*] Log Level: ${LOG_LEVEL}${NC}"

# Run with Gunicorn + Eventlet worker
exec gunicorn \
    --worker-class eventlet \
    --workers "$WORKERS" \
    --bind "$BIND" \
    --timeout "$TIMEOUT" \
    --log-level "$LOG_LEVEL" \
    --access-logfile - \
    --error-logfile - \
    --max-requests "$MAX_REQUESTS" \
    --max-requests-jitter "$MAX_REQUESTS_JITTER" \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --forwarded-allow-ips="*" \
    "dalga_web:app"
