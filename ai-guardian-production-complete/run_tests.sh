#!/bin/bash

# AI Guardian Enhanced - Robust Integration Test Runner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

cleanup() {
    log "🧹 Cleaning up Docker environment..."
    cd "$BASE_DIR"
    docker compose down -v --remove-orphans
    log "✅ Cleanup complete."
}

# Trap exit signals to ensure cleanup
trap cleanup EXIT

# 1. Start all services
log "🚀 Starting all AI Guardian services in detached mode..."
cd "$BASE_DIR"
docker compose up -d --build --force-recreate
log "✅ Services started. Allowing time for initialization..."
sleep 15

# 2. Wait for all services to be healthy
log "🩺 Waiting for all services to become healthy..."

declare -A services=(
    ["code_scanner"]="http://localhost:5001/health"
    ["adaptive_learning"]="http://localhost:5002/health"
    ["api_gateway"]="http://localhost:8000/health"
    ["advanced_ml"]="http://localhost:5004/health"
    ["blockchain_security"]="http://localhost:5005/health"
    ["iot_mobile_security"]="http://localhost:5006/health"
    ["cloud_security"]="http://localhost:5007/health"
    ["integrations"]="http://localhost:5008/health"
    ["communications"]="http://localhost:5009/health"
)

MAX_RETRIES=20
RETRY_INTERVAL=5
all_healthy=false

for i in $(seq 1 $MAX_RETRIES); do
    all_healthy=true
    for service_name in "${!services[@]}"; do
        url=${services[$service_name]}
        log "Checking health of ${YELLOW}$service_name${GREEN} at $url..."
        if ! curl -fsS "$url" > /dev/null; then
            log "${YELLOW}$service_name is not ready yet.${NC}"
            all_healthy=false
        else
            log "✅ ${GREEN}$service_name is healthy!${NC}"
            # Remove from check list
            unset services[$service_name]
        fi
    done

    if $all_healthy; then
        log "🎉 All services are healthy!"
        break
    fi

    if [ ${#services[@]} -eq 0 ]; then
        log "🎉 All services are healthy!"
        break
    fi

    log "Waiting for ${RETRY_INTERVAL} seconds before next check... ($i/$MAX_RETRIES)"
    sleep $RETRY_INTERVAL
done

if ! $all_healthy && [ ${#services[@]} -gt 0 ]; then
    error "Timeout waiting for services to become healthy. Failing services: ${!services[*]}"
fi

# 3. Install test dependencies
log "🐍 Installing Python test dependencies..."
pip install -r "$BASE_DIR/tests/requirements.txt"
log "✅ Test dependencies installed."

# 4. Run the integration tests
log "🔬 Running integration tests..."
TEST_RESULTS_FILE="$BASE_DIR/test_results.log"
if python -m unittest "$BASE_DIR/tests/integration/test_system_integration_v4.py" &> "$TEST_RESULTS_FILE"; then
    log "✅✅✅ Integration tests PASSED! ✅✅✅"
else
    error "❌❌❌ Integration tests FAILED. ❌❌❌ Check the log file: $TEST_RESULTS_FILE"
fi

log "📄 Full test output can be found in: $TEST_RESULTS_FILE"

# Cleanup is handled by the trap
exit 0 