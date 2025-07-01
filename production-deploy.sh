#!/bin/bash

# AI Guardian Enhanced v4.0.0 - Secure Production Deployment Script
# This script orchestrates the secure deployment of the AI Guardian stack using Docker Compose.
# It follows security best practices and validates the environment before deployment.

set -e # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Security banner
echo -e "${PURPLE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║      AI Guardian Enhanced v4.0.0 Secure Deployment          ║
║                                                              ║
║  🔒 Security-First Production Deployment                     ║
║  🛡️  Environment Validation & Secret Management              ║
║  🚀 Container-Based Architecture                             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "Starting AI Guardian Enhanced v4.0.0 secure production deployment..."

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================

info "Performing prerequisite checks..."

# Check for Docker
if ! command -v docker >/dev/null 2>&1; then
    error "Docker is not installed. Please install Docker before running this script."
fi

# Check for Docker Compose
if ! command -v docker-compose >/dev/null 2>&1 && ! command -v docker compose >/dev/null 2>&1; then
    error "Docker Compose is not installed. Please install it before running this script."
fi

# Determine Docker Compose command
if command -v docker compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

log "✅ Docker and Docker Compose are available"

# Check Docker daemon
if ! docker info >/dev/null 2>&1; then
    error "Docker daemon is not running. Please start Docker before running this script."
fi

log "✅ Docker daemon is running"

# Navigate to the project root
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$SCRIPT_DIR/ai-guardian-production-complete"

if [ ! -d "$PROJECT_ROOT" ]; then
    error "Project directory not found: $PROJECT_ROOT"
fi

cd "$PROJECT_ROOT"
log "✅ Changed to project directory: $(pwd)"

# =============================================================================
# ENVIRONMENT VALIDATION
# =============================================================================

info "Validating environment configuration..."

# Check for .env file
if [ ! -f ".env" ]; then
    error ".env file not found. Please copy .env.example to .env and configure it with your secure values."
fi

log "✅ .env file found"

# Load environment variables for validation
set -a  # Automatically export all variables
source .env
set +a  # Stop automatically exporting

# Validate critical environment variables
validate_env_var() {
    local var_name="$1"
    local var_value="${!var_name}"
    local is_optional="$2"
    
    if [ -z "$var_value" ] || [ "$var_value" = "CHANGE_ME_"* ] || [ "$var_value" = "your_"* ]; then
        if [ "$is_optional" = "optional" ]; then
            warn "Optional environment variable $var_name is not set or uses default value"
        else
            error "Required environment variable $var_name is not set or uses an insecure default value. Please update your .env file."
        fi
    fi
}

# Validate required environment variables
log "Validating required environment variables..."

# Database configuration
validate_env_var "POSTGRES_URL"
validate_env_var "POSTGRES_USER"
validate_env_var "POSTGRES_PASSWORD"
validate_env_var "POSTGRES_DB"

# Security configuration
validate_env_var "SECRET_KEY"
validate_env_var "JWT_SECRET_KEY"
validate_env_var "GRAFANA_ADMIN_PASSWORD"

# Optional variables (warn but don't fail)
validate_env_var "AWS_ACCESS_KEY_ID" "optional"
validate_env_var "SLACK_WEBHOOK_URL" "optional"
validate_env_var "SMTP_HOST" "optional"

log "✅ Environment variables validated"

# =============================================================================
# SECURITY CHECKS
# =============================================================================

info "Performing security checks..."

# Check if we're running as root (not recommended for production)
if [ "$EUID" -eq 0 ]; then
    warn "Running as root. Consider using a non-root user for better security."
fi

# Check for insecure default passwords
check_insecure_password() {
    local var_name="$1"
    local var_value="${!var_name}"
    
    # List of common insecure passwords
    local insecure_passwords=("password" "123456" "admin" "root" "changeme" "default" "test")
    
    for insecure in "${insecure_passwords[@]}"; do
        if [[ "${var_value,,}" == *"${insecure}"* ]]; then
            error "Insecure password detected in $var_name. Please use a strong, unique password."
        fi
    done
}

check_insecure_password "POSTGRES_PASSWORD"
check_insecure_password "GRAFANA_ADMIN_PASSWORD"

log "✅ Security checks passed"

# =============================================================================
# DOCKER ENVIRONMENT PREPARATION
# =============================================================================

info "Preparing Docker environment..."

# Create necessary directories
mkdir -p logs data/postgres data/redis data/grafana

# Set proper permissions
chmod 755 logs data
chmod 700 data/postgres data/redis data/grafana

log "✅ Directories created and permissions set"

# Clean up any existing containers (optional, commented out for safety)
# warn "Stopping existing containers..."
# $DOCKER_COMPOSE down --remove-orphans

# =============================================================================
# DEPLOYMENT
# =============================================================================

info "Starting deployment process..."

# Build and start services
log "Building and starting all services..."
if ! $DOCKER_COMPOSE up --build -d; then
    error "Failed to start services. Check the logs for details."
fi

log "✅ All services started successfully"

# =============================================================================
# HEALTH CHECKS
# =============================================================================

info "Performing health checks..."

# Wait for services to be ready
log "Waiting for services to initialize..."
sleep 30

# Check if containers are running
check_container_health() {
    local container_name="$1"
    local service_name="$2"
    
    if docker ps --filter "name=$container_name" --filter "status=running" | grep -q "$container_name"; then
        log "✅ $service_name is running"
        return 0
    else
        warn "❌ $service_name is not running properly"
        return 1
    fi
}

# Check core services
check_container_health "ai_guardian_postgres" "PostgreSQL Database"
check_container_health "ai_guardian_redis" "Redis Cache"
check_container_health "ai_guardian_api_gateway" "API Gateway"
check_container_health "ai_guardian_web_dashboard" "Web Dashboard"

# Check backend services
check_container_health "ai_guardian_code_scanner" "Code Scanner Service"
check_container_health "ai_guardian_adaptive_learning" "Adaptive Learning Service"
check_container_health "ai_guardian_remediation_engine" "Remediation Engine"
check_container_health "ai_guardian_intelligent_analysis" "Intelligent Analysis Service"

# Check optional services
check_container_health "ai_guardian_advanced_ml" "Advanced ML Service"
check_container_health "ai_guardian_blockchain_security" "Blockchain Security Service"
check_container_health "ai_guardian_iot_mobile_security" "IoT/Mobile Security Service"
check_container_health "ai_guardian_cloud_security" "Cloud Security Service"
check_container_health "ai_guardian_integrations_service" "Integrations Service"
check_container_health "ai_guardian_communications_service" "Communications Service"

# Check monitoring services
check_container_health "ai_guardian_prometheus" "Prometheus Monitoring"
check_container_health "ai_guardian_grafana" "Grafana Dashboard"

# =============================================================================
# DEPLOYMENT SUMMARY
# =============================================================================

echo ""
log "🎉 AI Guardian Enhanced v4.0.0 deployment completed successfully!"
echo ""

info "📊 Service Access Points:"
echo "   🌐 Web Dashboard:     http://localhost:3000"
echo "   🔌 API Gateway:       http://localhost:8000"
echo "   📈 Grafana:           http://localhost:3001 (admin/${GRAFANA_ADMIN_PASSWORD})"
echo "   📊 Prometheus:        http://localhost:9090"
echo ""

info "🔧 Backend Services:"
echo "   🔍 Code Scanner:      http://localhost:5001"
echo "   🧠 Adaptive Learning: http://localhost:5002"
echo "   🛠️  Remediation Engine: http://localhost:5003"
echo "   🤖 Advanced ML:       http://localhost:5004"
echo "   🔗 Blockchain Security: http://localhost:5005"
echo "   📱 IoT/Mobile Security: http://localhost:5006"
echo "   ☁️  Cloud Security:    http://localhost:5007"
echo "   🔗 Integrations:      http://localhost:5008"
echo "   📞 Communications:    http://localhost:5009"
echo "   🧩 Intelligent Analysis: http://localhost:5010"
echo ""

info "💡 Management Commands:"
echo "   📊 Check status:      $DOCKER_COMPOSE ps"
echo "   📋 View logs:         $DOCKER_COMPOSE logs -f [service_name]"
echo "   🛑 Stop services:     $DOCKER_COMPOSE down"
echo "   🔄 Restart service:   $DOCKER_COMPOSE restart [service_name]"
echo "   🔍 Service shell:     $DOCKER_COMPOSE exec [service_name] sh"
echo ""

info "🔒 Security Reminders:"
echo "   • Change default passwords regularly"
echo "   • Monitor logs for suspicious activity"
echo "   • Keep containers updated"
echo "   • Use HTTPS in production with proper SSL certificates"
echo "   • Implement proper firewall rules"
echo "   • Regular security audits and vulnerability scans"
echo ""

log "✅ AI Guardian Enhanced is now protecting your infrastructure!"

# =============================================================================
# POST-DEPLOYMENT VALIDATION
# =============================================================================

info "Running post-deployment validation..."

# Test API Gateway health
if curl -f -s http://localhost:8000/health >/dev/null 2>&1; then
    log "✅ API Gateway health check passed"
else
    warn "⚠️  API Gateway health check failed - service may still be starting"
fi

# Test Web Dashboard
if curl -f -s http://localhost:3000 >/dev/null 2>&1; then
    log "✅ Web Dashboard is accessible"
else
    warn "⚠️  Web Dashboard not yet accessible - may still be starting"
fi

echo ""
log "🚀 Deployment validation completed. Your AI Guardian platform is ready!"
echo ""

# Optional: Display resource usage
info "💻 Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" | head -15

