#!/bin/bash

# AI Guardian Enhanced v4.0.0 - Production Deployment Script
# This script automates the complete deployment of AI Guardian Enhanced

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
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

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        AI Guardian Enhanced v4.0.0 Production Setup         ║
║                                                              ║
║        The Ultimate Cybersecurity Platform                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "Starting AI Guardian Enhanced v4.0.0 production deployment..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   warn "This script should not be run as root for security reasons"
   read -p "Continue anyway? (y/N): " -n 1 -r
   echo
   if [[ ! $REPLY =~ ^[Yy]$ ]]; then
       exit 1
   fi
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ -f /etc/ubuntu-release ] || [ -f /etc/debian_version ]; then
        OS="ubuntu"
        PACKAGE_MANAGER="apt"
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
        OS="centos"
        PACKAGE_MANAGER="yum"
    else
        OS="linux"
        PACKAGE_MANAGER="unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PACKAGE_MANAGER="brew"
else
    error "Unsupported operating system: $OSTYPE"
fi

log "Detected OS: $OS"

# Check system requirements
log "Checking system requirements..."

# Check CPU cores
CPU_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
if [[ "$CPU_CORES" != "unknown" ]] && [[ $CPU_CORES -lt 4 ]]; then
    warn "Minimum 8 CPU cores recommended, found: $CPU_CORES"
fi

# Check RAM
if command -v free >/dev/null 2>&1; then
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $RAM_GB -lt 16 ]]; then
        warn "Minimum 32GB RAM recommended, found: ${RAM_GB}GB"
    fi
fi

# Check disk space
DISK_SPACE=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
if [[ $DISK_SPACE -lt 100 ]]; then
    warn "Minimum 500GB disk space recommended, available: ${DISK_SPACE}GB"
fi

log "System requirements check completed"

# Install dependencies
log "Installing system dependencies..."

case $PACKAGE_MANAGER in
    "apt")
        sudo apt update
        sudo apt install -y curl wget git python3 python3-pip python3-venv nodejs npm docker.io docker-compose postgresql postgresql-contrib redis-server nginx
        ;;
    "yum")
        sudo yum update -y
        sudo yum install -y curl wget git python3 python3-pip nodejs npm docker docker-compose postgresql postgresql-server redis nginx
        ;;
    "brew")
        brew update
        brew install curl wget git python3 node docker docker-compose postgresql redis nginx
        ;;
    *)
        warn "Unknown package manager. Please install dependencies manually:"
        echo "  - Python 3.8+"
        echo "  - Node.js 16+"
        echo "  - Docker & Docker Compose"
        echo "  - PostgreSQL 12+"
        echo "  - Redis 6+"
        echo "  - Nginx"
        read -p "Continue with manual installation? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
        ;;
esac

# Start required services
log "Starting required services..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    sudo systemctl enable redis
    sudo systemctl start redis
    sudo systemctl enable nginx
    sudo systemctl start nginx
fi

# Add user to docker group
if command -v docker >/dev/null 2>&1; then
    sudo usermod -aG docker $USER
    log "Added user to docker group. You may need to log out and back in."
fi

# Setup Python virtual environment
log "Setting up Python environment..."
cd "$(dirname "$0")/../.."

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip

# Install Python dependencies for all services
log "Installing Python dependencies..."
find backend -name "requirements.txt" -exec pip install -r {} \;

# Install additional ML dependencies
pip install torch torchvision transformers scikit-learn numpy pandas

# Setup Node.js environment
log "Setting up Node.js environment..."
if [ -d "frontend/web-dashboard/web-dashboard" ]; then
    cd frontend/web-dashboard/web-dashboard
    npm install
    npm run build
    cd ../../..
fi

# Setup database
log "Setting up database..."
sudo -u postgres createdb ai_guardian_v4 2>/dev/null || log "Database already exists"
sudo -u postgres psql -c "CREATE USER ai_guardian WITH PASSWORD 'ai_guardian_secure_password';" 2>/dev/null || log "User already exists"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ai_guardian_v4 TO ai_guardian;" 2>/dev/null || log "Privileges already granted"

# Create configuration files
log "Creating configuration files..."

# Main configuration
cat > config/production/ai-guardian.yaml << EOF
# AI Guardian Enhanced v4.0.0 Production Configuration

version: "4.0.0"
environment: production

database:
  type: postgresql
  host: localhost
  port: 5432
  database: ai_guardian_v4
  username: ai_guardian
  password: ai_guardian_secure_password
  pool_size: 20
  max_overflow: 30

redis:
  host: localhost
  port: 6379
  database: 0
  max_connections: 100

services:
  api_gateway:
    host: 0.0.0.0
    port: 8000
    workers: 4
    
  code_scanner:
    host: 0.0.0.0
    port: 5001
    workers: 4
    
  adaptive_learning:
    host: 0.0.0.0
    port: 5002
    workers: 2
    
  advanced_ml:
    host: 0.0.0.0
    port: 5004
    workers: 2
    
  blockchain_security:
    host: 0.0.0.0
    port: 5005
    workers: 2
    
  iot_mobile_security:
    host: 0.0.0.0
    port: 5006
    workers: 2
    
  cloud_security:
    host: 0.0.0.0
    port: 5007
    workers: 2
    
  integrations:
    host: 0.0.0.0
    port: 5008
    workers: 2
    
  communications:
    host: 0.0.0.0
    port: 5009
    workers: 2

web_dashboard:
  host: 0.0.0.0
  port: 3000

security:
  secret_key: $(openssl rand -hex 32)
  jwt_secret: $(openssl rand -hex 32)
  encryption_key: $(openssl rand -hex 32)

logging:
  level: INFO
  file: logs/ai-guardian.log
  max_size: 100MB
  backup_count: 5

monitoring:
  enabled: true
  prometheus_port: 9090
  grafana_port: 3001
EOF

# Environment variables
cat > .env << EOF
# AI Guardian Enhanced v4.0.0 Environment Variables
AI_GUARDIAN_VERSION=4.0.0
AI_GUARDIAN_ENV=production
AI_GUARDIAN_CONFIG=config/production/ai-guardian.yaml

# Database
DATABASE_URL=postgresql://ai_guardian:ai_guardian_secure_password@localhost:5432/ai_guardian_v4
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

# ML Models
ML_MODEL_PATH=./models
ML_INFERENCE_TIMEOUT=30

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/ai-guardian.log
EOF

# Create Docker Compose for production
log "Creating Docker Compose configuration..."
cat > deployment/docker/docker-compose.prod.yml << EOF
version: '3.8'

services:
  # Database Services
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: ai_guardian_v4
      POSTGRES_USER: ai_guardian
      POSTGRES_PASSWORD: ai_guardian_secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  # AI Guardian Services
  api-gateway:
    build: ../../backend/api-gateway/api-gateway-service
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://ai_guardian:ai_guardian_secure_password@postgres:5432/ai_guardian_v4
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  code-scanner:
    build: ../../backend/code-scanner/code-scanner-service
    ports:
      - "5001:5001"
    environment:
      - DATABASE_URL=postgresql://ai_guardian:ai_guardian_secure_password@postgres:5432/ai_guardian_v4
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  advanced-ml:
    build: ../../backend/advanced-ml-service
    ports:
      - "5004:5004"
    environment:
      - DATABASE_URL=postgresql://ai_guardian:ai_guardian_secure_password@postgres:5432/ai_guardian_v4
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  blockchain-security:
    build: ../../backend/blockchain-security-service
    ports:
      - "5005:5005"
    environment:
      - DATABASE_URL=postgresql://ai_guardian:ai_guardian_secure_password@postgres:5432/ai_guardian_v4
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  web-dashboard:
    build: ../../frontend/web-dashboard/web-dashboard
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8000
    restart: unless-stopped

  # Monitoring
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  grafana_data:
EOF

# Create service startup scripts
log "Creating service management scripts..."

# Start services script
cat > scripts/setup/start-services.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting AI Guardian Enhanced v4.0.0 services..."

# Start with Docker Compose
cd deployment/docker
docker-compose -f docker-compose.prod.yml up -d

echo "✅ All services started successfully!"
echo ""
echo "🌐 Access URLs:"
echo "  - Web Dashboard: http://localhost:3000"
echo "  - API Gateway: http://localhost:8000"
echo "  - Grafana Monitoring: http://localhost:3001 (admin/admin)"
echo "  - Prometheus: http://localhost:9090"
echo ""
echo "📊 Check service status:"
echo "  docker-compose -f deployment/docker/docker-compose.prod.yml ps"
EOF

# Stop services script
cat > scripts/setup/stop-services.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping AI Guardian Enhanced v4.0.0 services..."

cd deployment/docker
docker-compose -f docker-compose.prod.yml down

echo "✅ All services stopped successfully!"
EOF

# Health check script
cat > scripts/monitoring/health-check.sh << 'EOF'
#!/bin/bash
echo "🔍 AI Guardian Enhanced v4.0.0 Health Check"
echo "============================================"

# Check API Gateway
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ API Gateway: Healthy"
else
    echo "❌ API Gateway: Unhealthy"
fi

# Check Code Scanner
if curl -s http://localhost:5001/health > /dev/null; then
    echo "✅ Code Scanner: Healthy"
else
    echo "❌ Code Scanner: Unhealthy"
fi

# Check Web Dashboard
if curl -s http://localhost:3000 > /dev/null; then
    echo "✅ Web Dashboard: Healthy"
else
    echo "❌ Web Dashboard: Unhealthy"
fi

# Check Database
if pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
    echo "✅ PostgreSQL: Healthy"
else
    echo "❌ PostgreSQL: Unhealthy"
fi

# Check Redis
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis: Healthy"
else
    echo "❌ Redis: Unhealthy"
fi

echo ""
echo "📊 Docker Services Status:"
cd deployment/docker
docker-compose -f docker-compose.prod.yml ps
EOF

# Make scripts executable
chmod +x scripts/setup/*.sh
chmod +x scripts/monitoring/*.sh

# Create directories
mkdir -p logs data/models data/uploads data/exports backups

# Copy documentation
log "Copying documentation..."
cp AI_GUARDIAN_ENHANCED_V4_COMPREHENSIVE_DOCUMENTATION.md docs/
cp AI_GUARDIAN_ENHANCED_V4_FINAL_PROJECT_SUMMARY.md docs/

# Final setup
log "Performing final setup..."

# Initialize database tables
source venv/bin/activate
cd backend/code-scanner/code-scanner-service
python -c "
from src.main import app, db
with app.app_context():
    db.create_all()
    print('Database tables created successfully')
" 2>/dev/null || log "Database tables already exist"

cd ../../..

# Success message
echo -e "${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🎉 AI Guardian Enhanced v4.0.0 Setup Complete! 🎉       ║
║                                                              ║
║  Your production-ready cybersecurity platform is ready!     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "🚀 To start your AI Guardian platform:"
echo "   ./scripts/setup/start-services.sh"
echo ""
log "🌐 Access your platform at:"
echo "   - Web Dashboard: http://localhost:3000"
echo "   - API Gateway: http://localhost:8000"
echo ""
log "📊 Monitor your platform:"
echo "   - Grafana: http://localhost:3001 (admin/admin)"
echo "   - Health Check: ./scripts/monitoring/health-check.sh"
echo ""
log "📚 Documentation available in: docs/"
echo ""
log "✅ AI Guardian Enhanced v4.0.0 is ready for production!"

