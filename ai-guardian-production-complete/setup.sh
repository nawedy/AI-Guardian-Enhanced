#!/bin/bash

# AI Guardian Enhanced - Docker-Based Development Environment Setup

set -e

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

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    AI Guardian Enhanced - Development Environment Setup      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "Verifying development environment prerequisites..."

# 1. Check for Docker and Docker Compose
if ! command -v docker >/dev/null 2>&1; then
    error "Docker is not installed. Please install Docker to continue."
fi

if ! command -v docker-compose >/dev/null 2>&1; then
    error "Docker Compose is not installed. Please install it to continue."
fi

log "✅ Docker and Docker Compose are installed."

# 2. Check for .env file
if [ ! -f ".env" ]; then
    log "📄 .env file not found. Creating one from .env.example..."
    if [ ! -f ".env.example" ]; then
        error ".env.example not found. Cannot create .env file."
    fi
    cp .env.example .env
    log "✅ .env file created successfully."
    echo -e "${YELLOW}IMPORTANT: You must now edit the .env file and fill in your passwords and secrets.${NC}"
else
    log "✅ .env file already exists."
fi

# 3. Initialize git repository if it doesn't exist
if [ ! -d ".git" ]; then
    log "📦 Initializing git repository..."
    git init
    # Add a .gitignore if it doesn't exist
    if [ ! -f ".gitignore" ]; then
        echo ".env" > .gitignore
        echo "node_modules/" >> .gitignore
        echo "venv/" >> .gitignore
        echo "__pycache__/" >> .gitignore
    fi
    git add .
    git commit -m "Initial commit: AI Guardian project setup"
    log "✅ Git repository initialized."
fi

echo ""
log "🎉 Development environment setup is complete!"
echo ""
echo -e "${YELLOW}Your development environment now runs entirely inside Docker.${NC}"
echo ""
log "🚀 To start your development stack:"
echo "   docker compose up --build -d"
echo ""
log "💡 Other useful commands:"
echo "   - Follow logs for all services: docker compose logs -f"
echo "   - Follow logs for a specific service: docker compose logs -f <service_name>"
echo "   - Stop all services: docker compose down"
echo "   - Access a service's shell: docker compose exec <service_name> sh"
echo ""
log "📖 See the README.md and CHANGELOG.md for more details."

