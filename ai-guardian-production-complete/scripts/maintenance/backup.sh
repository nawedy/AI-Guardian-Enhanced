#!/bin/bash

# AI Guardian Enhanced v4.0.0 - Backup Script
# Creates comprehensive backups of all data and configurations

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

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

# Configuration
BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="ai-guardian-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

log "Starting AI Guardian Enhanced v4.0.0 backup..."

# Create backup directory
mkdir -p "${BACKUP_PATH}"

# Backup database
log "Backing up PostgreSQL database..."
if command -v pg_dump >/dev/null 2>&1; then
    pg_dump -h localhost -U ai_guardian -d ai_guardian_v4 > "${BACKUP_PATH}/database.sql" 2>/dev/null || \
    docker exec $(docker ps -q -f name=postgres) pg_dump -U ai_guardian ai_guardian_v4 > "${BACKUP_PATH}/database.sql"
    log "Database backup completed"
else
    warn "pg_dump not found, skipping database backup"
fi

# Backup Redis data
log "Backing up Redis data..."
if command -v redis-cli >/dev/null 2>&1; then
    redis-cli --rdb "${BACKUP_PATH}/redis.rdb" 2>/dev/null || \
    docker exec $(docker ps -q -f name=redis) redis-cli --rdb /data/redis.rdb && \
    docker cp $(docker ps -q -f name=redis):/data/redis.rdb "${BACKUP_PATH}/redis.rdb"
    log "Redis backup completed"
else
    warn "redis-cli not found, skipping Redis backup"
fi

# Backup configuration files
log "Backing up configuration files..."
cp -r config/ "${BACKUP_PATH}/"
cp .env "${BACKUP_PATH}/" 2>/dev/null || warn ".env file not found"
log "Configuration backup completed"

# Backup logs
log "Backing up logs..."
if [ -d "logs" ]; then
    cp -r logs/ "${BACKUP_PATH}/"
    log "Logs backup completed"
fi

# Backup uploaded data
log "Backing up data directory..."
if [ -d "data" ]; then
    cp -r data/ "${BACKUP_PATH}/"
    log "Data backup completed"
fi

# Create backup archive
log "Creating backup archive..."
cd "${BACKUP_DIR}"
tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}/"
rm -rf "${BACKUP_NAME}/"
cd ..

# Cleanup old backups (keep last 7 days)
log "Cleaning up old backups..."
find "${BACKUP_DIR}" -name "ai-guardian-backup-*.tar.gz" -mtime +7 -delete 2>/dev/null || true

BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" | cut -f1)
log "Backup completed successfully!"
log "Backup file: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz (${BACKUP_SIZE})"
log "To restore: ./scripts/maintenance/restore.sh ${BACKUP_NAME}.tar.gz"

