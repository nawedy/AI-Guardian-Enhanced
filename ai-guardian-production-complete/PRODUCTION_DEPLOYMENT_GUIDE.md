# AI Guardian Enhanced v4.0.0 - Production Deployment Guide

## 🚀 Overview

This guide covers the production deployment of AI Guardian Enhanced v4.0.0, a comprehensive AI-powered security platform with 11 containerized microservices.

## 🏗️ Architecture

### Containerized Microservices
- **API Gateway** (Port 8000) - Central API routing and authentication
- **Code Scanner** (Port 5001) - Static code analysis and vulnerability detection
- **Adaptive Learning** (Port 5002) - Machine learning-based threat adaptation
- **Remediation Engine** (Port 5003) - Automated security fix suggestions
- **Advanced ML** (Port 5004) - Deep learning security models
- **Blockchain Security** (Port 5005) - Smart contract and DeFi security analysis
- **IoT/Mobile Security** (Port 5006) - Device and mobile app security scanning
- **Cloud Security** (Port 5007) - Multi-cloud security assessment
- **Integrations** (Port 5008) - Third-party tool integrations (JIRA, Slack, Splunk)
- **Communications** (Port 5009) - Email and notification services
- **Intelligent Analysis** (Port 5010) - AI-powered security insights

### Frontend & Monitoring
- **Web Dashboard** (Port 3000) - React-based security dashboard
- **Grafana** (Port 3001) - Monitoring and analytics
- **Prometheus** (Port 9090) - Metrics collection

### Infrastructure
- **PostgreSQL** (Port 5432) - Primary database (NeonDB)
- **Redis** (Port 6379) - Caching and session storage

## 🔒 Security Features

### Environment Security
- ✅ No hardcoded passwords
- ✅ Environment variable validation
- ✅ Insecure password detection
- ✅ Secret management best practices
- ✅ Secure container permissions

### Container Security
- ✅ Multi-stage Docker builds
- ✅ Minimal base images (Alpine Linux)
- ✅ Non-root container execution
- ✅ Health checks for all services
- ✅ Resource limits and constraints

### Network Security
- ✅ Internal container networking
- ✅ Service isolation
- ✅ Exposed ports minimization
- ✅ TLS/SSL ready configuration

## 📋 Prerequisites

### System Requirements
- Docker 20.10+ installed
- Docker Compose 2.0+ installed
- 8GB+ RAM recommended
- 20GB+ disk space
- Linux/macOS/Windows with WSL2

### Environment Setup
- NeonDB PostgreSQL database (or compatible PostgreSQL)
- Optional: AWS/Azure/GCP credentials for cloud security scanning
- Optional: SMTP server for email notifications
- Optional: Slack/JIRA/Splunk integrations

## 🚀 Quick Start

### 1. Clone and Configure
```bash
git clone <repository>
cd ai-guardian-production-complete
cp .env.example .env
```

### 2. Configure Environment
Edit `.env` file with your secure values:
```bash
# Database (Required)
POSTGRES_URL=your_neon_database_url
POSTGRES_USER=your_db_user
POSTGRES_PASSWORD=your_secure_password

# Security (Required)
SECRET_KEY=your_secure_secret_key
JWT_SECRET_KEY=your_jwt_secret
GRAFANA_ADMIN_PASSWORD=your_grafana_password

# Optional integrations
AWS_ACCESS_KEY_ID=your_aws_key
SLACK_WEBHOOK_URL=your_slack_webhook
SMTP_HOST=your_smtp_server
```

### 3. Deploy
```bash
# Use the secure deployment script
../production-deploy.sh

# Or manually with Docker Compose
docker-compose up --build -d
```

## 🔧 Service Configuration

### Backend Services
Each backend service includes:
- **Dockerfile**: Multi-stage build with Python 3.11-slim
- **requirements.txt**: Service-specific dependencies
- **Gunicorn**: Production WSGI server
- **Health checks**: Container health monitoring
- **Environment variables**: Secure configuration

### Service Dependencies
```
Core Services:
├── Flask (web framework)
├── Flask-CORS (cross-origin requests)
├── Gunicorn (WSGI server)
└── Service-specific libraries

Specialized Services:
├── Advanced ML: numpy, scikit-learn, tensorflow
├── Cloud Security: boto3 (AWS), azure-mgmt, google-cloud
├── Blockchain: web3, solidity-parser
├── Communications: smtplib, email-validator
└── Integrations: requests, jira, slack-sdk
```

## 📊 Monitoring & Observability

### Grafana Dashboards
- System metrics and resource usage
- Service health and performance
- Security alerts and notifications
- Custom business metrics

### Prometheus Metrics
- Container resource utilization
- Application performance metrics
- Database connection pools
- API response times

### Logging
- Centralized logging via Docker
- Structured JSON logs
- Log aggregation ready
- Security event logging

## 🛠️ Management Commands

### Service Management
```bash
# Check service status
docker-compose ps

# View logs for all services
docker-compose logs -f

# View logs for specific service
docker-compose logs -f api-gateway

# Restart a service
docker-compose restart code-scanner

# Scale a service
docker-compose up -d --scale advanced-ml=3

# Access service shell
docker-compose exec api-gateway sh
```

### Database Operations
```bash
# Access PostgreSQL
docker-compose exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB

# Database backup
docker-compose exec postgres pg_dump -U $POSTGRES_USER $POSTGRES_DB > backup.sql

# Database restore
docker-compose exec -T postgres psql -U $POSTGRES_USER -d $POSTGRES_DB < backup.sql
```

### Maintenance
```bash
# Stop all services
docker-compose down

# Remove containers and volumes
docker-compose down -v

# Update and rebuild
docker-compose pull
docker-compose up --build -d

# Clean up unused resources
docker system prune -f
```

## 🔍 Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check container logs
docker-compose logs [service-name]

# Check resource usage
docker stats

# Verify environment variables
docker-compose config
```

#### Database Connection Issues
```bash
# Test database connectivity
docker-compose exec api-gateway python -c "import psycopg2; print('DB OK')"

# Check database logs
docker-compose logs postgres
```

#### Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep :8000

# Modify ports in docker-compose.yml if needed
```

### Health Checks
```bash
# API Gateway health
curl http://localhost:8000/health

# Web Dashboard
curl http://localhost:3000

# Service-specific health checks
curl http://localhost:5001/health  # Code Scanner
curl http://localhost:5002/health  # Adaptive Learning
```

## 🔐 Security Best Practices

### Production Checklist
- [ ] Change all default passwords
- [ ] Use strong, unique secrets
- [ ] Enable HTTPS with SSL certificates
- [ ] Configure firewall rules
- [ ] Set up log monitoring
- [ ] Regular security updates
- [ ] Backup and disaster recovery
- [ ] Access control and authentication

### Secrets Management
```bash
# Generate secure secrets
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Use Docker secrets in production
docker secret create postgres_password /path/to/password/file
```

### Network Security
```bash
# Create isolated network
docker network create ai-guardian-network

# Use internal networking
# Services communicate via container names
```

## 📈 Performance Optimization

### Resource Allocation
```yaml
# Example resource limits in docker-compose.yml
services:
  api-gateway:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
```

### Scaling Guidelines
- **API Gateway**: 2-4 instances behind load balancer
- **Code Scanner**: Scale based on scan volume
- **ML Services**: GPU-enabled instances for better performance
- **Database**: Use connection pooling and read replicas

## 🔄 Updates and Maintenance

### Update Process
1. Backup data and configurations
2. Test updates in staging environment
3. Update container images
4. Rolling deployment with health checks
5. Verify all services are operational

### Backup Strategy
- Daily database backups
- Configuration file versioning
- Container image versioning
- Log archival and retention

## 📞 Support and Documentation

### Additional Resources
- [API Documentation](./docs/API_DOCUMENTATION.md)
- [Development Setup](./docs/DEVELOPMENT_SETUP.md)
- [User Guide](./docs/USER_GUIDE.md)
- [Security Guidelines](./docs/SECURITY_GUIDELINES.md)

### Getting Help
- Check service logs for error details
- Review environment configuration
- Verify network connectivity
- Consult troubleshooting section

---

**AI Guardian Enhanced v4.0.0** - Protecting your digital infrastructure with AI-powered security. 