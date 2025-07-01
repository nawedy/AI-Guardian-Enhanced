# Remediation Engine Service

## Purpose

The Remediation Engine service is a simple service that provides a framework for generating and applying remediations for vulnerabilities. In this version, it primarily manages the user data associated with remediation actions.

## API Endpoints

### User Management (`/api/`)
- This service uses the common user model for tracking remediation history.
- `GET /api/user/remediation-history`
- `POST /api/user/apply-remediation`

### Health Check
- `GET /health`: Returns the health status of the service.

## Environment Variables

- `DATABASE_URL`: The connection string for the PostgreSQL database.
- `SECRET_KEY`: A secret key used for session management and signing. 