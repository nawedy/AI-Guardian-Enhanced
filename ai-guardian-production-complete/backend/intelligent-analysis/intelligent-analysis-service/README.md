# Intelligent Analysis Service

## Purpose

The Intelligent Analysis service is a simple service designed for long-running, complex analysis tasks that may be required by other parts of the platform. In this version, it primarily manages the user data associated with these tasks.

## API Endpoints

### User Management (`/api/`)
- This service uses the common user model for tracking analysis jobs.
- `GET /api/user/analysis-jobs`
- `POST /api/user/start-analysis`

### Health Check
- `GET /health`: Returns the health status of the service.

## Environment Variables

- `DATABASE_URL`: The connection string for the PostgreSQL database.
- `SECRET_KEY`: A secret key used for session management and signing. 