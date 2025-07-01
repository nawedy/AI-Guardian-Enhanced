# API Gateway Service

## Purpose

The API Gateway is the single public entry point for the entire AI Guardian platform. It is responsible for:
- Authenticating and authorizing incoming requests.
- Routing requests to the appropriate internal microservice.
- Rate limiting to prevent abuse.
- Handling multi-tenancy logic.
- Serving the frontend web dashboard.

## API Endpoints

The gateway exposes endpoints that map to the various services.

### User Management (`/api/`)
- `POST /api/register`
- `POST /api/login`
- `GET /api/profile`
- `GET /api/users`

### IDE Integration (`/api/ide/`)
- `POST /api/ide/connect`
- `POST /api/ide/scan`

### Single Sign-On (SSO) (`/api/sso/`)
- `GET /api/sso/saml`
- `POST /api/sso/saml/callback`
- `GET /api/sso/oidc`

### Analytics (`/api/analytics/`)
- `GET /api/analytics/vulnerabilities`
- `GET /api/analytics/scans`

### Rate Limiting (`/api/rate-limit/`)
- `GET /api/rate-limit/status`

### Multi-Tenancy (`/api/tenant/`)
- `GET /api/tenant/settings`
- `POST /api/tenant/update`

### Health Check
- `GET /health`: Returns the health status of the gateway.

## Environment Variables

- `DATABASE_URL`: The connection string for the PostgreSQL database.
- `SECRET_KEY`: A secret key used for session management and signing. 