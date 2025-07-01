# Code Scanner Service

## Purpose

The Code Scanner service is the core static analysis engine of the AI Guardian platform. It is responsible for scanning source code in multiple languages to identify security vulnerabilities, compliance issues, and quality problems.

## API Endpoints

### User Management (`/api/`)
- This service shares the common user model but exposes its own endpoints for scanner-specific user interactions.
- `GET /api/user/scan-history`

### Scanning (`/api/`)
- `POST /api/scan`: Initiates a new code scan.
- `GET /api/scan/result/<scan_id>`: Retrieves the results of a completed scan.
- `GET /api/scan/status/<scan_id>`: Checks the status of an ongoing scan.

### Real-time (`/api/`)
- `POST /api/realtime/subscribe`: Subscribes to real-time scanning events.

### Compliance (`/api/compliance/`)
- `POST /api/compliance/scan`: Runs a scan specifically for compliance frameworks (e.g., PCI, HIPAA).
- `GET /api/compliance/report/<scan_id>`: Generates a compliance report.

### AI Features (`/api/ai/`)
- `POST /api/ai/predict-vulnerability`: Uses an ML model to predict if a code snippet is vulnerable.
- `POST /api/ai/get-remediation`: Suggests an AI-generated fix for a vulnerability.

### Enterprise Features (`/api/enterprise/`)
- `POST /api/enterprise/risk-quantification`: Calculates a quantitative risk score for a project.

### Health Check
- `GET /health`: Returns the health status of the service.

## Environment Variables

- `DATABASE_URL`: The connection string for the PostgreSQL database.
- `SECRET_KEY`: A secret key used for session management and signing. 