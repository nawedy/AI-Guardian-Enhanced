# Cloud Security Service

## Purpose

The Cloud Security Service provides Cloud Security Posture Management (CSPM) capabilities. It can scan cloud environments (AWS, Azure, GCP) for misconfigurations, compliance violations, and security vulnerabilities.

## API Endpoints

### Scanning & Analysis (`/api/v1/cloud/`)
- `POST /api/v1/cloud/scan`: Initiates a scan of a configured cloud environment.
- `POST /api/v1/cloud/compliance`: Assesses the scan results against compliance frameworks (e.g., CIS, NIST).
- `POST /api/v1/cloud/posture`: Provides a high-level analysis of the overall security posture.
- `POST /api/v1/cloud/remediation`: Suggests remediation steps for identified issues.
- `POST /api/v1/cloud/benchmark`: Runs a security benchmark (e.g., CIS) against an environment.
- `POST /api/v1/cloud/inventory`: Gathers a complete inventory of cloud assets.
- `POST /api/v1/cloud/attack-surface`: Analyzes the potential attack surface of the cloud environment.

### Monitoring & Intelligence (`/api/v1/cloud/`)
- `POST /api/v1/cloud/monitor/start`: Starts continuous monitoring of a cloud environment.
- `GET /api/v1/cloud/monitor/status`: Gets the status of the monitoring agent.
- `POST /api/v1/cloud/threat-intelligence`: Retrieves threat intelligence specific to a cloud provider.
- `POST /api/v1/cloud/drift-detection`: Detects configuration drift from a known-good baseline.

### Health Check
- `GET /health`: Returns the health status of the service. 