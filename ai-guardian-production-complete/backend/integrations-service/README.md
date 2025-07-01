# Integrations Service

## Purpose

The Integrations Service is responsible for connecting AI Guardian to external SIEM (Security Information and Event Management) and DevOps platforms. This allows AI Guardian to push security events to systems like Splunk and trigger actions in CI/CD pipelines like Jenkins.

## API Endpoints

### SIEM Integrations (`/api/v1/siem/`)
- `POST /api/v1/siem/splunk/send-alert`
- `POST /api/v1/siem/qradar/send-event`
- `POST /api/v1/siem/arcsight/send-event`
- `POST /api/v1/siem/elastic/send-event`

### DevOps Integrations (`/api/v1/devops/`)
- `POST /api/v1/devops/jenkins/trigger-scan`
- `POST /api/v1/devops/gitlab/create-security-issue`
- `POST /api/v1/devops/azure-devops/create-work-item`
- `POST /api/v1/devops/github/create-security-advisory`

### Webhook Management (`/api/v1/webhooks/`)
- `POST /api/v1/webhooks/register`: Registers a new webhook for AI Guardian to call.
- `POST /api/v1/webhooks/send`: Sends a payload to a registered webhook.
- `GET /api/v1/webhooks/list`: Lists all registered webhooks.

### Universal Connector (`/api/v1/connector/`)
- `POST /api/v1/connector/send-data`: Sends data to a generic, user-configured destination.
- `POST /api/v1/connector/test-connection`: Tests the connection to a configured destination.

### Health Check
- `GET /health`: Returns the health status of the service. 