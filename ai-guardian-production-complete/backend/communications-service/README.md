# Communications Service

## Purpose

The Communications Service handles all outbound notifications and integrations with third-party communication and ticketing platforms. It acts as a centralized hub for sending alerts and creating issues in external systems.

## API Endpoints

### Ticketing Systems (`/api/v1/ticketing/`)
- `POST /api/v1/ticketing/jira/create-issue`
- `POST /api/v1/ticketing/servicenow/create-incident`
- `POST /api/v1/ticketing/zendesk/create-ticket`

### Messaging Platforms (`/api/v1/messaging/`)
- `POST /api/v1/messaging/slack/send-alert`
- `POST /api/v1/messaging/teams/send-alert`
- `POST /api/v1/messaging/discord/send-alert`

### Email (`/api/v1/email/`)
- `POST /api/v1/email/send-alert`
- `POST /api/v1/email/send-report`

### Notification Management (`/api/v1/notifications/`)
- `POST /api/v1/notifications/create-rule`
- `POST /api/v1/notifications/send-multi-channel`
- `POST /api/v1/notifications/escalate`

### Integration Management (`/api/v1/integrations/`)
- `GET /api/v1/integrations/status`
- `POST /api/v1/integrations/configure`
- `POST /api/v1/integrations/test`

### Health Check
- `GET /health`: Returns the health status of the service. 