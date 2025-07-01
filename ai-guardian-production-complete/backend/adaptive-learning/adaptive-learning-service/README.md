# Adaptive Learning Service

## Purpose

The Adaptive Learning service is responsible for managing and orchestrating the machine learning models used by the AI Guardian platform. It handles model training, evaluation, and deployment, ensuring the platform's detection capabilities improve over time.

## API Endpoints

### User Management (`/api/`)
- This service uses the common user model for tracking contributions to model training.
- `GET /api/user/contributions`

### Learning (`/api/`)
- `POST /api/learn/from-scan`: Submits new data from a code scan to the learning pipeline.
- `POST /api/model/retrain`: Triggers a retraining job for a specific ML model.
- `GET /api/model/status/<model_id>`: Checks the status of a training job.
- `GET /api/model/performance/<model_id>`: Retrieves performance metrics for a trained model.

### Health Check
- `GET /health`: Returns the health status of the service.

## Environment Variables

- `DATABASE_URL`: The connection string for the PostgreSQL database.
- `SECRET_KEY`: A secret key used for session management and signing. 