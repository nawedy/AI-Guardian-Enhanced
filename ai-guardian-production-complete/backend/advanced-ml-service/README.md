# Advanced ML Service

## Purpose

The Advanced ML Service provides access to sophisticated, specialized machine learning models for deep security analysis. This includes transformers, code-bert models, and graph neural networks for tasks beyond the scope of the standard code scanner.

## API Endpoints

### Core ML Analysis (`/api/ml/`)
- `POST /api/ml/predict-vulnerability`: Predicts vulnerabilities using a specific advanced model.
- `POST /api/ml/analyze-code-patterns`: Analyzes code for specific patterns using transformer models.
- `POST /api/ml/graph-analysis`: Performs graph-based code analysis for complex dependency and flow detection.
- `POST /api/ml/ensemble-prediction`: Gets an aggregated prediction from an ensemble of multiple models.

### Model Management (`/api/ml/`)
- `POST /api/ml/train-model`: Initiates training for one of the advanced models.
- `GET /api/ml/model-metrics`: Retrieves performance metrics for the models.
- `POST /api/ml/update-model`: Pushes a newly trained model into production use.

### Health Check
- `GET /health`: Returns the health status of the service. 