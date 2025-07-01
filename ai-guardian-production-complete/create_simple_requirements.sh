#!/bin/bash

echo "Creating simplified requirements.txt files..."

# Create a base requirements file with compatible versions
BASE_REQUIREMENTS="Flask==3.1.1
Flask-Cors==4.0.1
gunicorn==23.0.0
requests==2.32.3"

# Service-specific requirements
CLOUD_REQUIREMENTS="$BASE_REQUIREMENTS
boto3==1.35.0"

ML_REQUIREMENTS="$BASE_REQUIREMENTS
numpy==1.24.3
scikit-learn==1.3.0"

# Update all services with appropriate requirements
find backend -name "requirements.txt" | while read file; do
    service_name=$(basename $(dirname "$file"))
    echo "Updating $file for service: $service_name"
    
    case "$service_name" in
        *cloud-security*)
            echo "$CLOUD_REQUIREMENTS" > "$file"
            ;;
        *advanced-ml*)
            echo "$ML_REQUIREMENTS" > "$file"
            ;;
        *)
            echo "$BASE_REQUIREMENTS" > "$file"
            ;;
    esac
done

echo "All requirements.txt files updated with compatible versions!"
