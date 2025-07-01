#!/bin/bash

# Update all requirements.txt files with missing dependencies

# Common dependencies needed across services
COMMON_DEPS="requests==2.31.0
numpy==1.24.3
boto3==1.34.0
botocore==1.34.0
python-dateutil==2.8.2
urllib3==2.0.7
certifi==2023.11.17
charset-normalizer==3.3.2
idna==3.6
six==1.16.0
jmespath==1.0.1
s3transfer==0.10.0"

echo "Updating requirements.txt files..."

find backend -name "requirements.txt" | while read file; do
    echo "Updating $file"
    # Add common dependencies if not already present
    echo "$COMMON_DEPS" >> "$file"
    # Remove duplicates and sort
    sort -u "$file" -o "$file"
done

echo "All requirements.txt files updated!"
