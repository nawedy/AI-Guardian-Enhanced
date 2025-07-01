#!/bin/bash

echo "Cleaning duplicate packages from requirements.txt files..."

find backend -name "requirements.txt" | while read file; do
    echo "Cleaning $file"
    # Create a temporary file to store cleaned requirements
    temp_file="${file}.clean"
    
    # Extract package names and their versions, keep only the latest version
    python3 -c "
import sys
from collections import defaultdict

packages = defaultdict(list)
with open('$file', 'r') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
            if '==' in line:
                name, version = line.split('==', 1)
                packages[name].append(version)
            else:
                packages[line].append('')

# Write unique packages with latest versions
with open('$temp_file', 'w') as f:
    for name, versions in sorted(packages.items()):
        if versions[0]:  # Has version
            # Take the last (latest) version
            f.write(f'{name}=={versions[-1]}\n')
        else:
            f.write(f'{name}\n')
"
    
    # Replace original file with cleaned version
    mv "$temp_file" "$file"
done

echo "All requirements.txt files cleaned!"
