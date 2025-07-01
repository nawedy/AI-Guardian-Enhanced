#!/bin/bash

echo "Fixing requirements.txt files..."

find backend -name "requirements.txt" | while read file; do
    echo "Fixing $file"
    # Replace spaces with newlines to separate packages
    sed -i '' 's/ /\n/g' "$file"
    # Remove empty lines and sort
    grep -v '^$' "$file" | sort -u > "${file}.tmp"
    mv "${file}.tmp" "$file"
done

echo "All requirements.txt files fixed!"
