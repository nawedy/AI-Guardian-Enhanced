#!/bin/bash

# AI Guardian Enhanced v4.0.0 - Log Viewer Script

echo "📋 AI Guardian Enhanced v4.0.0 - Log Viewer"
echo "=========================================="

# Function to show service logs
show_logs() {
    local service=$1
    echo ""
    echo "📄 $service Logs (last 50 lines):"
    echo "-----------------------------------"
    
    if [ -f "logs/${service}.log" ]; then
        tail -50 "logs/${service}.log"
    elif docker ps -q -f name=$service > /dev/null 2>&1; then
        docker logs --tail 50 $(docker ps -q -f name=$service)
    else
        echo "❌ No logs found for $service"
    fi
}

# Check if specific service requested
if [ $# -eq 1 ]; then
    show_logs $1
    exit 0
fi

# Show all service logs
echo "🔍 Available log sources:"
echo "1. API Gateway"
echo "2. Code Scanner"
echo "3. Advanced ML"
echo "4. Blockchain Security"
echo "5. IoT/Mobile Security"
echo "6. Cloud Security"
echo "7. Integrations"
echo "8. Communications"
echo "9. All Services"
echo "0. Exit"

read -p "Select log source (0-9): " choice

case $choice in
    1) show_logs "api-gateway" ;;
    2) show_logs "code-scanner" ;;
    3) show_logs "advanced-ml" ;;
    4) show_logs "blockchain-security" ;;
    5) show_logs "iot-mobile-security" ;;
    6) show_logs "cloud-security" ;;
    7) show_logs "integrations" ;;
    8) show_logs "communications" ;;
    9) 
        for service in api-gateway code-scanner advanced-ml blockchain-security iot-mobile-security cloud-security integrations communications; do
            show_logs $service
        done
        ;;
    0) echo "👋 Goodbye!" ;;
    *) echo "❌ Invalid choice" ;;
esac

