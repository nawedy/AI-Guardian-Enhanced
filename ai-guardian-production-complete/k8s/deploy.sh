#!/bin/bash

# AI Guardian Kubernetes Deployment Script
# This script deploys the complete AI Guardian system to a Kubernetes cluster

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="ai-guardian"
KUBECTL_TIMEOUT="300s"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if kubectl is available
check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we can connect to the cluster
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    print_success "kubectl is available and connected to cluster"
}

# Function to check if required tools are available
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check kubectl
    check_kubectl
    
    # Check if helm is available (optional)
    if command -v helm &> /dev/null; then
        print_success "Helm is available"
    else
        print_warning "Helm is not available - some features may not work"
    fi
}

# Function to create namespace
create_namespace() {
    print_status "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace $NAMESPACE &> /dev/null; then
        print_warning "Namespace $NAMESPACE already exists"
    else
        kubectl apply -f k8s/namespace.yaml
        print_success "Namespace $NAMESPACE created"
    fi
}

# Function to apply configuration
apply_config() {
    print_status "Applying configuration..."
    
    # Apply ConfigMap
    kubectl apply -f k8s/configmap.yaml
    print_success "ConfigMap applied"
    
    # Apply Secrets
    kubectl apply -f k8s/secret.yaml
    print_success "Secrets applied"
}

# Function to deploy database
deploy_database() {
    print_status "Deploying PostgreSQL database..."
    
    kubectl apply -f k8s/postgres.yaml
    
    # Wait for PostgreSQL to be ready
    print_status "Waiting for PostgreSQL to be ready..."
    kubectl wait --for=condition=ready pod -l app=postgres -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    
    print_success "PostgreSQL deployed and ready"
}

# Function to deploy Redis
deploy_redis() {
    print_status "Deploying Redis cache..."
    
    kubectl apply -f k8s/redis.yaml
    
    # Wait for Redis to be ready
    print_status "Waiting for Redis to be ready..."
    kubectl wait --for=condition=ready pod -l app=redis -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    
    print_success "Redis deployed and ready"
}

# Function to deploy backend services
deploy_backend_services() {
    print_status "Deploying backend services..."
    
    # Deploy Scanner Service
    print_status "Deploying Scanner Service..."
    kubectl apply -f k8s/scanner-service.yaml
    
    # Deploy Learning Service
    print_status "Deploying Adaptive Learning Service..."
    kubectl apply -f k8s/learning-service.yaml
    
    # Deploy API Gateway
    print_status "Deploying API Gateway..."
    kubectl apply -f k8s/api-gateway.yaml
    
    # Wait for services to be ready
    print_status "Waiting for backend services to be ready..."
    kubectl wait --for=condition=ready pod -l app=scanner-service -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    kubectl wait --for=condition=ready pod -l app=learning-service -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    kubectl wait --for=condition=ready pod -l app=api-gateway -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    
    print_success "Backend services deployed and ready"
}

# Function to deploy frontend
deploy_frontend() {
    print_status "Deploying web dashboard..."
    
    kubectl apply -f k8s/web-dashboard.yaml
    
    # Wait for frontend to be ready
    print_status "Waiting for web dashboard to be ready..."
    kubectl wait --for=condition=ready pod -l app=web-dashboard -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    
    print_success "Web dashboard deployed and ready"
}

# Function to deploy monitoring
deploy_monitoring() {
    print_status "Deploying monitoring stack..."
    
    kubectl apply -f k8s/monitoring.yaml
    
    # Wait for monitoring to be ready
    print_status "Waiting for monitoring stack to be ready..."
    kubectl wait --for=condition=ready pod -l app=prometheus -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    kubectl wait --for=condition=ready pod -l app=grafana -n $NAMESPACE --timeout=$KUBECTL_TIMEOUT
    
    print_success "Monitoring stack deployed and ready"
}

# Function to verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Check all pods are running
    print_status "Checking pod status..."
    kubectl get pods -n $NAMESPACE
    
    # Check services
    print_status "Checking service status..."
    kubectl get services -n $NAMESPACE
    
    # Check ingress
    print_status "Checking ingress status..."
    kubectl get ingress -n $NAMESPACE
    
    # Get external IPs
    print_status "Getting external access information..."
    
    API_GATEWAY_IP=$(kubectl get service api-gateway-service -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "Pending")
    
    echo ""
    print_success "=== AI Guardian Deployment Complete ==="
    echo ""
    echo "📊 Dashboard URL: https://dashboard.ai-guardian.com"
    echo "🔌 API Gateway: https://api.ai-guardian.com"
    echo "📈 Grafana: http://$API_GATEWAY_IP:3000 (admin/admin123)"
    echo "🔍 Prometheus: http://$API_GATEWAY_IP:9090"
    echo ""
    echo "🔧 To access services locally:"
    echo "   kubectl port-forward -n $NAMESPACE service/api-gateway-service 8080:80"
    echo "   kubectl port-forward -n $NAMESPACE service/web-dashboard-service 8081:80"
    echo "   kubectl port-forward -n $NAMESPACE service/grafana-service 3000:3000"
    echo ""
    echo "📋 To check logs:"
    echo "   kubectl logs -f deployment/scanner-service-deployment -n $NAMESPACE"
    echo "   kubectl logs -f deployment/api-gateway-deployment -n $NAMESPACE"
    echo ""
}

# Function to show help
show_help() {
    echo "AI Guardian Kubernetes Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --check-only        Only check dependencies and cluster connectivity"
    echo "  --skip-monitoring   Skip monitoring stack deployment"
    echo "  --namespace NAME    Use custom namespace (default: ai-guardian)"
    echo ""
    echo "Examples:"
    echo "  $0                  Deploy complete AI Guardian system"
    echo "  $0 --check-only     Check if cluster is ready for deployment"
    echo "  $0 --skip-monitoring Deploy without monitoring stack"
    echo ""
}

# Function to cleanup on error
cleanup_on_error() {
    print_error "Deployment failed. Cleaning up..."
    kubectl delete namespace $NAMESPACE --ignore-not-found=true
    exit 1
}

# Main deployment function
main() {
    local skip_monitoring=false
    local check_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --check-only)
                check_only=true
                shift
                ;;
            --skip-monitoring)
                skip_monitoring=true
                shift
                ;;
            --namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Set up error handling
    trap cleanup_on_error ERR
    
    print_status "Starting AI Guardian Kubernetes deployment..."
    print_status "Target namespace: $NAMESPACE"
    
    # Check dependencies
    check_dependencies
    
    if [ "$check_only" = true ]; then
        print_success "Cluster is ready for AI Guardian deployment"
        exit 0
    fi
    
    # Start deployment
    create_namespace
    apply_config
    
    # Deploy infrastructure
    deploy_database
    deploy_redis
    
    # Deploy application services
    deploy_backend_services
    deploy_frontend
    
    # Deploy monitoring (optional)
    if [ "$skip_monitoring" = false ]; then
        deploy_monitoring
    else
        print_warning "Skipping monitoring stack deployment"
    fi
    
    # Verify deployment
    verify_deployment
    
    print_success "AI Guardian deployment completed successfully!"
}

# Run main function with all arguments
main "$@"

