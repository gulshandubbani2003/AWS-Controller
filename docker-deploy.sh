#!/bin/bash

# AWS Dashboard Docker Deployment Script
# Usage: ./docker-deploy.sh [dev|prod|stop|logs|clean]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install it and try again."
        exit 1
    fi
}

# Function to deploy development environment
deploy_dev() {
    print_status "Deploying development environment..."
    docker-compose up --build -d
    print_success "Development environment deployed successfully!"
    print_status "Frontend: http://localhost:3000"
    print_status "Backend: http://localhost:5001"
}

# Function to deploy production environment
deploy_prod() {
    print_status "Deploying production environment..."
    docker-compose -f docker-compose.prod.yml up --build -d
    print_success "Production environment deployed successfully!"
    print_status "Frontend: http://localhost:3000"
    print_status "Backend: http://localhost:5001"
    print_status "Nginx: http://localhost:80"
}

# Function to stop all services
stop_services() {
    print_status "Stopping all services..."
    docker-compose down
    docker-compose -f docker-compose.prod.yml down 2>/dev/null || true
    print_success "All services stopped!"
}

# Function to show logs
show_logs() {
    print_status "Showing logs (Press Ctrl+C to exit)..."
    docker-compose logs -f
}

# Function to clean up Docker resources
cleanup() {
    print_warning "This will remove all containers, images, and volumes. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_status "Cleaning up Docker resources..."
        docker-compose down -v
        docker-compose -f docker-compose.prod.yml down -v 2>/dev/null || true
        docker system prune -af
        print_success "Cleanup completed!"
    else
        print_status "Cleanup cancelled."
    fi
}

# Function to show status
show_status() {
    print_status "Container Status:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    print_status "Resource Usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
}

# Function to show help
show_help() {
    echo "AWS Dashboard Docker Deployment Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  dev     Deploy development environment"
    echo "  prod    Deploy production environment"
    echo "  stop    Stop all services"
    echo "  logs    Show logs from all services"
    echo "  status  Show container status and resource usage"
    echo "  clean   Clean up all Docker resources"
    echo "  help    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 dev      # Deploy development environment"
    echo "  $0 prod     # Deploy production environment"
    echo "  $0 stop     # Stop all services"
    echo "  $0 logs     # Show real-time logs"
}

# Main script logic
main() {
    # Check prerequisites
    check_docker
    check_docker_compose
    
    case "${1:-help}" in
        "dev")
            deploy_dev
            ;;
        "prod")
            deploy_prod
            ;;
        "stop")
            stop_services
            ;;
        "logs")
            show_logs
            ;;
        "status")
            show_status
            ;;
        "clean")
            cleanup
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@" 