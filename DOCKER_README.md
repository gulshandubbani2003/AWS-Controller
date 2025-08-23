# 🐳 Docker Deployment Guide

This guide explains how to deploy your AWS Management Dashboard using Docker containers.

## 📋 Prerequisites

- Docker installed on your system
- Docker Compose installed
- At least 2GB of available RAM
- Ports 3000 and 5001 available

## 🚀 Quick Start

### 1. Build and Run (Development)

```bash
# Build and start both services
docker-compose up --build

# Run in background
docker-compose up -d --build

# View logs
docker-compose logs -f
```

### 2. Production Deployment

```bash
# Build and start production services
docker-compose -f docker-compose.prod.yml up --build -d

# View production logs
docker-compose -f docker-compose.prod.yml logs -f
```

## 🏗️ Manual Docker Commands

### Backend Only

```bash
# Build backend image
docker build -f Dockerfile.backend -t aws-dashboard-backend .

# Run backend container
docker run -d \
  --name aws-dashboard-backend \
  -p 5001:5001 \
  -e FLASK_ENV=production \
  aws-dashboard-backend
```

### Frontend Only

```bash
# Build frontend image
docker build -f Dockerfile.frontend -t aws-dashboard-frontend .

# Run frontend container
docker run -d \
  --name aws-dashboard-frontend \
  -p 3000:3000 \
  -e NODE_ENV=production \
  aws-dashboard-frontend
```

## 🔧 Docker Compose Commands

```bash
# Start services
docker-compose up

# Start in background
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# View logs
docker-compose logs

# View specific service logs
docker-compose logs backend
docker-compose logs frontend

# Rebuild and start
docker-compose up --build

# Remove containers and volumes
docker-compose down -v

# Scale services (if needed)
docker-compose up --scale backend=2
```

## 📊 Service Information

### Backend (Flask)
- **Port**: 5001
- **Health Check**: `/api/health`
- **Base URL**: `http://localhost:5001`
- **API Endpoints**: `/api/*`

### Frontend (React)
- **Port**: 3000
- **Health Check**: `/`
- **Base URL**: `http://localhost:3000`
- **Build Output**: `dist/` folder

### Nginx (Production)
- **Port**: 80 (HTTP), 443 (HTTPS)
- **Health Check**: `/health`
- **Reverse Proxy**: Routes traffic to frontend/backend

## 🔍 Monitoring & Debugging

### Check Container Status

```bash
# View running containers
docker ps

# View all containers (including stopped)
docker ps -a

# View container resources
docker stats
```

### View Logs

```bash
# Real-time logs
docker-compose logs -f

# Specific service logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Last 100 lines
docker-compose logs --tail=100
```

### Health Checks

```bash
# Check backend health
curl http://localhost:5001/api/health

# Check frontend health
curl http://localhost:3000

# Check nginx health (production)
curl http://localhost/health
```

## 🛠️ Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Find process using port
   lsof -i :5001
   lsof -i :3000
   
   # Kill process
   kill -9 <PID>
   ```

2. **Container Won't Start**
   ```bash
   # Check container logs
   docker logs <container_name>
   
   # Check container status
   docker inspect <container_name>
   ```

3. **Build Failures**
   ```bash
   # Clean Docker cache
   docker system prune -a
   
   # Rebuild without cache
   docker-compose build --no-cache
   ```

4. **Permission Issues**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER .
   ```

### Performance Issues

```bash
# Monitor resource usage
docker stats

# Check container limits
docker inspect <container_name> | grep -i memory
docker inspect <container_name> | grep -i cpu
```

## 🔒 Security Considerations

### Production Security

1. **Use production compose file**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

2. **Enable resource limits**
   - Memory and CPU limits are set in production compose
   - Prevents resource exhaustion attacks

3. **Use non-root users**
   - Both containers run as non-root users
   - Reduces security risks

4. **Network isolation**
   - Services use isolated Docker network
   - Only necessary ports are exposed

### Environment Variables

```bash
# Set production environment
export FLASK_ENV=production
export NODE_ENV=production

# Or use .env file
echo "FLASK_ENV=production" > .env
echo "NODE_ENV=production" >> .env
```

## 📈 Scaling

### Horizontal Scaling

```bash
# Scale backend to 3 instances
docker-compose up --scale backend=3

# Scale frontend to 2 instances
docker-compose up --scale frontend=2
```

### Load Balancing

The Nginx configuration automatically load balances between multiple instances.

## 🚢 Deployment Options

### 1. Local Development
```bash
docker-compose up --build
```

### 2. Production Server
```bash
docker-compose -f docker-compose.prod.yml up -d --build
```

### 3. Cloud Deployment
- **AWS ECS**: Use the Dockerfiles with ECS task definitions
- **Google Cloud Run**: Deploy each service separately
- **Azure Container Instances**: Use the Dockerfiles directly
- **Kubernetes**: Create deployments from the Dockerfiles

### 4. CI/CD Pipeline

```yaml
# Example GitHub Actions
- name: Build and push Docker images
  run: |
    docker build -f Dockerfile.backend -t $REGISTRY/backend:$TAG .
    docker build -f Dockerfile.frontend -t $REGISTRY/frontend:$TAG .
    docker push $REGISTRY/backend:$TAG
    docker push $REGISTRY/frontend:$TAG
```

## 📝 Environment Variables

### Backend Variables
- `FLASK_ENV`: Environment (development/production)
- `FLASK_DEBUG`: Debug mode (0/1)
- `PYTHONUNBUFFERED`: Python output buffering

### Frontend Variables
- `NODE_ENV`: Environment (development/production)
- `REACT_APP_API_URL`: Backend API URL

## 🔄 Updates & Maintenance

### Update Application

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose up --build -d
```

### Update Dependencies

```bash
# Update Python dependencies
docker-compose exec backend pip install -r requirements.txt

# Update Node dependencies
docker-compose exec frontend npm update
```

### Backup & Restore

```bash
# Backup data
docker run --rm -v aws-dashboard_data:/data -v $(pwd):/backup alpine tar czf /backup/data-backup.tar.gz -C /data .

# Restore data
docker run --rm -v aws-dashboard_data:/data -v $(pwd):/backup alpine tar xzf /backup/data-backup.tar.gz -C /data
```

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [Flask Production Deployment](https://flask.palletsprojects.com/en/2.3.x/deploying/)
- [React Production Build](https://create-react-app.dev/docs/production-build/)

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review container logs: `docker-compose logs`
3. Verify container status: `docker ps`
4. Check health endpoints
5. Ensure ports are available
6. Verify Docker and Docker Compose versions

---

**Happy Containerizing! 🐳✨** 