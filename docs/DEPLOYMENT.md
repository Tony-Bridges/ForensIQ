
# ForensIQ Deployment Guide

## Overview

This guide covers deployment of ForensIQ Enterprise Digital Forensics Platform on Replit for both development and production environments.

## Deployment Options

### 1. Replit Development Deployment

#### Quick Development Setup
```bash
# Start development server
python main.py

# Application available at:
# https://your-repl-name.replit.app
```

#### Development Configuration
- **Database**: SQLite (development) / PostgreSQL (production)
- **Debug Mode**: Enabled
- **File Storage**: Instance directory
- **Authentication**: Optional
- **HTTPS**: Provided by Replit

### 2. Replit Production Deployment

#### Production Setup Steps

1. **Configure Environment Variables**
   ```bash
   # Set in Replit Secrets (recommended)
   FLASK_SECRET_KEY=your-production-secret-key
   DATABASE_URL=postgresql://user:pass@host:port/db
   FLASK_ENV=production
   ```

2. **Database Configuration**
   ```python
   # PostgreSQL automatically configured in Replit
   # Production database URL set via environment
   ```

3. **Security Hardening**
   ```python
   # CSRF protection enabled
   # Secure headers configured
   # Input validation active
   # File upload restrictions
   ```

4. **Performance Optimization**
   ```python
   # Database connection pooling
   # Static file caching
   # Gzip compression
   # Response optimization
   ```

## Replit-Specific Deployment

### Using Replit Deployments

#### 1. Static Deployment (Not Recommended)
ForensIQ is a dynamic Flask application and requires server-side processing.

#### 2. Autoscale Deployment (Recommended)

1. **Open Deployments Tab**
   - Click "Deploy" button in Replit header
   - Select "Autoscale" deployment type

2. **Configure Deployment**
   ```
   Machine Configuration: 1vCPU, 2GB RAM
   Max Machines: 3
   Primary Domain: your-forensiq-domain.com
   Build Command: (leave blank)
   Run Command: python main.py
   ```

3. **Deploy Application**
   - Click "Deploy" button
   - Wait for deployment to complete
   - Application available at your custom domain

#### 3. Reserved VM Deployment (Enterprise)

For high-performance requirements:

1. **Configure Reserved VM**
   ```
   Machine Type: 2vCPU, 4GB RAM (or higher)
   Storage: 50GB SSD
   Network: Private networking
   ```

2. **Production Settings**
   ```python
   # Gunicorn for production WSGI
   # Multiple worker processes
   # Load balancing
   # Health checks
   ```

## Configuration Management

### Environment Variables

#### Required Variables
```bash
# Core application settings
FLASK_SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:pass@host:port/db
FLASK_ENV=production

# Optional API keys for enhanced features
VIRUSTOTAL_API_KEY=your-virustotal-key
ETHERSCAN_API_KEY=your-etherscan-key
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
```

#### Setting Environment Variables in Replit
1. **Using Replit Secrets**
   - Open Secrets tab in Replit
   - Add key-value pairs
   - Automatically loaded by application

2. **Using .env File** (Not Recommended)
   ```bash
   # Create .env file (not recommended for production)
   echo "FLASK_SECRET_KEY=your-secret" > .env
   ```

### Database Configuration

#### PostgreSQL Setup
```python
# Automatically configured in Replit
# Connection string via DATABASE_URL
# Connection pooling enabled
# Automatic failover support
```

#### Database Migrations
```python
# Tables created automatically on first run
# No manual migration required
# Schema updates handled automatically
```

### File Storage Configuration

#### Evidence Storage
```python
# Instance directory for evidence files
# Automatic cleanup of temporary files
# Secure file handling
# File size limits enforced
```

#### Backup Strategy
```python
# Database backups: Automatic
# File backups: Manual export
# Configuration backups: Code repository
```

## Security Configuration

### HTTPS Configuration
```python
# Automatically handled by Replit
# TLS 1.2+ encryption
# Secure headers configured
# HSTS enabled
```

### Authentication Setup
```python
# Optional authentication system
# Role-based access control
# Session management
# CSRF protection
```

### Input Validation
```python
# File upload validation
# SQL injection prevention
# XSS protection
# Input sanitization
```

## Performance Optimization

### Application Performance
```python
# Database connection pooling
# Query optimization
# Caching strategies
# Lazy loading
```

### Static File Optimization
```python
# CSS/JS minification
# Image optimization
# Browser caching
# CDN integration (optional)
```

### Resource Management
```python
# Memory usage optimization
# CPU usage monitoring
# Disk space management
# Network bandwidth optimization
```

## Monitoring and Logging

### Application Monitoring
```python
# Health check endpoints
# Performance metrics
# Error tracking
# Uptime monitoring
```

### Logging Configuration
```python
# Structured logging
# Log levels: DEBUG, INFO, WARNING, ERROR
# Log rotation
# Log analysis
```

### Alerting Setup
```python
# System alerts
# Error notifications
# Performance alerts
# Security alerts
```

## Backup and Recovery

### Backup Strategy
```python
# Database backups: Daily
# File backups: Weekly
# Configuration backups: Version control
# Evidence backups: Secure storage
```

### Recovery Procedures
```python
# Database recovery
# File recovery
# Configuration recovery
# Disaster recovery
```

## Maintenance Procedures

### Regular Maintenance
```python
# Database maintenance
# Log cleanup
# Performance optimization
# Security updates
```

### Update Management
```python
# Dependency updates
# Security patches
# Feature updates
# Configuration updates
```

## Troubleshooting Deployment Issues

### Common Issues

#### Database Connection Problems
```bash
# Check DATABASE_URL environment variable
# Verify database service status
# Check connection limits
# Review database logs
```

#### Application Start Issues
```bash
# Check Python dependencies
# Verify environment variables
# Review application logs
# Check file permissions
```

#### Performance Issues
```bash
# Monitor resource usage
# Check database performance
# Analyze slow queries
# Review application metrics
```

#### Security Issues
```bash
# Verify HTTPS configuration
# Check authentication setup
# Review access controls
# Validate input sanitization
```

### Debugging Tools
```python
# Flask debug mode
# Database query profiling
# Application logging
# Performance monitoring
```

## Deployment Checklist

### Pre-Deployment
- [ ] Code tested and validated
- [ ] Environment variables configured
- [ ] Database setup complete
- [ ] Security settings verified
- [ ] Performance optimized
- [ ] Backup strategy implemented

### Deployment
- [ ] Application deployed successfully
- [ ] Database connection verified
- [ ] All features functional
- [ ] Security measures active
- [ ] Performance acceptable
- [ ] Monitoring configured

### Post-Deployment
- [ ] Smoke tests passed
- [ ] User acceptance testing
- [ ] Performance monitoring
- [ ] Security monitoring
- [ ] Backup verification
- [ ] Documentation updated

## Scaling Considerations

### Horizontal Scaling
```python
# Multiple application instances
# Load balancing
# Session management
# Database scaling
```

### Vertical Scaling
```python
# Increase CPU/memory
# Optimize database
# Improve caching
# Code optimization
```

### Database Scaling
```python
# Connection pooling
# Query optimization
# Indexing strategy
# Partitioning
```

## Security Best Practices

### Application Security
```python
# Input validation
# Output encoding
# Authentication
# Authorization
```

### Infrastructure Security
```python
# Network security
# Access controls
# Encryption
# Monitoring
```

### Data Security
```python
# Data encryption
# Access controls
# Audit logging
# Backup security
```

## Support and Maintenance

### Production Support
- **Monitoring**: 24/7 system monitoring
- **Incident Response**: Rapid incident response
- **Maintenance Windows**: Scheduled maintenance
- **Support Channels**: Multiple support options

### Continuous Improvement
- **Performance Monitoring**: Ongoing optimization
- **Security Updates**: Regular security patches
- **Feature Updates**: New feature deployment
- **User Feedback**: Continuous improvement

---

**Deployment Complete**: ForensIQ is now ready for production forensic investigations!
