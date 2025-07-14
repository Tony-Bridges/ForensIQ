
# ForensIQ Setup Guide

## Initial Configuration

This guide walks you through the initial setup and configuration of ForensIQ Enterprise Digital Forensics Platform.

## Quick Setup (5 Minutes)

### 1. Start the Application
```bash
python main.py
```

### 2. Access Web Interface
- Open the Replit web preview
- URL: `https://your-repl-name.replit.app`
- The application runs on port 5000

### 3. Verify Core Functions
- **Dashboard**: Should load with system metrics
- **Evidence Upload**: Test with a small file
- **Analysis Tools**: Check each forensic module
- **Reporting**: Generate a sample report

## Detailed Setup Process

### System Configuration

#### 1. Database Setup
```python
# Database is automatically configured
# Tables created on first run
# No manual setup required
```

#### 2. Storage Configuration
```python
# File storage: Instance directory
# Max file size: 16MB
# Supported formats: All file types
```

#### 3. Security Settings
```python
# CSRF protection: Enabled
# File validation: Active
# Secure headers: Configured
```

### Feature Configuration

#### 1. AI Analysis Settings
Navigate to **Settings** > **AI Configuration**:
- **Anomaly Detection**: Enabled
- **Malware Classification**: Behavioral analysis
- **Entity Extraction**: NLP processing
- **Media Verification**: Deepfake detection

#### 2. Cloud Forensics Setup
Configure cloud provider access:
- **AWS**: Access key and secret (optional)
- **Azure**: Subscription ID and credentials (optional)
- **GCP**: Service account JSON (optional)

#### 3. Blockchain Analysis
Set up blockchain endpoints:
- **Bitcoin**: Default RPC endpoint
- **Ethereum**: Web3 provider URL
- **Smart Contracts**: Etherscan API key (optional)

#### 4. Device Acquisition
Configure device support:
- **Android**: ADB tools enabled
- **iOS**: libimobiledevice support
- **IoT Devices**: Protocol handlers

### Advanced Configuration

#### 1. Threat Intelligence
Set up threat intelligence feeds:
- **VirusTotal**: API key for malware detection
- **MISP**: Threat sharing platform
- **YARA Rules**: Custom rule repositories

#### 2. Network Analysis
Configure network capabilities:
- **PCAP Analysis**: Wireshark integration
- **DNS Monitoring**: Passive DNS lookups
- **Traffic Analysis**: Deep packet inspection

#### 3. Memory Analysis
Set up memory forensics:
- **Volatility**: Framework integration
- **Memory Dumps**: Automated acquisition
- **Process Analysis**: Live system monitoring

### User Management

#### 1. Access Control
Configure user access:
- **Authentication**: Optional for development
- **Role-Based Access**: Admin, Analyst, Viewer
- **Session Management**: Secure session handling

#### 2. Audit Logging
Enable audit capabilities:
- **Action Logging**: All user actions
- **Chain of Custody**: Evidence handling
- **Report Generation**: Automated documentation

### Integration Setup

#### 1. External APIs
Configure third-party integrations:
- **Threat Intelligence**: Multiple providers
- **Cloud Services**: Multi-cloud support
- **Blockchain**: Various networks

#### 2. Export Capabilities
Set up data export:
- **Report Formats**: PDF, JSON, XML
- **Evidence Export**: Forensic image formats
- **Timeline Export**: Multiple formats

## Configuration Files

### Main Configuration
```python
# app.py contains primary configuration
# Environment variables for secrets
# Database URL automatically configured
```

### Security Configuration
```python
# CSRF protection enabled
# Secure file handling
# Input validation active
```

### Feature Toggles
```python
# All features enabled by default
# Configurable through settings interface
# Runtime configuration changes
```

## Environment Variables

### Required Variables
```bash
# Automatically configured in Replit
FLASK_SECRET_KEY=auto-generated
DATABASE_URL=auto-configured
```

### Optional Variables
```bash
# API Keys for enhanced features
VIRUSTOTAL_API_KEY=your-key-here
ETHERSCAN_API_KEY=your-key-here
AWS_ACCESS_KEY_ID=your-key-here
AWS_SECRET_ACCESS_KEY=your-secret-here
```

## Testing Setup

### 1. Functional Testing
```bash
# Test file upload
# Verify analysis modules
# Check report generation
```

### 2. Performance Testing
```bash
# Monitor resource usage
# Test file size limits
# Verify response times
```

### 3. Security Testing
```bash
# Validate input sanitization
# Test file validation
# Check access controls
```

## Maintenance Setup

### 1. Backup Configuration
```python
# Database backups: Automatic
# Evidence storage: Persistent
# Configuration backup: Manual
```

### 2. Monitoring Setup
```python
# System health monitoring
# Performance metrics
# Error tracking
```

### 3. Update Management
```python
# Dependency updates: Automatic
# Feature updates: Manual
# Security patches: Immediate
```

## Setup Verification

### Checklist
- [ ] Application starts successfully
- [ ] Database connection working
- [ ] File upload functional
- [ ] All analysis modules responding
- [ ] Reports generating
- [ ] Admin functions accessible
- [ ] Security measures active
- [ ] Logging operational

### Performance Benchmarks
- [ ] Page load times < 3 seconds
- [ ] File analysis < 30 seconds
- [ ] Report generation < 60 seconds
- [ ] Database queries < 1 second

## Troubleshooting Common Setup Issues

### Database Issues
```bash
# Restart the application
# Check database permissions
# Verify connection string
```

### File Upload Problems
```bash
# Check file size limits
# Verify file permissions
# Clear browser cache
```

### Module Loading Errors
```bash
# Check Python dependencies
# Verify module imports
# Review error logs
```

## Next Steps

After completing setup:

1. Review the [User Manual](USER_MANUAL.md)
2. Read the [Technical Guide](TECHNICAL_GUIDE.md)
3. Check the [Deployment Guide](DEPLOYMENT.md)
4. Explore the [Feature Guide](FEATURES.md)

---

**Setup Complete**: ForensIQ is ready for forensic investigations!
