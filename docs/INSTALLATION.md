
# ForensIQ Installation Guide

## Overview

ForensIQ is designed to run seamlessly on Replit's cloud platform. This guide covers the complete installation and initial setup process.

## Prerequisites

### System Requirements
- **Platform**: Replit account (free or paid)
- **Internet Connection**: Required for cloud operation
- **Browser**: Modern web browser with JavaScript enabled
- **Storage**: Minimum 100MB available space

### Replit Environment
- **Python**: 3.11+ (automatically provided)
- **Database**: PostgreSQL (automatically configured)
- **Dependencies**: Managed through `pyproject.toml`

## Installation Steps

### 1. Access the Application

The ForensIQ platform is already installed and configured in your Replit environment.

```bash
# No installation required - dependencies are automatically managed
```

### 2. Initialize the Database

The database is automatically initialized when you first run the application:

```bash
python main.py
```

### 3. Verify Installation

1. **Check Application Status**
   ```bash
   # The application should start without errors
   python main.py
   ```

2. **Access Web Interface**
   - Open the web preview in Replit
   - URL: `https://your-repl-name.replit.app`
   - Alternative: `http://localhost:5000` (development)

3. **Test Core Features**
   - Navigate to Dashboard
   - Upload a test file for analysis
   - Check all menu items are accessible

### 4. Configuration Verification

Check that all components are properly configured:

#### Database Connection
```python
# Database is automatically configured via environment variables
# No manual setup required
```

#### File Upload Limits
```python
# Maximum file size: 16MB
# Supported formats: All file types
```

#### Security Settings
```python
# CSRF protection enabled
# Secure headers configured
# File validation active
```

## Post-Installation Setup

### 1. Initial Configuration

Navigate to **Settings** > **System Configuration**:

- **Evidence Storage**: Configured automatically
- **Chain of Custody**: Enabled by default
- **Logging Level**: Debug (development) / Info (production)
- **File Retention**: 30 days default

### 2. User Management

Access **Admin Portal** > **User Management**:

- **Default Access**: Open (no authentication required)
- **Role-Based Access**: Available for enterprise deployment
- **Audit Logging**: Enabled for all actions

### 3. Integration Setup

Configure external integrations if needed:

- **Threat Intelligence**: APIs for malware detection
- **Cloud Providers**: AWS, Azure, GCP credentials
- **Blockchain Networks**: RPC endpoints for analysis

## Verification Checklist

- [ ] Application starts without errors
- [ ] Database connection successful
- [ ] Web interface accessible
- [ ] File upload working
- [ ] All analysis modules responding
- [ ] Reports generating successfully
- [ ] Admin functions accessible

## Common Installation Issues

### Database Connection Errors
```bash
# Usually resolved by restarting the application
# Database is automatically configured in Replit
```

### Missing Dependencies
```bash
# Dependencies are automatically installed
# Restart the Repl if issues persist
```

### File Upload Problems
```bash
# Check file size (max 16MB)
# Verify file permissions
# Clear browser cache
```

## Next Steps

After successful installation:

1. Read the [Setup Guide](SETUP.md) for initial configuration
2. Review the [User Manual](USER_MANUAL.md) for feature overview
3. Check the [Technical Guide](TECHNICAL_GUIDE.md) for advanced configuration

## Support

If you encounter installation issues:

1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Verify system requirements are met
3. Restart the Replit environment
4. Contact support through the admin panel

---

**Installation Complete**: You're ready to start using ForensIQ!
