
# How to Run ForensIQ

## Quick Start (30 Seconds)

### 1. Launch the Application
```bash
python main.py
```

### 2. Access the Interface
- **Development URL**: `http://localhost:5000`
- **Replit Preview**: Click the web preview button
- **Custom Domain**: `https://your-repl-name.replit.app`

### 3. Start Investigating
- Upload evidence files through the Analysis section
- Explore the Dashboard for system overview
- Generate reports from your investigations

## Detailed Running Instructions

### Prerequisites Check
```bash
# Verify Python version (should be 3.11+)
python --version

# Check if all dependencies are available
# (Automatically handled by Replit)
```

### Starting the Application

#### Method 1: Using Replit Run Button
1. Click the **Run** button at the top of the Replit interface
2. Wait for the application to start
3. Click the web preview to open the interface

#### Method 2: Using Terminal
```bash
# Navigate to project directory (if not already there)
cd /path/to/forensiq

# Run the application
python main.py
```

#### Method 3: Using Gunicorn (Production)
```bash
# For production deployment
gunicorn --bind 0.0.0.0:5000 app:app
```

### Verification Steps

#### 1. Check Application Status
```bash
# Application should display:
# * Running on http://127.0.0.1:5000
# * Debug mode: on
# * Database initialized successfully
```

#### 2. Test Web Interface
- Navigate to the application URL
- Verify the dashboard loads
- Check that all navigation links work
- Test file upload functionality

#### 3. Test Core Functions
- **Evidence Upload**: Upload a test file
- **Analysis**: Run a basic analysis
- **Reporting**: Generate a sample report
- **Dashboard**: Check system metrics

### Running Different Modes

#### Development Mode (Default)
```bash
# Debug mode enabled
# Detailed error messages
# Auto-reload on file changes
python main.py
```

#### Production Mode
```bash
# Set environment variable
export FLASK_ENV=production

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

#### Testing Mode
```bash
# Enable testing mode
export FLASK_ENV=testing

# Run tests
python -m pytest tests/
```

### Environment Configuration

#### Required Environment Variables
```bash
# Core settings (automatically configured in Replit)
FLASK_SECRET_KEY=auto-generated
DATABASE_URL=postgresql://...

# Optional settings
FLASK_ENV=development
DEBUG=True
```

#### Database Setup
```bash
# Database is automatically initialized
# Tables created on first run
# No manual setup required
```

### Troubleshooting Startup Issues

#### Common Problems

1. **Port Already in Use**
   ```bash
   # Change port in main.py
   app.run(host="0.0.0.0", port=5001, debug=True)
   ```

2. **Database Connection Error**
   ```bash
   # Database is automatically configured in Replit
   # Restart the application if issues persist
   ```

3. **Module Not Found**
   ```bash
   # Dependencies are automatically installed
   # Restart the Repl if issues occur
   ```

4. **Permission Errors**
   ```bash
   # Usually not an issue in Replit
   # Check file permissions if needed
   ```

### Running Specific Features

#### AI Analysis Only
```bash
# Run with AI analysis enabled
python -c "from app import app; app.run(host='0.0.0.0', port=5000)"
```

#### Cloud Forensics Mode
```bash
# Enable cloud forensics features
export ENABLE_CLOUD_FORENSICS=True
python main.py
```

#### Blockchain Analysis
```bash
# Enable blockchain analysis
export ENABLE_BLOCKCHAIN=True
python main.py
```

### Performance Optimization

#### Memory Usage
```bash
# Monitor memory usage
python -c "
import psutil
print(f'Memory usage: {psutil.virtual_memory().percent}%')
"
```

#### Database Performance
```bash
# Check database performance
python -c "
from app import db
print('Database connection OK')
"
```

### Development Workflow

#### Running with Auto-Reload
```bash
# Auto-reload is enabled by default in debug mode
python main.py
```

#### Running Tests
```bash
# Run unit tests
python -m unittest discover tests/

# Run integration tests
python -m pytest tests/integration/
```

#### Code Quality Checks
```bash
# Check code formatting
python -m black app.py

# Check imports
python -m isort app.py

# Run linter
python -m flake8 app.py
```

### Production Deployment

#### Using Replit Deployments
1. Click **Deploy** in the Replit interface
2. Choose **Autoscale** deployment
3. Configure domain and settings
4. Click **Deploy**

#### Manual Production Setup
```bash
# Set production environment
export FLASK_ENV=production
export DATABASE_URL=postgresql://...

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

### Monitoring and Logs

#### View Application Logs
```bash
# Logs are displayed in the console
# Look for startup messages and errors
```

#### Monitor Performance
```bash
# Check system resources
python -c "
import psutil
print(f'CPU: {psutil.cpu_percent()}%')
print(f'Memory: {psutil.virtual_memory().percent}%')
print(f'Disk: {psutil.disk_usage(\"/\").percent}%')
"
```

### Stopping the Application

#### Graceful Shutdown
```bash
# Press Ctrl+C in the terminal
# Or click Stop button in Replit
```

#### Force Stop
```bash
# If application is unresponsive
# Click the Stop button in Replit
# Or restart the entire Repl
```

### Advanced Running Options

#### Custom Configuration
```bash
# Run with custom settings
python -c "
from app import app
app.config['CUSTOM_SETTING'] = 'value'
app.run(host='0.0.0.0', port=5000, debug=True)
"
```

#### Multiple Workers
```bash
# Run with multiple workers (production)
gunicorn --bind 0.0.0.0:5000 --workers 4 --worker-class sync app:app
```

#### Background Tasks
```bash
# Run with Celery for background tasks
celery -A app.celery worker --loglevel=info
```

### Health Checks

#### Application Health
```bash
# Check if application is responding
curl http://localhost:5000/health
```

#### Database Health
```bash
# Check database connection
python -c "
from app import db
try:
    db.session.execute('SELECT 1')
    print('Database: OK')
except Exception as e:
    print(f'Database error: {e}')
"
```

### Security Considerations

#### Running Securely
```bash
# Ensure secure configuration
export FLASK_ENV=production
export SECRET_KEY=your-secure-secret-key

# Run with security headers
python main.py
```

#### File Permissions
```bash
# Check file permissions (if needed)
ls -la instance/
```

### Integration with External Services

#### Threat Intelligence
```bash
# Run with threat intelligence enabled
export VIRUSTOTAL_API_KEY=your-key
python main.py
```

#### Cloud Providers
```bash
# Run with cloud provider support
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
python main.py
```

## Summary

ForensIQ is designed to run easily on Replit with minimal setup:

1. **Start**: `python main.py`
2. **Access**: Click web preview or visit your Replit URL
3. **Use**: Begin forensic investigations immediately

The application handles all dependencies, database setup, and configuration automatically in the Replit environment.

---

**Ready to Run**: ForensIQ is now ready for digital forensic investigations!
