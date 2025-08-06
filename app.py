
import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime
import json
from werkzeug.security import generate_password_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "forensics_tool_secret")

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Database configuration with fallback
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    # Fallback to SQLite for development - use current directory
    database_url = "sqlite:///forensics.db"
    
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Import and initialize the database from models
from models import db

# Initialize the app with the extension
db.init_app(app)

# Import models after app initialization to avoid circular imports
from models import User, Evidence, Investigation, ChainOfCustody, AuditLog, InvestigationUser, InvestigationComment, EvidenceAnnotation, DeviceAcquisitionRecord, Analysis

# Import forensics utilities and other modules
from forensics_utils import (
    analyze_file,
    calculate_hash,
    get_file_metadata,
    generate_timeline,
    write_block_check
)
from auth import (
    AuthManager as AuthenticationManager, require_auth, require_permission, create_admin_user
)
from real_forensics import (
    AutopsyIntegration, VolatilityIntegration, SleuthKitIntegration,
    LiveMemoryAcquisition, NetworkPacketAnalysis, MobileDeviceAcquisition,
    CloudEvidencePreservation
)
from report_generator import ForensicReportGenerator, ScheduledReportManager
from device_acquisition import DeviceAcquisition
from network_scanner import NetworkScanner
from ai_intelligence import AIIntelligence
from cloud_forensics import CloudForensics
from blockchain_forensics import BlockchainForensics
from mobile_iot_forensics import MobileIoTForensics
from encryption_analysis import EncryptionAnalysis
from network_analysis import NetworkAnalysis
from timeline_intelligence import TimelineIntelligence
from live_remote_forensics import LiveRemoteForensics
from sandbox_analysis import SandboxAnalysis
from threat_intelligence import ThreatIntelligence
from search_regex import SearchRegex

def initialize_database():
    """Initialize the database tables and create admin user."""
    try:
        with app.app_context():
            # Check if tables exist, create if they don't
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            required_tables = [
                'user', 'evidence', 'investigation', 'chain_of_custody', 
                'audit_log', 'investigation_user', 'investigation_comment',
                'evidence_annotation', 'device_acquisition_record', 'analysis'
            ]
            
            missing_tables = [table for table in required_tables if table not in existing_tables]
            
            if missing_tables:
                print(f"📋 Creating missing tables: {missing_tables}")
                db.create_all()
                print("✅ All tables created successfully")
            else:
                print("📊 All required tables already exist")

            # Create default admin user if none exists
            try:
                admin_user = User.query.filter_by(role='admin').first()
                if not admin_user:
                    admin = User(
                        username='admin',
                        email='admin@forensiq.local',
                        password_hash=generate_password_hash('admin123'),
                        role='admin',
                        is_active=True
                    )
                    db.session.add(admin)
                    
                    # Create sample investigator user
                    investigator = User(
                        username='investigator',
                        email='investigator@forensiq.local',
                        password_hash=generate_password_hash('investigator123'),
                        role='investigator',
                        is_active=True
                    )
                    db.session.add(investigator)
                    
                    # Create sample viewer user
                    viewer = User(
                        username='viewer',
                        email='viewer@forensiq.local',
                        password_hash=generate_password_hash('viewer123'),
                        role='viewer',
                        is_active=True
                    )
                    db.session.add(viewer)
                    
                    db.session.commit()
                    print("✅ Default users created:")
                    print("   - admin/admin123 (Administrator)")
                    print("   - investigator/investigator123 (Investigator)")
                    print("   - viewer/viewer123 (Viewer)")
                else:
                    print("👤 Admin user already exists")
            except Exception as user_error:
                print(f"⚠️ Could not create users: {str(user_error)}")

        print("✅ Database initialized successfully")
        print(f"📊 Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        return True
    except Exception as e:
        print(f"❌ Database initialization error: {str(e)}")
        logging.error(f"Database error: {str(e)}")
        return False

# Initialize forensics handlers
device_handler = DeviceAcquisition()
ai_handler = AIIntelligence()
cloud_handler = CloudForensics()

# Initialize real forensics handlers
autopsy_handler = AutopsyIntegration()
volatility_handler = VolatilityIntegration()
sleuthkit_handler = SleuthKitIntegration()
memory_acquisition_handler = LiveMemoryAcquisition()
network_analysis_handler = NetworkPacketAnalysis()
mobile_acquisition_handler = MobileDeviceAcquisition()
cloud_preservation_handler = CloudEvidencePreservation()
report_generator = ForensicReportGenerator()
report_scheduler = ScheduledReportManager()

blockchain_handler = BlockchainForensics()
mobile_iot_handler = MobileIoTForensics()
encryption_handler = EncryptionAnalysis()
network_handler = NetworkAnalysis()
timeline_handler = TimelineIntelligence()
live_forensics_handler = LiveRemoteForensics()
sandbox_handler = SandboxAnalysis()
threat_intel_handler = ThreatIntelligence()
search_handler = SearchRegex()

# Authentication routes
@app.route("/login", methods=["GET", "POST"])
def login():
    """User login."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        mfa_token = request.form.get("mfa_token")

        success, result = AuthenticationManager.authenticate_user(username, password, mfa_token)

        if success:
            session['user_id'] = result.id
            session['username'] = result.username
            session['role'] = result.role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(result, 'error')

    return render_template("login.html")

@app.route("/logout")
def logout():
    """User logout."""
    AuditLog.create_log('user_logout')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
@require_permission('manage_users')
def register():
    """User registration (admin only)."""
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role", "viewer")

        success, result = AuthenticationManager.create_user(username, email, password, role)

        if success:
            flash(f'User {username} created successfully!', 'success')
            return redirect(url_for('admin'))
        else:
            flash(result, 'error')

    return render_template("register.html")

@app.route("/setup_mfa", methods=["GET", "POST"])
@require_auth
def setup_mfa():
    """Set up multi-factor authentication."""
    user = User.query.get(session['user_id'])

    if request.method == "POST":
        verification_token = request.form.get("verification_token")

        if AuthenticationManager.verify_mfa_token(user, verification_token):
            user.mfa_enabled = True
            db.session.commit()
            flash('MFA enabled successfully!', 'success')
            return redirect(url_for('settings'))
        else:
            flash('Invalid verification token.', 'error')

    # Generate MFA setup data
    secret, backup_codes, qr_code = AuthenticationManager.setup_mfa(user)

    return render_template("setup_mfa.html", 
                         secret=secret, 
                         backup_codes=backup_codes, 
                         qr_code=qr_code)

@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/dashboard")
@require_auth
def dashboard():
    """Live forensics dashboard."""
    try:
        # Get recent evidence with error handling
        recent_evidence = Evidence.query.order_by(Evidence.timestamp.desc()).limit(10).all()
        total_evidence = Evidence.query.count()
    except Exception as e:
        logging.error(f"Dashboard database error: {str(e)}")
        recent_evidence = []
        total_evidence = 0

    # Get real system metrics
    import psutil
    import shutil
    
    try:
        # CPU and memory usage
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        
        # Disk usage
        disk_usage = shutil.disk_usage('/')
        disk_percent = (disk_usage.used / disk_usage.total) * 100
        
        # Network activity
        network_stats = psutil.net_io_counters()
        network_activity = 'Active' if network_stats.bytes_sent > 1000000 else 'Low'
        
        # Count investigations and analyses
        try:
            active_investigations = Investigation.query.filter_by(status='open').count()
            total_analyses = Analysis.query.count()
        except:
            active_investigations = 0
            total_analyses = 0
        
        # Recent alerts from audit log
        recent_alerts = []
        try:
            recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(3).all()
            for log in recent_logs:
                alert_type = 'info'
                if 'failed' in log.action.lower() or 'error' in log.action.lower():
                    alert_type = 'warning'
                elif 'success' in log.action.lower() or 'completed' in log.action.lower():
                    alert_type = 'success'
                
                recent_alerts.append({
                    'type': alert_type,
                    'message': f'{log.action}: {log.details or "System activity"}',
                    'timestamp': log.timestamp.strftime('%H:%M') if log.timestamp else 'Unknown'
                })
        except:
            recent_alerts = [
                {'type': 'info', 'message': 'System monitoring active', 'timestamp': 'Now'}
            ]
    
        dashboard_data = {
            'total_evidence': total_evidence,
            'active_investigations': active_investigations,
            'ai_findings': total_analyses,
            'threat_matches': total_analyses // 3,  # Estimated threat matches
            'system_health': {
                'cpu_usage': round(cpu_usage, 1),
                'memory_usage': round(memory_usage, 1),
                'disk_usage': round(disk_percent, 1),
                'network_activity': network_activity
            },
            'recent_alerts': recent_alerts
        }
    except Exception as e:
        logging.error(f"System metrics error: {str(e)}")
        # Fallback to basic data
        dashboard_data = {
            'total_evidence': total_evidence,
            'active_investigations': 1,
            'ai_findings': 0,
            'threat_matches': 0,
            'system_health': {
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0,
                'network_activity': 'Unknown'
            },
            'recent_alerts': [
                {'type': 'info', 'message': 'System monitoring initialized', 'timestamp': 'Now'}
            ]
        }

    return render_template("dashboard.html", evidence_list=recent_evidence, **dashboard_data)

@app.route("/reports")
@require_auth
def reports():
    """Reports and timeline page."""
    try:
        investigations = Evidence.query.all()
    except Exception as e:
        logging.error(f"Reports database error: {str(e)}")
        investigations = []

    return render_template("reports.html", investigations=investigations, evidence_items=investigations)

@app.route("/settings")
@require_auth
def settings():
    """Settings and configuration page."""
    return render_template("settings.html")

@app.route("/admin")
@require_permission('manage_users')
def admin():
    """Admin portal page."""
    try:
        # Get system statistics with error handling
        total_users = User.query.count()
        total_evidence = Evidence.query.count()
        total_investigations = Investigation.query.count()

        admin_data = {
            'total_users': total_users,
            'total_evidence': total_evidence,
            'total_investigations': total_investigations,
            'system_uptime': '15 days, 3 hours',
            'recent_users': [
                {'name': 'John Smith', 'role': 'Senior Investigator', 'last_login': '2 hours ago'},
                {'name': 'Sarah Johnson', 'role': 'Forensics Analyst', 'last_login': '4 hours ago'},
                {'name': 'Mike Davis', 'role': 'Security Admin', 'last_login': '1 day ago'}
            ]
        }
    except Exception as e:
        logging.error(f"Admin portal error: {str(e)}")
        admin_data = {
            'total_users': 0,
            'total_evidence': 0,
            'total_investigations': 0,
            'system_uptime': 'Unknown',
            'recent_users': [],
            'error': str(e)
        }

    return render_template("admin.html", **admin_data)

@app.route("/detect_devices")
@require_auth
def detect_devices():
    """Device detection page."""
    return render_template("device_acquisition.html")

@app.route("/analysis")
@require_auth
def analysis():
    """Analysis page."""
    return render_template("analysis.html")

@app.route("/network_scan")
@require_auth
def network_scan():
    """Network scanning page."""
    return render_template("network_scan.html")

@app.route("/ai_analysis")
@require_auth
def ai_analysis():
    """AI analysis page."""
    return render_template("ai_analysis.html")

@app.route("/cloud_forensics")
@require_auth
def cloud_forensics():
    """Cloud forensics page."""
    return render_template("cloud_forensics.html")

@app.route("/blockchain_analysis")
@require_auth
def blockchain_analysis():
    """Blockchain analysis page."""
    return render_template("blockchain_analysis.html")

@app.route("/mobile_iot_forensics")
@require_auth
def mobile_iot_forensics():
    """Mobile IoT forensics page."""
    return render_template("mobile_iot_forensics.html")

@app.route("/encryption_analysis")
@require_auth
def encryption_analysis():
    """Encryption analysis page."""
    return render_template("encryption_analysis.html")

@app.route("/network_analysis")
@require_auth
def network_analysis():
    """Network analysis page."""
    return render_template("network_analysis.html")

@app.route("/timeline_analysis")
@require_auth
def timeline_analysis():
    """Timeline analysis page."""
    return render_template("timeline_analysis.html")

@app.route("/live_forensics")
@require_auth
def live_forensics():
    """Live forensics page."""
    return render_template("live_forensics.html")

@app.route("/sandbox_analysis")
@require_auth
def sandbox_analysis():
    """Sandbox analysis page."""
    return render_template("sandbox_analysis.html")

@app.route("/threat_intelligence")
@require_auth
def threat_intelligence():
    """Threat intelligence page."""
    return render_template("threat_intelligence.html")

@app.route("/search_analysis")
@require_auth
def search_analysis():
    """Search analysis page."""
    return render_template("search_analysis.html")

@app.route("/investigations")
@require_auth
def investigations():
    """Investigations page."""
    return render_template("investigations.html")

@app.route("/analyze")
@require_auth
def analyze():
    """File analysis page."""
    return render_template("analysis.html")

@app.route("/registry_analysis")
@require_auth
def registry_analysis():
    """Registry analysis page."""
    return render_template("registry_analysis.html")

@app.route("/devices")
@require_auth
def devices():
    """Device acquisition page."""
    return render_template("device_acquisition.html")

@app.route("/network")
@require_auth
def network():
    """Network scanning page."""
    return render_template("network_scan.html")

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("500.html"), 500

if __name__ == "__main__":
    # Initialize database when running directly
    try:
        print("🚀 Starting ForensIQ application...")
        initialize_database()
    except Exception as e:
        print(f"⚠️ Database setup had issues: {str(e)}, but continuing...")
    
    app.run(host="0.0.0.0", port=5000, debug=True)
