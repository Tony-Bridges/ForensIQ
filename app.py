
import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_moment import Moment
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime
import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from google.cloud import storage
from google.cloud import logging as gcp_logging
import kubernetes.client
from kubernetes.config import kube_config
import docker
#import libvirt
import hashlib
import json
from werkzeug.security import generate_password_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "forensics_tool_secret")
csrf = CSRFProtect(app)

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
from flask_moment import Moment

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
moment = Moment(app)

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



ALLOWED_EXTENSIONS = {'vmdk', 'vhdx', 'vdi', 'qcow2'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/cloud_forensics", methods=["GET", "POST"])
@require_auth
def cloud_forensics():
    """Cloud and container forensics analysis dashboard."""
    results = None
    analysis_type = None
    cloud_handler = CloudForensics()
    visualization_data = None

    if request.method == "POST":
        analysis_type = request.form.get('analysis_type')

        try:
            if analysis_type == "cloud_acquisition":
                cloud_provider = request.form.get('cloud_provider')
                resource_types = request.form.getlist('resource_types')

                # Get credentials from secure session storage
                credentials = session.get('cloud_credentials', {}).get(cloud_provider, {})

                if not credentials:
                    flash(f'No credentials found for {cloud_provider}. Please configure first.', 'error')
                    return redirect(url_for('cloud_settings'))

                results = cloud_handler.acquire_cloud_data(
                    cloud_provider,
                    credentials,
                    resource_types
                )

                # Generate visualization data
                if results and 'resources' in results:
                    visualization_data = {
                        'resource_types': list(results['resources'].keys()),
                        'counts': [len(v) if isinstance(v, list) else 1 for v in results['resources'].values()]
                    }

            elif analysis_type == "container_analysis":
                container_runtime = request.form.get('container_runtime')

                if container_runtime == 'docker':
                    results = cloud_handler.analyze_docker_containers()
                    visualization_data = cloud_handler.generate_container_visualization(results)

                elif container_runtime == 'kubernetes':
                    kubeconfig_path = request.form.get('kubeconfig_path', os.path.expanduser('~/.kube/config'))
                    namespace = request.form.get('namespace', 'default')
                    results = cloud_handler.analyze_kubernetes_pods(kubeconfig_path, namespace)
                    visualization_data = cloud_handler.generate_k8s_visualization(results)

                elif container_runtime == 'containerd':
                    results = {'error': 'containerd analysis not yet implemented'}

            elif analysis_type == "serverless_trace":
                cloud_provider = request.form.get('cloud_provider')
                function_names = [f.strip() for f in request.form.get('function_names', '').split(',') if f.strip()]

                credentials = session.get('cloud_credentials', {}).get(cloud_provider, {})
                if not credentials:
                    flash(f'No credentials found for {cloud_provider}. Please configure first.', 'error')
                    return redirect(url_for('cloud_settings'))

                results = cloud_handler.trace_serverless_functions(cloud_provider, function_names, credentials)
                visualization_data = cloud_handler.generate_serverless_visualization(results)

            elif analysis_type == "vm_analysis":
                vm_format = request.form.get('vm_format')

                if 'disk_file' in request.files:
                    file = request.files['disk_file']
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        temp_dir = tempfile.mkdtemp()
                        disk_path = os.path.join(temp_dir, filename)
                        file.save(disk_path)
                        results = cloud_handler.analyze_vm_disks(vm_format, disk_path)
                        visualization_data = cloud_handler.generate_vm_visualization(results)
                        # Clean up temp file
                        try:
                            os.remove(disk_path)
                            os.rmdir(temp_dir)
                        except:
                            pass
                    else:
                        flash('Invalid file type for VM disk', 'error')
                else:
                    disk_path = request.form.get('disk_path')
                    if os.path.exists(disk_path):
                        results = cloud_handler.analyze_vm_disks(vm_format, disk_path)
                        visualization_data = cloud_handler.generate_vm_visualization(results)
                    else:
                        flash('Specified disk path does not exist', 'error')

            if results and not results.get('error'):
                flash(f'{analysis_type.replace("_", " ").title()} completed successfully!', 'success')
            elif results and results.get('error'):
                flash(f'Analysis error: {results["error"]}', 'error')

        except Exception as e:
            logger.error(f"Cloud forensics error: {str(e)}", exc_info=True)
            flash(f'Analysis failed: {str(e)}', 'error')
            results = {'error': str(e)}

    return render_template(
        "cloud_forensics.html",
        results=results,
        analysis_type=analysis_type,
        visualization=visualization_data
    )

@app.route("/cloud_settings", methods=["GET", "POST"])
@require_auth
def cloud_settings():
    """Cloud credentials configuration."""
    if request.method == "POST":
        try:
            cloud_provider = request.form.get('cloud_provider')
            credentials = {
                'aws': {
                    'access_key': request.form.get('aws_access_key'),
                    'secret_key': request.form.get('aws_secret_key'),
                    'region': request.form.get('aws_region')
                },
                'azure': {
                    'subscription_id': request.form.get('azure_subscription_id'),
                    'tenant_id': request.form.get('azure_tenant_id'),
                    'client_id': request.form.get('azure_client_id'),
                    'client_secret': request.form.get('azure_client_secret')
                },
                'gcp': {
                    'project_id': request.form.get('gcp_project_id'),
                    'credentials_json': request.form.get('gcp_credentials_json')
                }
            }

            # Validate credentials
            if cloud_provider == 'aws':
                boto3.client('sts', 
                    aws_access_key_id=credentials['aws']['access_key'],
                    aws_secret_access_key=credentials['aws']['secret_key'],
                    region_name=credentials['aws']['region']
                ).get_caller_identity()

            # Store in session (in production, use a secure database)
            if 'cloud_credentials' not in session:
                session['cloud_credentials'] = {}
            session['cloud_credentials'][cloud_provider] = credentials[cloud_provider]
            session.modified = True

            flash(f'{cloud_provider.upper()} credentials validated and saved!', 'success')

        except Exception as e:
            logger.error(f"Cloud credentials error: {str(e)}", exc_info=True)
            flash(f'Failed to validate credentials: {str(e)}', 'error')

    return render_template("cloud_settings.html")


@app.route("/clear_credentials/<provider>", methods=["POST"])
@require_auth
def clear_credentials(provider):
    """Remove credentials for a specific provider."""
    if 'cloud_credentials' in session and provider in session['cloud_credentials']:
        del session['cloud_credentials'][provider]
        session.modified = True
        flash(f'{provider.upper()} credentials removed', 'success')
    return redirect(url_for('cloud_settings'))

@app.route("/cloud_forensics", methods=["POST"])
@require_auth
def api_cloud_forensics():
    """API endpoint for cloud forensics operations."""
    try:
        data = request.get_json()
        if not data or 'analysis_type' not in data:
            return jsonify({"error": "Missing analysis_type in request"}), 400

        cloud_handler = CloudForensics()
        analysis_type = data['analysis_type']
        results = {}
        visualization = None

        if analysis_type == "cloud_acquisition":
            if 'cloud_provider' not in data:
                return jsonify({"error": "Missing cloud_provider for acquisition"}), 400
            cloud_provider = data['cloud_provider']
            credentials = data.get('credentials', {})
            resource_types = data.get('resource_types', ['logs', 'storage', 'iam'])
            results = cloud_handler.acquire_cloud_data(cloud_provider, credentials, resource_types)
            visualization = cloud_handler.generate_cloud_visualization(results)

        elif analysis_type == "container_analysis":
            container_runtime = data.get('container_runtime', 'docker')

            if container_runtime == 'docker':
                container_ids = data.get('container_ids')
                results = cloud_handler.analyze_docker_containers(container_ids)
                visualization = cloud_handler.generate_container_visualization(results)
            elif container_runtime == 'kubernetes':
                kubeconfig = data.get('kubeconfig')
                namespace = data.get('namespace', 'default')
                results = cloud_handler.analyze_kubernetes_pods(kubeconfig, namespace)
                visualization = cloud_handler.generate_k8s_visualization(results)
            else:
                return jsonify({"error": "Unsupported container runtime"}), 400

        elif analysis_type == "serverless_trace":
            if 'cloud_provider' not in data:
                return jsonify({"error": "Missing cloud_provider for serverless tracing"}), 400
            cloud_provider = data['cloud_provider']
            credentials = data.get('credentials', {})
            function_names = data.get('function_names')
            results = cloud_handler.trace_serverless_functions(cloud_provider, function_names, credentials)
            visualization = cloud_handler.generate_serverless_visualization(results)

        elif analysis_type == "vm_analysis":
            if 'vm_format' not in data or 'disk_path' not in data:
                return jsonify({"error": "Missing vm_format or disk_path for VM analysis"}), 400
            vm_format = data['vm_format']
            disk_path = data['disk_path']
            results = cloud_handler.analyze_vm_disks(vm_format, disk_path)
            visualization = cloud_handler.generate_vm_visualization(results)

        else:
            return jsonify({"error": "Invalid analysis_type specified"}), 400

        return jsonify({
            "results": results,
            "visualization": visualization
        })

    except Exception as e:
        logger.error(f"API cloud forensics error: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500



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



#Agent Route 
@app.route("/agent")
@require_auth
def list_agents():
   """Display all agents with filtering and pagination"""
   page = request.args.get('page', 1, type=int)
   status_filter = request.args.get('status', '')
   platform_filter = request.args.get('platform', '')

   query = Agent.query

   if status_filter:
       query = query.filter_by(status=AgentStatus(status_filter))
   if platform_filter:
       query = query.filter_by(platform=platform_filter)

   agents = query.paginate(page=page, per_page=20, error_out=False)

   # Get unique platforms for filter dropdown
   platforms = db.session.query(Agent.platform).distinct().all()
   platforms = [p[0] for p in platforms]

   return render_template('agents.html', 
                        agents=agents, 
                        platforms=platforms,
                        current_status=status_filter,
                        current_platform=platform_filter)

# Agent Management Routes
@app.route("/agent/deploy", methods=["GET", "POST"])
@require_auth
def deploy_agent():
    """Agent deployment page with configuration options."""
    if request.method == "POST":
        try:
            # Get form data
            platform = request.form.get('platform')
            deployment_method = request.form.get('method')
            target_ips = request.form.get('target_ips')
            agent_version = request.form.get('agent_version')
            collection_interval = request.form.get('collection_interval')

            # Get capabilities
            capabilities = {
                'memory_capture': 'memory-capture' in request.form,
                'file_hashing': 'file-hashing' in request.form,
                'network_monitoring': 'network-monitoring' in request.form,
                'process_analysis': 'process-analysis' in request.form,
                'system_info': 'system-info' in request.form,
                'federated_learning': 'federated-learning' in request.form
            }

            # Get credentials if remote deployment
            credentials = {}
            if deployment_method == 'remote':
                credentials = {
                    'username': request.form.get('username'),
                    'password': request.form.get('password')
                }

            # Validate inputs
            if not platform or not target_ips:
                flash('Platform and target IPs are required', 'error')
                return redirect(url_for('deploy_agent'))

            # Process IP addresses
            ip_list = [ip.strip() for ip in target_ips.split('\n') if ip.strip()]

            # Create deployment task (in a real app, this would be async)
            deployment = {
                'platform': platform,
                'method': deployment_method,
                'targets': ip_list,
                'version': agent_version,
                'interval': collection_interval,
                'capabilities': capabilities,
                'credentials': credentials,
                'status': 'pending',
                'start_time': datetime.utcnow()
            }

            # In a real app, you would save this to a database and start deployment
            flash('Agent deployment started successfully!', 'success')
            return redirect(url_for('list_agents'))

        except Exception as e:
            logging.error(f"Agent deployment error: {str(e)}")
            flash(f'Deployment failed: {str(e)}', 'error')

    return render_template("deploy_agent.html")

@app.route("/agent/federated", methods=["GET", "POST"])
@require_auth
def federated_learning():
    """Federated learning configuration page."""
    if request.method == "POST":
        try:
            # Get form data
            model = request.form.get('fl-model')
            rounds = request.form.get('fl-rounds')
            learning_rate = request.form.get('fl-learning-rate')
            batch_size = request.form.get('fl-batch-size')
            epochs = request.form.get('fl-epochs')
            privacy = request.form.get('fl-privacy')
            agents = request.form.getlist('fl-agents')

            # Validate inputs
            if not model:
                flash('Model selection is required', 'error')
                return redirect(url_for('federated_learning'))

            # Create training task
            training_config = {
                'model': model,
                'rounds': int(rounds),
                'learning_rate': float(learning_rate),
                'batch_size': int(batch_size),
                'epochs': int(epochs),
                'privacy': float(privacy),
                'agents': agents,
                'status': 'pending',
                'start_time': datetime.utcnow()
            }

            # In a real app, you would save this and start the training process
            flash('Federated learning training started!', 'success')
            return redirect(url_for('federated_learning'))

        except Exception as e:
            logging.error(f"Federated learning error: {str(e)}")
            flash(f'Training configuration failed: {str(e)}', 'error')

    return render_template("deploy_agent.html", active_tab='federated')

@app.route("/agent/manage")
@require_auth
def manage_agents():
    """Agent management dashboard."""
    # In a real app, you would query your database for agent status
    agents = [
        {
            'id': 'agent-001',
            'name': 'WIN-AGENT-01',
            'platform': 'Windows',
            'status': 'online',
            'ip': '192.168.1.100',
            'version': '1.0.0',
            'last_seen': datetime.utcnow()
        },
        {
            'id': 'agent-002',
            'name': 'LINUX-AGENT-01',
            'platform': 'Linux',
            'status': 'online',
            'ip': '192.168.1.101',
            'version': '1.0.0',
            'last_seen': datetime.utcnow()
        },
        {
            'id': 'agent-003',
            'name': 'MAC-AGENT-01',
            'platform': 'macOS',
            'status': 'offline',
            'ip': '192.168.1.102',
            'version': '0.9.5',
            'last_seen': datetime.utcnow() - timedelta(hours=1)
        }
    ]

    return render_template("deploy_agent.html", active_tab='management', agents=agents)

@app.route("/agent/<agent_id>")
@require_auth
def agent_details(agent_id):
    """Detailed view of a specific agent."""
    # In a real app, you would query your database for this agent
    agent = {
        'id': agent_id,
        'name': f'AGENT-{agent_id.upper()}',
        'platform': 'Windows',
        'status': 'online',
        'ip': '192.168.1.100',
        'version': '1.0.0',
        'last_seen': datetime.utcnow(),
        'capabilities': ['memory_capture', 'file_hashing', 'network_monitoring'],
        'deployment_time': datetime.utcnow() - timedelta(days=7),
        'resources': {
            'cpu': 45.2,
            'memory': 32.1,
            'network': 5.7
        }
    }

    return render_template("agent_details.html", agent=agent)

@app.route("/agent/<agent_id>/command", methods=["POST"])
@require_auth
def send_agent_command(agent_id):
    """Send a command to a specific agent."""
    command = request.form.get('command')

    if not command:
        flash('No command specified', 'error')
        return redirect(url_for('agent_details', agent_id=agent_id))

    try:
        # In a real app, you would send this command to the agent
        result = {
            'success': True,
            'command': command,
            'output': f"Command '{command}' executed successfully on agent {agent_id}",
            'timestamp': datetime.utcnow()
        }

        flash('Command sent successfully', 'success')
        return render_template("agent_details.html", 
                             agent=agent_details(agent_id)['agent'],
                             command_result=result)

    except Exception as e:
        logging.error(f"Agent command error: {str(e)}")
        flash(f'Command failed: {str(e)}', 'error')
        return redirect(url_for('agent_details', agent_id=agent_id))

@app.route("/agent/<agent_id>/update", methods=["POST"])
@require_auth
def update_agent(agent_id):
    """Update agent configuration or version."""
    try:
        version = request.form.get('version')
        capabilities = request.form.getlist('capabilities')

        # In a real app, you would update the agent configuration
        flash(f'Agent {agent_id} update scheduled', 'success')
        return redirect(url_for('agent_details', agent_id=agent_id))

    except Exception as e:
        logging.error(f"Agent update error: {str(e)}")
        flash(f'Update failed: {str(e)}', 'error')
        return redirect(url_for('agent_details', agent_id=agent_id))

@app.route("/agent/<agent_id>/remove", methods=["POST"])
@require_auth
def remove_agent(agent_id):
    """Remove/uninstall an agent."""
    try:
        # In a real app, you would initiate agent removal
        flash(f'Agent {agent_id} removal initiated', 'success')
        return redirect(url_for('list_agents'))

    except Exception as e:
        logging.error(f"Agent removal error: {str(e)}")
        flash(f'Removal failed: {str(e)}', 'error')
        return redirect(url_for('agent_details', agent_id=agent_id))

# API Endpoints for Agent Management
@app.route("/api/agents", methods=["GET"])
@require_auth
def api_list_agents():
    """API endpoint to list all agents."""
    # In a real app, you would query your database
    agents = [
        {
            'id': 'agent-001',
            'name': 'WIN-AGENT-01',
            'platform': 'Windows',
            'status': 'online',
            'ip': '192.168.1.100',
            'version': '1.0.0',
            'last_seen': datetime.utcnow().isoformat()
        },
        # ... more agents
    ]
    return jsonify(agents)

@app.route("/api/agents/deploy", methods=["POST"])
@require_auth
def api_deploy_agent():
    """API endpoint to deploy agents."""
    data = request.get_json()

    if not data or 'platform' not in data or 'targets' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # In a real app, you would process the deployment
        deployment_id = f"deploy-{uuid.uuid4().hex[:8]}"
        return jsonify({
            'success': True,
            'deployment_id': deployment_id,
            'message': 'Deployment started'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/agents/<agent_id>", methods=["GET"])
@require_auth
def api_agent_details(agent_id):
    """API endpoint for agent details."""
    # In a real app, you would query your database
    agent = {
        'id': agent_id,
        'name': f'AGENT-{agent_id.upper()}',
        'platform': 'Windows',
        'status': 'online',
        'ip': '192.168.1.100',
        'version': '1.0.0',
        'last_seen': datetime.utcnow().isoformat()
    }
    return jsonify(agent)

@app.route("/api/agents/<agent_id>/command", methods=["POST"])
@require_auth
def api_send_agent_command(agent_id):
    """API endpoint to send commands to agents."""
    data = request.get_json()

    if not data or 'command' not in data:
        return jsonify({'error': 'Command required'}), 400

    try:
        # In a real app, you would send the command to the agent
        return jsonify({
            'success': True,
            'command': data['command'],
            'output': f"Command '{data['command']}' executed on {agent_id}",
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route("/ai_intelligence", methods=["GET", "POST"])
@require_auth
def ai_intelligence():
    """AI Intelligence dashboard with multiple analysis capabilities."""
    analysis_results = None
    analysis_type = None
    ai_handler = AIIntelligence()

    if request.method == "POST":
        analysis_type = request.form.get('analysis_type')

        try:
            if analysis_type == "anomaly_detection":
                uploaded_files = request.files.getlist('anomaly_files')
                if uploaded_files and uploaded_files[0].filename != '':
                    file_paths = []
                    for file in uploaded_files:
                        temp_path = os.path.join('/tmp', file.filename)
                        file.save(temp_path)
                        file_paths.append(temp_path)

                    results = ai_handler.detect_anomalies(file_paths)
                    analysis_results = results

                    # Clean up temp files
                    for path in file_paths:
                        try:
                            os.remove(path)
                        except:
                            pass
                else:
                    flash('No files uploaded for anomaly detection', 'error')

            elif analysis_type == "malware_classification":
                uploaded_file = request.files.get('malware_file')
                classification_type = request.form.get('classification_type', 'behavioral')

                if uploaded_file and uploaded_file.filename != '':
                    temp_path = os.path.join('/tmp', uploaded_file.filename)
                    uploaded_file.save(temp_path)

                    with open(temp_path, 'rb') as f:
                        results = ai_handler.classify_malware(f, analysis_type=classification_type)
                        analysis_results = results

                    try:
                        os.remove(temp_path)
                    except:
                        pass
                else:
                    flash('No file uploaded for malware classification', 'error')

            elif analysis_type == "entity_extraction":
                text_content = request.form.get('text_content')
                query_context = request.form.get('query_context')

                if text_content:
                    results = ai_handler.extract_entities_nlp(text_content, query_context)
                    analysis_results = results
                else:
                    flash('No text content provided for entity extraction', 'error')

            elif analysis_type == "compromise_prediction":
                try:
                    incident_history = json.loads(request.form.get('incident_history', '[]'))
                    current_indicators = json.loads(request.form.get('current_indicators', '{}'))

                    if incident_history or current_indicators:
                        results = ai_handler.predict_compromise_zones(incident_history, current_indicators)
                        analysis_results = results
                    else:
                        flash('No historical incidents or current indicators provided', 'error')
                except json.JSONDecodeError:
                    flash('Invalid JSON format for incident history or indicators', 'error')

            elif analysis_type == "media_verification":
                uploaded_file = request.files.get('media_file')
                media_type = request.form.get('media_type', 'image')

                if uploaded_file and uploaded_file.filename != '':
                    temp_path = os.path.join('/tmp', uploaded_file.filename)
                    uploaded_file.save(temp_path)

                    with open(temp_path, 'rb') as f:
                        results = ai_handler.verify_media_authenticity(f, media_type=media_type)
                        analysis_results = results

                    try:
                        os.remove(temp_path)
                    except:
                        pass
                else:
                    flash('No media file uploaded for verification', 'error')

            if analysis_results and not analysis_results.get('error'):
                flash(f'{analysis_type.replace("_", " ").title()} completed successfully!', 'success')
            elif analysis_results and analysis_results.get('error'):
                flash(f'Analysis error: {analysis_results["error"]}', 'error')

        except Exception as e:
            logging.error(f"AI Intelligence analysis error: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')
            analysis_results = {'error': str(e)}

    return render_template(
        "ai_intelligence.html",
        results=analysis_results,
        analysis_type=analysis_type,
        ml_available=ML_AVAILABLE
    )

@app.route("/ai_analysis", methods=["POST"])
@require_auth
def api_ai_analyze():
    """API endpoint for AI-powered analysis."""
    try:
        data = request.get_json()
        if not data or 'analysis_type' not in data:
            return jsonify({"error": "Missing analysis_type in request"}), 400

        ai_handler = AIIntelligence()
        analysis_type = data['analysis_type']
        results = {}

        if analysis_type == "anomaly_detection":
            if 'file_data' not in data:
                return jsonify({"error": "Missing file_data for anomaly detection"}), 400
            file_data = data['file_data']  # Could be list of file paths or data
            results = ai_handler.detect_anomalies(file_data)

        elif analysis_type == "malware_classification":
            if 'file_data' not in data:
                return jsonify({"error": "Missing file_data for malware classification"}), 400
            file_data = data['file_data']  # Could be file content or path
            analysis_method = data.get('analysis_method', 'behavioral')
            results = ai_handler.classify_malware(file_data, analysis_method)

        elif analysis_type == "entity_extraction":
            if 'text_content' not in data:
                return jsonify({"error": "Missing text_content for entity extraction"}), 400
            text_content = data['text_content']
            query_context = data.get('query_context')
            results = ai_handler.extract_entities_nlp(text_content, query_context)

        elif analysis_type == "compromise_prediction":
            incident_history = data.get('incident_history', [])
            current_indicators = data.get('current_indicators', {})
            results = ai_handler.predict_compromise_zones(incident_history, current_indicators)

        elif analysis_type == "media_verification":
            if 'media_data' not in data:
                return jsonify({"error": "Missing media_data for verification"}), 400
            media_data = data['media_data']
            media_type = data.get('media_type', 'image')
            results = ai_handler.verify_media_authenticity(media_data, media_type)

        else:
            return jsonify({"error": "Invalid analysis_type specified"}), 400

        return jsonify(results)

    except Exception as e:
        logging.error(f"API AI analysis error: {str(e)}")
        return jsonify({"error": str(e)}), 500

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

@app.route("/agents")
@require_auth
def agents():
    """Agents page."""
    return render_template("agent.html")       
    

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

# Encryption, Steganography, and Evasion Analysis Routes
@app.route("/encryption_analysis", methods=["GET", "POST"])
@require_auth
def encryption_analysis():
    """Encryption analysis page and processing."""
    analysis_results = None
    selected_analysis_type = 'file'  # Default value

    if request.method == "POST":
        try:
            # Handle file upload
            uploaded_file = request.files.get('file')
            selected_analysis_type = request.form.get('analysis_type', 'file')

            if uploaded_file and uploaded_file.filename != '':
                # Save temporarily or process in memory
                encryption_handler = EncryptionAnalysis()
                analysis_results = encryption_handler.detect_encrypted_volumes(
                    uploaded_file.stream, 
                    analysis_type=selected_analysis_type
                )

                flash('Encryption analysis completed successfully!', 'success')
            else:
                flash('No file uploaded for analysis', 'error')

        except Exception as e:
            logging.error(f"Encryption analysis error: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')

    return render_template(
        "encryption_analysis.html", 
        results=analysis_results,
        analysis_type=selected_analysis_type
    )
@app.route("/steganography_analysis", methods=["GET", "POST"])
@require_auth
def steganography_analysis():
    """Steganography analysis page and processing."""
    analysis_results = None
    if request.method == "POST":
        try:
            uploaded_file = request.files.get('file')
            media_type = request.form.get('media_type', 'auto')

            if uploaded_file:
                encryption_handler = EncryptionAnalysis()
                analysis_results = encryption_handler.detect_steganography(
                    uploaded_file.stream,
                    media_type=media_type
                )

                flash('Steganography analysis completed!', 'success')
            else:
                flash('No media file uploaded', 'error')

        except Exception as e:
            logging.error(f"Steganography analysis error: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')

    return render_template("steganography_analysis.html", results=analysis_results)

@app.route("/rootkit_analysis", methods=["GET", "POST"])
@require_auth
def rootkit_analysis():
    """Rootkit detection page and processing."""
    analysis_results = None
    if request.method == "POST":
        try:
            # Could accept memory dumps, system logs, etc.
            analysis_scope = request.form.get('analysis_scope', 'full')

            # In a real implementation, this would process uploaded system data
            encryption_handler = EncryptionAnalysis()
            analysis_results = encryption_handler.detect_rootkits(
                {},  # Empty dict as placeholder for real system data
                analysis_scope=analysis_scope
            )

            flash('Rootkit analysis completed!', 'success')
        except Exception as e:
            logging.error(f"Rootkit analysis error: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')

    return render_template("rootkit_analysis.html", results=analysis_results)

@app.route("/fileless_malware_analysis", methods=["GET", "POST"])
@require_auth
def fileless_malware_analysis():
    """Fileless malware detection page and processing."""
    analysis_results = None
    if request.method == "POST":
        try:
            # Could accept memory dumps, process lists, etc.
            memory_dump = request.files.get('memory_dump')

            if memory_dump:
                encryption_handler = EncryptionAnalysis()
                analysis_results = encryption_handler.detect_fileless_malware(
                    memory_dump.stream,
                    process_list=None  # Could be provided separately
                )

                flash('Fileless malware analysis completed!', 'success')
            else:
                flash('No memory dump provided', 'error')

        except Exception as e:
            logging.error(f"Fileless malware analysis error: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')

    return render_template("fileless_malware_analysis.html", results=analysis_results)

@app.route("/api/analyze_encryption", methods=["POST"])
@require_auth
def api_analyze_encryption():
    """API endpoint for encryption analysis."""
    try:
        data = request.get_json()
        if not data or 'file_data' not in data:
            return jsonify({"error": "No file data provided"}), 400

        file_data = base64.b64decode(data['file_data'])
        analysis_type = data.get('analysis_type', 'file')

        encryption_handler = EncryptionAnalysis()
        results = encryption_handler.detect_encrypted_volumes(
            file_data,
            analysis_type=analysis_type
        )

        return jsonify(results)
    except Exception as e:
        logging.error(f"API encryption analysis error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze_steganography", methods=["POST"])
@require_auth
def api_analyze_steganography():
    """API endpoint for steganography analysis."""
    try:
        data = request.get_json()
        if not data or 'file_data' not in data:
            return jsonify({"error": "No file data provided"}), 400

        file_data = base64.b64decode(data['file_data'])
        media_type = data.get('media_type', 'auto')

        encryption_handler = EncryptionAnalysis()
        results = encryption_handler.detect_steganography(
            file_data,
            media_type=media_type
        )

        return jsonify(results)
    except Exception as e:
        logging.error(f"API steganography analysis error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/encryption_evasion", methods=["GET", "POST"])
@require_auth
def encryption_evasion():
    """Encryption and evasion analysis page with dynamic form handling."""
    results = None
    analysis_type = None
    encryption_handler = EncryptionAnalysis()

    if request.method == "POST":
        analysis_type = request.form.get('analysis_type')

        try:
            if analysis_type == "encryption_detection":
                uploaded_file = request.files.get('file')
                file_analysis_type = request.form.get('file_analysis_type', 'file')

                if uploaded_file and uploaded_file.filename != '':
                    results = encryption_handler.detect_encrypted_volumes(
                        uploaded_file.stream,
                        analysis_type=file_analysis_type
                    )
                else:
                    flash('No file uploaded for encryption detection', 'error')

            elif analysis_type == "steganography":
                media_file = request.files.get('media_file')
                media_type = request.form.get('media_type', 'auto')

                if media_file and media_file.filename != '':
                    results = encryption_handler.detect_steganography(
                        media_file.stream,
                        media_type=media_type
                    )
                else:
                    flash('No media file uploaded for steganography analysis', 'error')

            elif analysis_type == "rootkit_detection":
                analysis_scope = request.form.get('analysis_scope', 'full')
                # In a real implementation, you would process system data here
                results = encryption_handler.detect_rootkits(
                    {},  # Placeholder for real system data
                    analysis_scope=analysis_scope
                )

            elif analysis_type == "fileless_malware":
                # In a real implementation, you would process memory dumps here
                results = encryption_handler.detect_fileless_malware(
                    None,  # Placeholder for memory dump
                    None   # Placeholder for process list
                )

            if results and not results.get('error'):
                flash(f'{analysis_type.replace("_", " ").title()} analysis completed!', 'success')
            elif results and results.get('error'):
                flash(f'Analysis error: {results["error"]}', 'error')

        except Exception as e:
            logging.error(f"Encryption/Evasion analysis error: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')
            results = {'error': str(e)}

    return render_template(
        "encryption_evasion.html",
        results=results,
        analysis_type=analysis_type
    )

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
