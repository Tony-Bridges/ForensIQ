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

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

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
    # Fallback to SQLite for development
    database_url = "sqlite:///instance/forensics.db"
    
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

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

# Import models after db initialization
from models import User, Investigation, InvestigationUser, InvestigationComment, AuditLog, Evidence, ChainOfCustody, DeviceAcquisitionRecord, Analysis

def initialize_database():
    """Initialize the database tables and create admin user."""
    try:
        # Ensure instance directory exists with proper permissions
        os.makedirs('instance', exist_ok=True)
        os.chmod('instance', 0o755)
        
        # Check if database file exists and create if needed
        db_path = 'instance/forensics.db'
        if not os.path.exists(db_path):
            # Create empty database file with proper permissions
            open(db_path, 'a').close()
            os.chmod(db_path, 0o644)
        
        db.create_all()

        # Create default admin user if none exists
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
            db.session.commit()
            print("✅ Default admin user created: admin/admin123")

        print("✅ Database initialized successfully")
        print(f"📊 Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        return True
    except Exception as e:
        print(f"❌ Database initialization error: {str(e)}")
        logging.error(f"Database error: {str(e)}")
        # Try to fix common issues
        try:
            # Drop and recreate tables if there are schema issues
            db.drop_all()
            db.create_all()
            print("✅ Database schema rebuilt")
            return True
        except Exception as e2:
            print(f"❌ Failed to rebuild database: {str(e2)}")
            logging.error(f"Database rebuild error: {str(e2)}")
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

# Real forensics routes
@app.route("/real_forensics/autopsy", methods=["GET", "POST"])
@require_permission('analyze_evidence')
def autopsy_analysis():
    """Autopsy integration interface."""
    if request.method == "POST":
        action = request.form.get("action")

        if action == "create_case":
            case_name = request.form.get("case_name")
            investigator = request.form.get("investigator")
            description = request.form.get("description", "")

            result = autopsy_handler.create_case(case_name, investigator, description)

        elif action == "add_data_source":
            case_name = request.form.get("case_name")
            data_source_path = request.form.get("data_source_path")
            source_type = request.form.get("source_type", "disk_image")

            result = autopsy_handler.add_data_source(case_name, data_source_path, source_type)

        elif action == "run_ingest":
            case_name = request.form.get("case_name")
            modules = request.form.getlist("modules")

            result = autopsy_handler.run_ingest_modules(case_name, modules)

        else:
            result = {"success": False, "error": "Invalid action"}

        # Log the action
        AuditLog.create_log('autopsy_analysis', 'analysis', None, 
                          f"Autopsy {action} performed")

        return render_template("autopsy_analysis.html", result=result)

    return render_template("autopsy_analysis.html")

@app.route("/real_forensics/volatility", methods=["GET", "POST"])
@require_permission('analyze_evidence')
def volatility_analysis():
    """Volatility memory analysis interface."""
    if request.method == "POST":
        dump_path = request.form.get("dump_path")
        profile = request.form.get("profile")

        result = volatility_handler.analyze_memory_dump(dump_path, profile)

        # Log the action
        AuditLog.create_log('volatility_analysis', 'analysis', None, 
                          f"Memory dump analysis: {dump_path}")

        return render_template("volatility_analysis.html", result=result)

    return render_template("volatility_analysis.html")

@app.route("/real_forensics/sleuthkit", methods=["GET", "POST"])
@require_permission('analyze_evidence')
def sleuthkit_analysis():
    """Sleuth Kit file system analysis interface."""
    if request.method == "POST":
        image_path = request.form.get("image_path")
        fs_type = request.form.get("fs_type", "auto")

        result = sleuthkit_handler.analyze_file_system(image_path, fs_type)

        # Log the action
        AuditLog.create_log('sleuthkit_analysis', 'analysis', None, 
                          f"File system analysis: {image_path}")

        return render_template("sleuthkit_analysis.html", result=result)

    return render_template("sleuthkit_analysis.html")

@app.route("/real_forensics/memory_acquisition", methods=["GET", "POST"])
@require_permission('create_evidence')
def memory_acquisition():
    """Live memory acquisition interface."""
    if request.method == "POST":
        target_system = {
            "hostname": request.form.get("hostname"),
            "os": request.form.get("os_type"),
            "ip_address": request.form.get("ip_address")
        }
        output_path = request.form.get("output_path")
        tool = request.form.get("tool", "auto")

        result = memory_acquisition_handler.acquire_memory(target_system, output_path, tool)

        # Log the action
        AuditLog.create_log('memory_acquisition', 'acquisition', None, 
                          f"Memory acquired from {target_system['hostname']}")

        return render_template("memory_acquisition.html", result=result)

    return render_template("memory_acquisition.html")

@app.route("/real_forensics/network_capture", methods=["GET", "POST"])
@require_permission('create_evidence')
def network_capture():
    """Network packet capture interface."""
    if request.method == "POST":
        action = request.form.get("action")

        if action == "live_capture":
            interface = request.form.get("interface", "eth0")
            duration = int(request.form.get("duration", 300))
            filter_expr = request.form.get("filter_expr", "")

            result = network_analysis_handler.live_capture(interface, duration, filter_expr)

        elif action == "analyze_pcap":
            pcap_path = request.form.get("pcap_path")
            result = network_analysis_handler.analyze_pcap_file(pcap_path)

        else:
            result = {"success": False, "error": "Invalid action"}

        # Log the action
        AuditLog.create_log('network_analysis', 'analysis', None, 
                          f"Network {action} performed")

        return render_template("network_capture.html", result=result)

    return render_template("network_capture.html")

@app.route("/real_forensics/mobile_acquisition", methods=["GET", "POST"])
@require_permission('create_evidence')
def mobile_physical_acquisition():
    """Physical mobile device acquisition interface."""
    if request.method == "POST":
        device_info = {
            "type": request.form.get("device_type"),
            "model": request.form.get("device_model"),
            "os_version": request.form.get("os_version")
        }
        method = request.form.get("acquisition_method", "physical")

        result = mobile_acquisition_handler.physical_acquisition(device_info, method)

        # Log the action
        AuditLog.create_log('mobile_acquisition', 'acquisition', None, 
                          f"Mobile device acquisition: {device_info['type']}")

        return render_template("mobile_physical_acquisition.html", result=result)

    return render_template("mobile_physical_acquisition.html")

@app.route("/real_forensics/cloud_preservation", methods=["GET", "POST"])
@require_permission('create_evidence')
def cloud_preservation():
    """Cloud evidence preservation interface."""
    if request.method == "POST":
        provider = request.form.get("provider")
        evidence_type = request.form.get("evidence_type")
        preservation_request = {
            "account_id": request.form.get("account_id"),
            "regions": request.form.getlist("regions"),
            "resource_groups": request.form.getlist("resource_groups")
        }

        result = cloud_preservation_handler.preserve_cloud_evidence(
            provider, evidence_type, preservation_request)

        # Log the action
        AuditLog.create_log('cloud_preservation', 'preservation', None, 
                          f"Cloud evidence preserved: {provider}")

        return render_template("cloud_preservation.html", result=result)

    return render_template("cloud_preservation.html")

# Investigation management routes
@app.route("/investigations", methods=["GET", "POST"])
@require_permission('investigations_create')
def investigations():
    """Investigation management."""
    if request.method == "POST":
        case_number = request.form.get("case_number")
        title = request.form.get("title")
        description = request.form.get("description")
        priority = request.form.get("priority", "medium")

        investigation = Investigation(
            case_number=case_number,
            title=title,
            description=description,
            priority=priority,
            created_by=session['user_id']
        )

        db.session.add(investigation)
        db.session.commit()

        # Log investigation creation
        AuditLog.create_log('investigation_created', 'investigation', investigation.id, 
                          f"Investigation {case_number} created")

        flash('Investigation created successfully!', 'success')
        return redirect(url_for('investigations'))

    # Get user's investigations based on role
    user = User.query.get(session['user_id'])
    if user.role == 'admin':
        investigations = Investigation.query.all()
    else:
        investigations = Investigation.query.join(InvestigationUser).filter(
            InvestigationUser.user_id == session['user_id']
        ).all()

    return render_template("investigations.html", investigations=investigations)

@app.route("/investigation/<int:investigation_id>")
@require_auth
def investigation_detail(investigation_id):
    """Investigation detail view."""
    investigation = Investigation.query.get_or_404(investigation_id)

    # Check access permissions
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        assignment = InvestigationUser.query.filter_by(
            investigation_id=investigation_id, 
            user_id=session['user_id']
        ).first()
        if not assignment:
            flash('Access denied to this investigation.', 'error')
            return redirect(url_for('investigations'))

    evidence_items = Evidence.query.filter_by(investigation_id=investigation_id).all()
    comments = InvestigationComment.query.filter_by(investigation_id=investigation_id).all()

    return render_template("investigation_detail.html", 
                         investigation=investigation,
                         evidence_items=evidence_items,
                         comments=comments)

# Report generation routes
@app.route("/generate_report/<int:investigation_id>", methods=["GET", "POST"])
@require_permission('generate_reports')
def generate_investigation_report(investigation_id):
    """Generate investigation report."""
    if request.method == "POST":
        report_type = request.form.get("report_type", "comprehensive")
        output_format = request.form.get("output_format", "pdf")

        result = report_generator.generate_report(investigation_id, report_type, output_format)

        if result["success"]:
            # Log report generation
            AuditLog.create_log('report_generated', 'report', investigation_id, 
                              f"Report generated: {report_type}")

            flash('Report generated successfully!', 'success')
            return redirect(url_for('download_report', filename=os.path.basename(result["report_file"])))
        else:
            flash(f'Report generation failed: {result["error"]}', 'error')

    investigation = Investigation.query.get_or_404(investigation_id)
    return render_template("generate_report.html", investigation=investigation)

@app.route("/download_report/<filename>")
@require_auth
def download_report(filename):
    """Download generated report."""
    from flask import send_file
    filepath = os.path.join("/tmp", filename)

    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        flash('Report file not found.', 'error')
        return redirect(url_for('reports'))

@app.route("/schedule_report", methods=["POST"])
@require_permission('generate_reports')
def schedule_report():
    """Schedule automated report generation."""
    investigation_id = request.form.get("investigation_id")
    schedule_config = {
        "report_type": request.form.get("report_type", "comprehensive"),
        "output_format": request.form.get("output_format", "pdf"),
        "frequency": request.form.get("frequency", "weekly"),
        "recipients": request.form.get("recipients", "").split(",")
    }

    result = report_scheduler.schedule_report(investigation_id, schedule_config)

    if result["success"]:
        flash('Report scheduled successfully!', 'success')
    else:
        flash(f'Scheduling failed: {result["error"]}', 'error')

    return redirect(url_for('investigations'))


blockchain_handler = BlockchainForensics()
mobile_iot_handler = MobileIoTForensics()
encryption_handler = EncryptionAnalysis()
network_handler = NetworkAnalysis()
timeline_handler = TimelineIntelligence()
live_forensics_handler = LiveRemoteForensics()
sandbox_handler = SandboxAnalysis()
threat_intel_handler = ThreatIntelligence()
search_handler = SearchRegex()

@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/")
@require_auth
def authenticated_index():
    return redirect(url_for('dashboard'))

@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    """File analysis interface with real forensic capabilities."""
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("Please select a file to analyze.", "error")
            return redirect(request.url)

        try:
            from core_forensics_engine import CoreForensicsEngine
            from forensic_tool_integrations import ForensicToolIntegrations

            # Initialize forensic engines
            core_engine = CoreForensicsEngine()
            tool_integrations = ForensicToolIntegrations()

            # Calculate file hash first
            file_hash = calculate_hash(file, "sha256")
            file_metadata = get_file_metadata(file)

            # Create evidence record
            evidence = Evidence(
                filename=file.filename,
                file_size=file_metadata["size"],
                file_hash=file_hash,
                file_type=file_metadata["mime_type"],
                investigator_id=session.get("user_id", 1)
            )
            db.session.add(evidence)

            # Perform comprehensive forensic analysis
            file.seek(0)  # Reset file pointer

            analysis_results = {
                'timestamp': datetime.utcnow().isoformat(),
                'file_metadata': file_metadata,
                'core_analysis': core_engine.analyze_file_structure(file),
                'strings_analysis': tool_integrations.analyze_with_strings(file),
                'file_type_analysis': tool_integrations.analyze_with_file_command(file),
                'hash_analysis': tool_integrations.calculate_hashes(file),
                'hexdump_analysis': tool_integrations.create_hexdump(file, length=512),
                'pattern_search': tool_integrations.search_patterns(file, [
                    'password', 'admin', 'malware', 'virus', 'trojan',
                    'http://', 'https://', 'cmd.exe', 'powershell'
                ])
            }

            # Additional analysis based on file type
            if file_metadata["mime_type"] == "application/x-sqlite3":
                file.seek(0)
                analysis_results['sqlite_analysis'] = tool_integrations.analyze_sqlite_database(file)

            # Create analysis record
            analysis = Analysis(
                evidence_id=evidence.id,
                analysis_type="comprehensive_file_analysis",
                analysis_results=json.dumps(analysis_results, default=str)
            )
            db.session.add(analysis)

            # Create chain of custody entry
            custody = ChainOfCustody(
                evidence=evidence,
                action="Comprehensive file analysis",
                details=f"File {file.filename} analyzed with multiple forensic tools"
            )
            db.session.add(custody)
            db.session.commit()

            return redirect(url_for("generate_report", evidence_id=evidence.id))

        except Exception as e:
            db.session.rollback()
            flash(f"Analysis failed: {str(e)}", "error")
            logging.error(f"Analysis error: {str(e)}")
            return redirect(request.url)

    return render_template("analysis.html")

@app.route("/memory_analysis", methods=["GET", "POST"])
def memory_analysis():
    """Memory analysis interface with real forensic capabilities."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "dump_analysis":
            memory_file = request.files.get("memory_file")
            if memory_file:
                from core_forensics_engine import CoreForensicsEngine
                from forensic_tool_integrations import ForensicToolIntegrations

                core_engine = CoreForensicsEngine()
                tool_integrations = ForensicToolIntegrations()

                # Perform real memory dump analysis
                results = {
                    'memory_analysis': core_engine.analyze_memory_dump(memory_file),
                    'strings_from_memory': tool_integrations.analyze_with_strings(memory_file, min_length=6),
                    'file_type': tool_integrations.analyze_with_file_command(memory_file),
                    'memory_hashes': tool_integrations.calculate_hashes(memory_file),
                    'suspicious_patterns': tool_integrations.search_patterns(memory_file, [
                        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                        'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
                        'cmd.exe', 'powershell.exe', 'malware', 'backdoor'
                    ])
                }
            else:
                results = {"error": "No memory dump file provided"}

        elif analysis_type == "process_analysis":
            # Real process analysis using available system tools
            from forensic_tool_integrations import ForensicToolIntegrations
            tool_integrations = ForensicToolIntegrations()

            # Create a simple script to analyze running processes
            process_script = '''
import psutil
import json
import sys

try:
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'status', 'create_time']):
        try:
            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'ppid': proc.info['ppid'],
                'status': proc.info['status'],
                'create_time': proc.info['create_time']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print(json.dumps({
        'total_processes': len(processes),
        'processes': processes[:50],  # Limit output
        'analysis': 'Real process enumeration completed'
    }))
except Exception as e:
    print(json.dumps({'error': str(e)}))
'''

            # Use empty file as placeholder for script execution
            import tempfile
            with tempfile.NamedTemporaryFile() as dummy_file:
                script_result = tool_integrations.run_custom_forensic_script(
                    process_script, dummy_file, 'python'
                )

            if script_result.get('return_code') == 0:
                try:
                    results = json.loads(script_result['output'])
                except:
                    results = {
                        'error': 'Failed to parse process analysis results',
                        'raw_output': script_result['output']
                    }
            else:
                results = {
                    'error': 'Process analysis script failed',
                    'script_error': script_result.get('error', 'Unknown error')
                }

        elif analysis_type == "volatility_analysis":
            memory_file = request.files.get("memory_file")
            if memory_file:
                from core_forensics_engine import CoreForensicsEngine
                core_engine = CoreForensicsEngine()

                # Perform Volatility-style analysis
                results = core_engine.analyze_memory_dump(memory_file)
            else:
                results = {"error": "No memory dump file provided for Volatility analysis"}

        return render_template("memory_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("memory_analysis.html")

@app.route("/devices")
def detect_devices():
    """Detect and list connected mobile devices."""
    devices = device_handler.detect_devices()
    return render_template("device_acquisition.html", devices=devices)

@app.route("/network")
def network_scan():
    """Perform network scanning."""
    scanner = NetworkScanner()
    devices = scanner.scan_network()
    return render_template("network_scan.html", devices=devices)

@app.route("/acquire_device", methods=["POST"])
def acquire_device():
    """Handle device acquisition request."""
    device_id = request.form.get("device_id")
    device_type = request.form.get("device_type")
    acquisition_type = request.form.get("acquisition_type", "logical")
    features = request.form.getlist("features")

    if not all([device_id, device_type]):
        return jsonify({"error": "Missing device information"}), 400

    # Perform device acquisition
    acquisition_data = device_handler.acquire_device_data(
        device_id, device_type, acquisition_type
    )

    if "error" in acquisition_data:
        return jsonify(acquisition_data), 400

    # Create evidence record
    evidence = Evidence(
        filename=f"{device_type}_{device_id}_{acquisition_type}",
        md5_hash="N/A",  # Device acquisitions don't have file hashes
        sha256_hash="N/A",
        file_metadata=json.dumps({"device_type": device_type, "device_id": device_id}),
        analysis_results=json.dumps(acquisition_data)
    )
    db.session.add(evidence)

    # Create device acquisition record
    device_acquisition = DeviceAcquisitionRecord(
        evidence=evidence,
        device_type=device_type,
        device_id=device_id,
        acquisition_type=acquisition_type,
        acquisition_data=json.dumps(acquisition_data)
    )
    db.session.add(device_acquisition)

    # Create chain of custody entry
    custody = ChainOfCustody(
        evidence=evidence,
        action=f"{device_type.upper()} device acquisition",
        details=f"Performed {acquisition_type} acquisition"
    )
    db.session.add(custody)
    db.session.commit()

    return redirect(url_for("generate_report", evidence_id=evidence.id))

# AI-Powered Intelligence Routes
@app.route("/ai_analysis", methods=["GET", "POST"])
def ai_analysis():
    """AI-powered analysis interface."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")
        data_source = request.form.get("data_source")

        if analysis_type == "anomaly_detection":
            # Mock system data for demonstration
            system_data = {
                "processes": [{"name": "suspicious.exe", "pid": 1234}],
                "network_connections": [{"dest": "192.168.1.100", "port": 445}],
                "network_traffic": [{"destination": "malware.com", "packets": 1000}]
            }
            results = ai_handler.detect_anomalies(system_data)
        elif analysis_type == "malware_classification":
            file_data = request.files.get("file")
            if file_data:
                results = ai_handler.classify_malware(file_data, "behavioral")
            else:
                results = {"error": "No file provided"}
        elif analysis_type == "entity_extraction":
            text_content = request.form.get("text_content", "")
            query_context = request.form.get("query_context")
            results = ai_handler.extract_entities_nlp(text_content, query_context)
        elif analysis_type == "media_verification":
            media_file = request.files.get("media_file")
            media_type = request.form.get("media_type", "image")
            if media_file:
                results = ai_handler.verify_media_authenticity(media_file, media_type)
            else:
                results = {"error": "No media file provided"}
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("ai_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("ai_analysis.html")

@app.route("/cloud_forensics", methods=["GET", "POST"])
def cloud_forensics():
    """Cloud forensics interface."""
    if request.method == "POST":
        cloud_provider = request.form.get("cloud_provider")
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "cloud_acquisition":
            credentials = {"access_key": "demo", "secret_key": "demo"}
            resource_types = request.form.getlist("resource_types")
            results = cloud_handler.acquire_cloud_data(cloud_provider, credentials, resource_types)
        elif analysis_type == "container_analysis":
            container_runtime = request.form.get("container_runtime", "docker")
            if container_runtime == "kubernetes":
                results = cloud_handler.analyze_kubernetes_pods()
            else:
                results = cloud_handler.analyze_docker_containers()
        elif analysis_type == "serverless_trace":
            function_names = request.form.get("function_names", "").split(",")
            results = cloud_handler.trace_serverless_functions(cloud_provider, function_names)
        elif analysis_type == "vm_analysis":
            vm_format = request.form.get("vm_format")
            disk_path = request.form.get("disk_path", "/demo/vm.vmdk")
            results = cloud_handler.analyze_vm_disks(vm_format, disk_path)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("cloud_forensics.html", results=results, analysis_type=analysis_type)

    return render_template("cloud_forensics.html")

@app.route("/blockchain_analysis", methods=["GET", "POST"])
def blockchain_analysis():
    """Blockchain and cryptocurrency forensics."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "wallet_trace":
            wallet_address = request.form.get("wallet_address")
            blockchain = request.form.get("blockchain", "bitcoin")
            depth = int(request.form.get("depth", 3))
            results = blockchain_handler.trace_wallet_transactions(wallet_address, blockchain, depth)
        elif analysis_type == "smart_contract":
            contract_address = request.form.get("contract_address")
            blockchain = request.form.get("blockchain", "ethereum")
            results = blockchain_handler.analyze_smart_contract(contract_address, blockchain)
        elif analysis_type == "nft_verification":
            token_id = request.form.get("token_id")
            contract_address = request.form.get("contract_address")
            blockchain = request.form.get("blockchain", "ethereum")
            results = blockchain_handler.verify_nft_authenticity(token_id, contract_address, blockchain)
        elif analysis_type == "defi_analysis":
            wallet_address = request.form.get("wallet_address")
            blockchain = request.form.get("blockchain", "ethereum")
            results = blockchain_handler.analyze_defi_interactions(wallet_address, blockchain)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("blockchain_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("blockchain_analysis.html")

@app.route("/mobile_iot_forensics", methods=["GET", "POST"])
def mobile_iot_forensics():
    """Mobile and IoT device forensics."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "mobile_acquisition":
            device_info = {
                "type": request.form.get("device_type"),
                "os": request.form.get("device_os"),
                "model": request.form.get("device_model", "Unknown")
            }
            acquisition_type = request.form.get("acquisition_type", "logical")
            results = mobile_iot_handler.advanced_mobile_acquisition(device_info, acquisition_type)
        elif analysis_type == "iot_analysis":
            device_info = {
                "type": request.form.get("iot_device_type"),
                "manufacturer": request.form.get("manufacturer", "Unknown"),
                "model": request.form.get("model", "Unknown")
            }
            data_sources = request.form.getlist("data_sources")
            results = mobile_iot_handler.analyze_iot_device(device_info, data_sources)
        elif analysis_type == "vehicle_telematics":
            vehicle_info = {
                "make": request.form.get("vehicle_make"),
                "model": request.form.get("vehicle_model"),
                "year": request.form.get("vehicle_year")
            }
            data_types = request.form.getlist("data_types")
            results = mobile_iot_handler.extract_vehicle_telematics(vehicle_info, data_types)
        elif analysis_type == "social_media":
            device_data = {"apps": {"whatsapp": {}, "telegram": {}, "signal": {}}}
            platforms = request.form.getlist("platforms")
            results = mobile_iot_handler.extract_social_media_artifacts(device_data, platforms)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("mobile_iot_forensics.html", results=results, analysis_type=analysis_type)

    return render_template("mobile_iot_forensics.html")

@app.route("/encryption_analysis", methods=["GET", "POST"])
def encryption_analysis():
    """Encryption and steganography analysis."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "encryption_detection":
            uploaded_file = request.files.get("file")
            file_analysis_type = request.form.get("file_analysis_type", "file")
            if uploaded_file:
                results = encryption_handler.detect_encrypted_volumes(uploaded_file, file_analysis_type)
            else:
                results = {"error": "No file provided"}
        elif analysis_type == "steganography":
            media_file = request.files.get("media_file")
            media_type = request.form.get("media_type", "auto")
            if media_file:
                results = encryption_handler.detect_steganography(media_file, media_type)
            else:
                results = {"error": "No media file provided"}
        elif analysis_type == "rootkit_detection":
            # Mock system data for demonstration
            system_data = {
                "memory_dump": "mock_memory_data",
                "registry": "mock_registry_data",
                "filesystem": "mock_filesystem_data"
            }
            analysis_scope = request.form.get("analysis_scope", "full")
            results = encryption_handler.detect_rootkits(system_data, analysis_scope)
        elif analysis_type == "fileless_malware":
            # Mock memory dump and process list
            memory_dump = "mock_memory_dump_data"
            process_list = [{"pid": 1234, "name": "explorer.exe"}]
            results = encryption_handler.detect_fileless_malware(memory_dump, process_list)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("encryption_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("encryption_analysis.html")

@app.route("/network_analysis", methods=["GET", "POST"])
def network_analysis():
    """Network analysis and PCAP forensics."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "pcap_analysis":
            uploaded_file = request.files.get("pcap_file")
            analysis_options = request.form.getlist("analysis_options")
            if uploaded_file:
                results = network_handler.analyze_pcap(uploaded_file, analysis_options)
            else:
                results = {"error": "No PCAP file provided"}
        elif analysis_type == "browser_history":
            browser_type = request.form.get("browser_type", "chrome")
            # Mock browser history data
            history_data = {"visits": [], "downloads": [], "cookies": []}
            results = network_handler.analyze_browser_history(browser_type, history_data)
        elif analysis_type == "email_analysis":
            email_client = request.form.get("email_client", "outlook")
            # Mock email data
            email_data = {"messages": [], "attachments": [], "contacts": []}
            results = network_handler.analyze_email_artifacts(email_data, email_client)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("network_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("network_analysis.html")

@app.route("/timeline_analysis", methods=["GET", "POST"])
def timeline_analysis():
    """Timeline intelligence and correlation."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "timeline_correlation":
            # Mock data sources
            data_sources = {
                "filesystem": {"events": [{"timestamp": "2024-01-15T10:30:00Z", "type": "file_creation", "description": "File created"}]},
                "registry": {"events": [{"timestamp": "2024-01-15T10:31:00Z", "type": "registry_modification", "description": "Registry key modified"}]},
                "network": {"events": [{"timestamp": "2024-01-15T10:32:00Z", "type": "network_connection", "description": "Connection established"}]}
            }
            results = timeline_handler.correlate_timeline(data_sources)
        elif analysis_type == "attack_chain":
            # Mock timeline events
            timeline_events = [
                {"timestamp": "2024-01-15T10:30:00Z", "event_type": "process_execution", "description": "Suspicious process started"},
                {"timestamp": "2024-01-15T10:31:00Z", "event_type": "network_connection", "description": "Outbound connection"}
            ]
            results = timeline_handler.analyze_attack_chain(timeline_events)
        elif analysis_type == "user_activity":
            user_id = request.form.get("user_id", "user123")
            # Mock user events
            user_events = [
                {"timestamp": "2024-01-15T08:00:00Z", "event_type": "user_login", "description": "User logged in"},
                {"timestamp": "2024-01-15T08:05:00Z", "event_type": "file_access", "description": "File accessed"}
            ]
            results = timeline_handler.reconstruct_user_activity(user_events, user_id)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("timeline_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("timeline_analysis.html")

@app.route("/live_forensics", methods=["GET", "POST"])
def live_forensics():
    """Live and remote forensics."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        # Mock target system info
        target_info = {
            "hostname": request.form.get("hostname", "target-system"),
            "ip_address": request.form.get("ip_address", "192.168.1.100"),
            "username": request.form.get("username", "admin"),
            "protocol": request.form.get("protocol", "ssh")
        }

        if analysis_type == "memory_acquisition":
            acquisition_method = request.form.get("acquisition_method", "winpmem")
            results = live_forensics_handler.remote_memory_acquisition(target_info, acquisition_method)
        elif analysis_type == "process_analysis":
            analysis_options = request.form.getlist("analysis_options")
            results = live_forensics_handler.live_process_analysis(target_info, analysis_options)
        elif analysis_type == "file_collection":
            collection_rules = {"include_patterns": ["*.log", "*.exe"], "exclude_patterns": ["*.tmp"]}
            results = live_forensics_handler.remote_file_collection(target_info, collection_rules)
        elif analysis_type == "registry_analysis":
            registry_keys = request.form.get("registry_keys", "").split(",") if request.form.get("registry_keys") else None
            results = live_forensics_handler.live_registry_analysis(target_info, registry_keys)
        elif analysis_type == "network_analysis":
            capture_duration = int(request.form.get("capture_duration", 300))
            results = live_forensics_handler.remote_network_analysis(target_info, capture_duration)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("live_forensics.html", results=results, analysis_type=analysis_type)

    return render_template("live_forensics.html")

@app.route("/sandbox_analysis", methods=["GET", "POST"])
def sandbox_analysis():
    """Sandbox analysis and dynamic execution."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "file_execution":
            uploaded_file = request.files.get("file")
            sandbox_config = {
                "environment": request.form.get("environment", "docker"),
                "os": request.form.get("os", "windows_10"),
                "execution_time": int(request.form.get("execution_time", 300)),
                "network_isolation": request.form.get("network_isolation") == "on"
            }
            if uploaded_file:
                results = sandbox_handler.execute_file_analysis(uploaded_file, sandbox_config)
            else:
                results = {"error": "No file provided"}
        elif analysis_type == "behavior_analysis":
            # Mock execution data
            execution_data = {
                "processes": [{"name": "malware.exe", "pid": 1234}],
                "network_activity": [{"destination": "malicious.com", "port": 8080}],
                "file_operations": [{"operation": "create", "path": "C:\\temp\\payload.exe"}]
            }
            results = sandbox_handler.analyze_suspicious_behavior(execution_data)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("sandbox_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("sandbox_analysis.html")

@app.route("/threat_intelligence", methods=["GET", "POST"])
def threat_intelligence():
    """Threat intelligence integration."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "ioc_check":
            indicators = request.form.get("indicators", "").split(",")
            indicators = [i.strip() for i in indicators if i.strip()]
            threat_sources = request.form.getlist("threat_sources")
            if indicators:
                results = threat_intel_handler.check_threat_intelligence(indicators, threat_sources)
            else:
                results = {"error": "No indicators provided"}
        elif analysis_type == "yara_scan":
            uploaded_file = request.files.get("file")
            rule_categories = request.form.getlist("rule_categories")
            if uploaded_file:
                results = threat_intel_handler.scan_with_yara_rules(uploaded_file, rule_categories)
            else:
                results = {"error": "No file provided"}
        elif analysis_type == "custom_indicators":
            # Mock analysis data
            analysis_data = {
                "file_analysis": {"sha256_hash": "abc123def456"},
                "network_analysis": {"suspicious_domains": ["malicious.com"]},
                "registry_analysis": {"suspicious_keys": ["HKLM\\Software\\Malware"]}
            }
            indicator_types = request.form.getlist("indicator_types")
            results = threat_intel_handler.create_custom_indicators(analysis_data, indicator_types)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("threat_intelligence.html", results=results, analysis_type=analysis_type)

    return render_template("threat_intelligence.html")

@app.route("/search_analysis", methods=["GET", "POST"])
def search_analysis():
    """Search and regex matching capabilities."""
    if request.method == "POST":
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "disk_scan":
            disk_image_path = request.form.get("disk_image_path", "/evidence/disk.img")
            patterns = {
                "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
            }
            scan_options = {
                "include_deleted": request.form.get("include_deleted") == "on",
                "scan_slack_space": request.form.get("scan_slack_space") == "on"
            }
            results = search_handler.deep_scan_disk_image(disk_image_path, patterns, scan_options)
        elif analysis_type == "memory_search":
            memory_dump_path = request.form.get("memory_dump_path", "/evidence/memory.dmp")
            patterns = {
                "password": r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'"]+)',
                "url": r'https?://[^\s<>"{}|\\^`\[\]]+'
            }
            results = search_handler.search_memory_dump(memory_dump_path, patterns)
        elif analysis_type == "pii_search":
            data_source = request.form.get("data_source", "/evidence/files")
            scan_depth = request.form.get("scan_depth", "standard")
            results = search_handler.search_pii_data(data_source, scan_depth)
        elif analysis_type == "credential_search":
            data_source = request.form.get("data_source", "/evidence/files")
            credential_types = request.form.getlist("credential_types")
            results = search_handler.search_credentials(data_source, credential_types)
        elif analysis_type == "custom_regex":
            data_source = request.form.get("data_source", "/evidence/files")
            custom_patterns = {}
            pattern_name = request.form.get("pattern_name", "custom_pattern")
            pattern_regex = request.form.get("pattern_regex", r'\b[A-Z0-9]{10,}\b')
            custom_patterns[pattern_name] = pattern_regex
            results = search_handler.custom_regex_search(data_source, custom_patterns)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("search_analysis.html", results=results, analysis_type=analysis_type)

    return render_template("search_analysis.html")

@app.route("/dashboard")
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

    # Mock data for dashboard metrics
    dashboard_data = {
        'total_evidence': total_evidence,
        'active_investigations': 3,
        'ai_findings': 15,
        'threat_matches': 8,
        'system_health': {
            'cpu_usage': 45,
            'memory_usage': 67,
            'disk_usage': 32,
            'network_activity': 'Normal'
        },
        'recent_alerts': [
            {'type': 'warning', 'message': 'Suspicious network activity detected', 'timestamp': '2 min ago'},
            {'type': 'info', 'message': 'Evidence analysis completed', 'timestamp': '5 min ago'},
            {'type': 'success', 'message': 'Threat intelligence updated', 'timestamp': '10 min ago'}
        ]
    }

    return render_template("dashboard.html", evidence_list=recent_evidence, **dashboard_data)

@app.route("/reports")
def reports():
    """Reports and timeline page."""
    try:
        investigations = Evidence.query.all()
    except Exception as e:
        logging.error(f"Reports database error: {str(e)}")
        investigations = []

    return render_template("reports.html", investigations=investigations, evidence_items=investigations)

@app.route("/settings")
def settings():
    """Settings and configuration page."""
    return render_template("settings.html")

@app.route("/admin")
def admin():
    """Admin portal page."""
    try:
        # Get system statistics with error handling
        total_users = User.query.count() if db.session.query(User).first() else 0
        total_evidence = Evidence.query.count() if db.session.query(Evidence).first() else 0
        total_investigations = Investigation.query.count() if db.session.query(Investigation).first() else 0

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

@app.route("/api/generate-report", methods=["POST"])
def api_generate_report():
    """API endpoint for generating reports."""
    try:
        data = request.get_json()
        report_type = data.get('report_type', 'comprehensive')
        output_format = data.get('output_format', 'pdf')
        investigation_id = data.get('investigation_id')
        sections = data.get('sections', [])

        # Mock report generation
        report_data = {
            'success': True,
            'report_id': f"RPT_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'download_url': f"/download/report_{report_type}_{output_format}.{output_format}",
            'size': '2.4 MB',
            'generated_at': datetime.now().isoformat()
        }

        return jsonify(report_data)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route("/report/<int:evidence_id>")
def generate_report(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)
    custody_chain = ChainOfCustody.query.filter_by(evidence_id=evidence_id).all()

    return render_template(
        "report.html",
        evidence=evidence,
        custody_chain=custody_chain
    )

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("500.html"), 500

if __name__ == "__main__":
    # Initialize database when running directly
    with app.app_context():
        initialize_database()
    
    app.run(host="0.0.0.0", port=5000, debug=True)