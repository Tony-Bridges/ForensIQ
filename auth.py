import functools
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import session, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Investigation, InvestigationUser, InvestigationComment, AuditLog
import pyotp
import qrcode
import io
import base64
from functools import wraps

class Role:
    ADMIN = 'admin'
    INVESTIGATOR = 'investigator'
    VIEWER = 'viewer'

    @classmethod
    def get_permissions(cls, role):
        permissions = {
            cls.ADMIN: [
                'view_all', 'edit_all', 'delete_all', 'manage_users', 
                'system_settings', 'audit_logs', 'investigations_manage'
            ],
            cls.INVESTIGATOR: [
                'view_assigned', 'edit_assigned', 'create_evidence',
                'analyze_evidence', 'generate_reports', 'investigations_create'
            ],
            cls.VIEWER: [
                'view_assigned', 'view_reports'
            ]
        }
        return permissions.get(role, [])

class AuthManager:
    @staticmethod
    def create_user(username, email, password, role='viewer'):
        """Create a new user account."""
        if User.query.filter_by(username=username).first():
            return False, "Username already exists"
        if User.query.filter_by(email=email).first():
            return False, "Email already exists"

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role
        )

        db.session.add(user)
        db.session.commit()

        # Log user creation
        AuditLog.create_log('user_created', 'user', user.id, f"User {username} created")

        return True, user

    @staticmethod
    def authenticate_user(username, password, mfa_token=None):
        """Authenticate user with username/password and optional MFA."""
        user = User.query.filter_by(username=username).first()

        if not user or not user.is_active:
            return False, "Invalid credentials"

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            return False, f"Account locked until {user.locked_until}"

        # Verify password
        if not check_password_hash(user.password_hash, password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
            return False, "Invalid credentials"

        # Check MFA if enabled
        if user.mfa_enabled:
            if not mfa_token:
                return False, "MFA token required"
            if not AuthManager.verify_mfa_token(user, mfa_token):
                return False, "Invalid MFA token"

        # Successful login
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        db.session.commit()

        # Log successful login
        AuditLog.create_log('user_login', 'user', user.id, f"User {username} logged in")

        return True, user

    @staticmethod
    def setup_mfa(user):
        """Set up MFA for a user."""
        secret = pyotp.random_base32()
        user.mfa_secret = secret

        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        user.backup_codes = ','.join(backup_codes)

        db.session.commit()

        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            user.username,
            issuer_name="ForensIQ"
        )

        qr = qrcode.QRCode()
        qr.add_data(totp_uri)
        qr.make()

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()

        return secret, backup_codes, qr_code_data

    @staticmethod
    def verify_mfa_token(user, token):
        """Verify MFA token."""
        if not user.mfa_secret:
            return False

        totp = pyotp.TOTP(user.mfa_secret)

        # Check TOTP token
        if totp.verify(token, valid_window=1):
            return True

        # Check backup codes
        if user.backup_codes:
            backup_codes = user.backup_codes.split(',')
            if token in backup_codes:
                # Remove used backup code
                backup_codes.remove(token)
                user.backup_codes = ','.join(backup_codes)
                db.session.commit()
                return True

        return False

def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))

            user = User.query.get(session['user_id'])
            if not user or permission not in Role.get_permissions(user.role):
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_role(required_role):
    """Decorator to require specific role."""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user = User.query.get(session['user_id'])
            if not user or user.role != required_role:
                flash('Access denied. Insufficient role.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def create_admin_user():
    """Create default admin user if none exists."""
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin_user = User(
            username='admin',
            email='admin@forensiq.local',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created: admin/admin123")

# Extend AuditLog with static method
AuditLog.create_log = staticmethod(lambda action, resource_type=None, resource_id=None, details=None: 
    db.session.add(AuditLog(
        user_id=session.get('user_id'),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )) or db.session.commit()
)