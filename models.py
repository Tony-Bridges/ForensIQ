from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

class Investigation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')  # open, closed, archived
    priority = db.Column(db.String(10), default='medium')  # low, medium, high, critical
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    evidence_items = db.relationship('Evidence', backref='investigation', lazy=True)
    assigned_users = db.relationship('InvestigationUser', back_populates='investigation', lazy=True)
    comments = db.relationship('InvestigationComment', back_populates='investigation', lazy=True)

class InvestigationUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.Integer, db.ForeignKey('investigation.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), default='viewer')  # lead, investigator, viewer
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    investigation = db.relationship('Investigation', back_populates='assigned_users')
    user = db.relationship('User', back_populates='investigation_assignments')

class InvestigationComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.Integer, db.ForeignKey('investigation.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    investigation = db.relationship('Investigation', back_populates='comments')
    user = db.relationship('User', backref='comments')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # MFA fields
    mfa_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text)  # JSON array of backup codes
    
    # Relationships
    investigation_assignments = db.relationship('InvestigationUser', back_populates='user')
    audit_logs = db.relationship('AuditLog', back_populates='user')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='audit_logs')
    
    @classmethod
    def create_log(cls, action, resource_type=None, resource_id=None, details=None, user_id=None, ip_address=None, user_agent=None):
        """Create audit log entry."""
        log = cls(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(log)
        db.session.commit()
        return log

class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    md5_hash = db.Column(db.String(32), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    file_metadata = db.Column(db.Text, nullable=False)
    analysis_results = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    investigation_id = db.Column(db.Integer, db.ForeignKey('investigation.id'), nullable=True)
    custody_chain = db.relationship('ChainOfCustody', backref='evidence', lazy=True)
    device_acquisition = db.relationship('DeviceAcquisitionRecord', backref='evidence', uselist=False)
    annotations = db.relationship('EvidenceAnnotation', backref='evidence', lazy=True)


class EvidenceAnnotation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    annotation = db.Column(db.Text, nullable=False)
    annotation_type = db.Column(db.String(50), default='comment')  # comment, tag, highlight
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ChainOfCustody(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

class DeviceAcquisitionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)  # 'ios' or 'android'
    device_id = db.Column(db.String(255), nullable=False)
    acquisition_type = db.Column(db.String(50), nullable=False)  # 'logical' or 'physical'
    acquisition_data = db.Column(db.Text, nullable=False)  # JSON data of acquired information
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    analysis_type = db.Column(db.String(100), nullable=False)
    analysis_results = db.Column(db.Text, nullable=False)  # JSON data of analysis results
    investigator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    evidence = db.relationship('Evidence', backref='analyses')
    investigator = db.relationship('User', backref='analyses')