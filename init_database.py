
#!/usr/bin/env python3
"""
Database initialization script for ForensIQ
Creates all tables and sets up initial data
"""

import os
import sys
from app import app, db
from models import User, Evidence, Investigation, ChainOfCustody, AuditLog
from werkzeug.security import generate_password_hash
import logging

def init_database():
    """Initialize database with tables and default users."""
    with app.app_context():
        try:
            print("🔄 Initializing database...")
            
            # Create all tables
            print("🏗️  Creating database tables...")
            db.create_all()
            
            # Check if admin user already exists
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                print("👤 Creating default admin user...")
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
                
                print("✅ Database initialized successfully!")
                print("👤 Default users created:")
                print("   - admin/admin123 (Administrator)")
                print("   - investigator/investigator123 (Investigator)")
                print("   - viewer/viewer123 (Viewer)")
            else:
                print("✅ Database already initialized with admin user")
            
            return True
            
        except Exception as e:
            print(f"❌ Database initialization failed: {str(e)}")
            db.session.rollback()
            return False

if __name__ == "__main__":
    if init_database():
        print("🎉 Database setup complete!")
    else:
        print("💥 Database setup failed!")
        sys.exit(1)
