
#!/usr/bin/env python3
"""
Database migration script for ForensIQ
Fixes schema issues and adds missing columns
"""

import os
import sys
from app import app, db
from models import User, Evidence, Investigation, ChainOfCustody
from werkzeug.security import generate_password_hash
import logging

def migrate_database():
    """Migrate database schema and fix issues."""
    with app.app_context():
        try:
            print("🔄 Starting database migration...")
            
            # Drop all tables and recreate (for development)
            print("📋 Dropping existing tables...")
            db.drop_all()
            
            print("🏗️  Creating new tables...")
            db.create_all()
            
            # Create default admin user
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
            
            print("✅ Database migration completed successfully!")
            print("👤 Users created:")
            print("   - admin/admin123 (Administrator)")
            print("   - investigator/investigator123 (Investigator)")
            print("   - viewer/viewer123 (Viewer)")
            
            return True
            
        except Exception as e:
            print(f"❌ Migration failed: {str(e)}")
            db.session.rollback()
            return False

if __name__ == "__main__":
    migrate_database()
