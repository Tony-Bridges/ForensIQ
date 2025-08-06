
#!/usr/bin/env python3
"""
Database migration script for ForensIQ
Creates all tables and sets up initial data with comprehensive error handling
"""

import os
import sys
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_and_create_tables():
    """Check if all required tables exist and create them if they don't."""
    db_path = 'forensics.db'
    
    # Table creation SQL
    tables_sql = {
        'user': '''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(80) NOT NULL UNIQUE,
            email VARCHAR(120) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'viewer',
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            mfa_secret VARCHAR(32),
            mfa_enabled BOOLEAN DEFAULT 0,
            backup_codes TEXT
        )''',
        
        'investigation': '''
        CREATE TABLE IF NOT EXISTS investigation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number VARCHAR(50) NOT NULL UNIQUE,
            title VARCHAR(200) NOT NULL,
            description TEXT,
            status VARCHAR(20) DEFAULT 'open',
            priority VARCHAR(10) DEFAULT 'medium',
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES user (id)
        )''',
        
        'investigation_user': '''
        CREATE TABLE IF NOT EXISTS investigation_user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role VARCHAR(20) DEFAULT 'viewer',
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (investigation_id) REFERENCES investigation (id),
            FOREIGN KEY (user_id) REFERENCES user (id)
        )''',
        
        'investigation_comment': '''
        CREATE TABLE IF NOT EXISTS investigation_comment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (investigation_id) REFERENCES investigation (id),
            FOREIGN KEY (user_id) REFERENCES user (id)
        )''',
        
        'audit_log': '''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action VARCHAR(100) NOT NULL,
            resource_type VARCHAR(50),
            resource_id INTEGER,
            details TEXT,
            ip_address VARCHAR(45),
            user_agent VARCHAR(255),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )''',
        
        'evidence': '''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename VARCHAR(255) NOT NULL,
            file_size INTEGER,
            file_hash VARCHAR(64),
            file_type VARCHAR(100),
            md5_hash VARCHAR(32),
            sha256_hash VARCHAR(64),
            file_metadata TEXT,
            analysis_results TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            investigation_id INTEGER,
            investigator_id INTEGER,
            FOREIGN KEY (investigation_id) REFERENCES investigation (id),
            FOREIGN KEY (investigator_id) REFERENCES user (id)
        )''',
        
        'evidence_annotation': '''
        CREATE TABLE IF NOT EXISTS evidence_annotation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            annotation TEXT NOT NULL,
            annotation_type VARCHAR(50) DEFAULT 'comment',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id),
            FOREIGN KEY (user_id) REFERENCES user (id)
        )''',
        
        'chain_of_custody': '''
        CREATE TABLE IF NOT EXISTS chain_of_custody (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            action VARCHAR(255) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id)
        )''',
        
        'device_acquisition_record': '''
        CREATE TABLE IF NOT EXISTS device_acquisition_record (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            device_type VARCHAR(50) NOT NULL,
            device_id VARCHAR(255) NOT NULL,
            acquisition_type VARCHAR(50) NOT NULL,
            acquisition_data TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id)
        )''',
        
        'analysis': '''
        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            analysis_type VARCHAR(100) NOT NULL,
            analysis_results TEXT NOT NULL,
            investigator_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id),
            FOREIGN KEY (investigator_id) REFERENCES user (id)
        )'''
    }
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check which tables already exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        logger.info(f"📊 Existing tables: {existing_tables}")
        
        # Create missing tables
        created_tables = []
        for table_name, create_sql in tables_sql.items():
            if table_name not in existing_tables:
                logger.info(f"📋 Creating table: {table_name}")
                cursor.execute(create_sql)
                created_tables.append(table_name)
            else:
                logger.info(f"✅ Table {table_name} already exists")
        
        if created_tables:
            logger.info(f"✅ Created tables: {created_tables}")
        else:
            logger.info("📊 All tables already exist")
        
        conn.commit()
        conn.close()
        
        return True, created_tables
        
    except Exception as e:
        logger.error(f"❌ Database table creation failed: {str(e)}")
        return False, []

def seed_initial_data():
    """Seed database with initial user data."""
    db_path = 'forensics.db'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT COUNT(*) FROM user WHERE role = 'admin'")
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            logger.info("👤 Creating default users...")
            
            # Create admin user
            admin_password = generate_password_hash('admin123')
            cursor.execute('''
                INSERT INTO user (username, email, password_hash, role, is_active)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', 'admin@forensiq.local', admin_password, 'admin', True))
            
            # Create investigator user
            investigator_password = generate_password_hash('investigator123')
            cursor.execute('''
                INSERT INTO user (username, email, password_hash, role, is_active)
                VALUES (?, ?, ?, ?, ?)
            ''', ('investigator', 'investigator@forensiq.local', investigator_password, 'investigator', True))
            
            # Create viewer user
            viewer_password = generate_password_hash('viewer123')
            cursor.execute('''
                INSERT INTO user (username, email, password_hash, role, is_active)
                VALUES (?, ?, ?, ?, ?)
            ''', ('viewer', 'viewer@forensiq.local', viewer_password, 'viewer', True))
            
            # Create sample investigation
            cursor.execute('''
                INSERT INTO investigation (case_number, title, description, created_by)
                VALUES (?, ?, ?, ?)
            ''', ('CASE-2024-001', 'Sample Investigation', 'Sample forensic investigation for testing', 1))
            
            conn.commit()
            
            logger.info("✅ Default users created:")
            logger.info("   - admin/admin123 (Administrator)")
            logger.info("   - investigator/investigator123 (Investigator)")
            logger.info("   - viewer/viewer123 (Viewer)")
            logger.info("✅ Sample investigation created")
            
        else:
            logger.info("👤 Users already exist, skipping seed data")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"❌ Seeding failed: {str(e)}")
        return False

def verify_database():
    """Verify database structure and data."""
    db_path = 'forensics.db'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        logger.info(f"📊 Database contains {len(tables)} tables: {tables}")
        
        # Check users
        cursor.execute("SELECT username, role FROM user")
        users = cursor.fetchall()
        logger.info(f"👥 Database contains {len(users)} users: {users}")
        
        # Check investigations
        cursor.execute("SELECT case_number, title FROM investigation")
        investigations = cursor.fetchall()
        logger.info(f"🔍 Database contains {len(investigations)} investigations: {investigations}")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"❌ Database verification failed: {str(e)}")
        return False

def migrate_database():
    """Main migration function."""
    logger.info("🔄 Starting database migration...")
    
    # Step 1: Create tables
    success, created_tables = check_and_create_tables()
    if not success:
        logger.error("❌ Table creation failed")
        return False
    
    # Step 2: Seed initial data
    if not seed_initial_data():
        logger.error("❌ Data seeding failed")
        return False
    
    # Step 3: Verify database
    if not verify_database():
        logger.error("❌ Database verification failed")
        return False
    
    logger.info("✅ Database migration completed successfully!")
    return True

if __name__ == "__main__":
    if migrate_database():
        print("🎉 Database setup complete!")
        sys.exit(0)
    else:
        print("💥 Database setup failed!")
        sys.exit(1)
