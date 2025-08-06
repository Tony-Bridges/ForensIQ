
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
        from app import initialize_database
        return initialize_database()

if __name__ == "__main__":
    if init_database():
        print("🎉 Database setup complete!")
    else:
        print("💥 Database setup failed!")
        sys.exit(1)
