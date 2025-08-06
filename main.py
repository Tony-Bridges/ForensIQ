
#!/usr/bin/env python3
"""
ForensIQ - Professional Digital Forensics Investigation Platform
Main entry point for the application
"""

from app import app, initialize_database

if __name__ == "__main__":
    print("🚀 Starting ForensIQ application...")
    
    # Initialize database on startup
    try:
        initialize_database()
        print("✅ Database initialization completed")
    except Exception as e:
        print(f"⚠️ Database initialization warning: {str(e)}")
        print("⚠️ Continuing with application startup...")
    
    # Start the Flask application
    print("🌐 Starting web server on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
