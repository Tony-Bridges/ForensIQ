
#!/usr/bin/env python3
"""
Main entry point for ForensIQ application
"""

import os
import sys

def main():
    """Main application entry point."""
    # Set up the application
    from app import app, initialize_database
    
    # Initialize database
    with app.app_context():
        if initialize_database():
            print("🎉 Database setup complete!")
        else:
            print("⚠️ Database setup had issues, but continuing...")
    
    # Run the application
    print("🚀 Starting ForensIQ application...")
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    main()
