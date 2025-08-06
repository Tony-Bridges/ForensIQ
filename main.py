#!/usr/bin/env python3
"""
ForensIQ - Digital Forensics Investigation Tool
Production-ready main entry point.
"""

from app import app, initialize_database
import logging
import os

def setup_logging():
    """Setup production logging configuration."""
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('forensiq.log') if os.access('.', os.W_OK) else logging.NullHandler()
        ]
    )

def main():
    """Main application entry point."""
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("🚀 Starting ForensIQ Digital Forensics Platform")

    # Initialize database
    try:
        if initialize_database():
            logger.info("✅ Database initialization completed successfully")
        else:
            logger.warning("⚠️ Database initialization had issues, but continuing...")
    except Exception as e:
        logger.error(f"❌ Database setup failed: {str(e)}")
        logger.info("Continuing with limited functionality...")

    # Get configuration from environment
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

    logger.info(f"🌐 Starting web server on http://{host}:{port}")
    logger.info(f"🔧 Debug mode: {'Enabled' if debug_mode else 'Disabled'}")

    # Start the Flask application
    try:
        app.run(
            host=host,
            port=port,
            debug=debug_mode,
            threaded=True,
            use_reloader=debug_mode
        )
    except Exception as e:
        logger.error(f"❌ Failed to start web server: {str(e)}")
        raise

if __name__ == "__main__":
    main()