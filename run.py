import logging
from app import create_app, socketio
from config.config import config
import os

# Configure logging to output to both a file and the console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'), # Log to a file
        logging.StreamHandler() # Log to the console
    ])
logger = logging.getLogger(__name__)

def create_application():
    """Create and configure the Flask application based on environment."""
    # Use FLASK_ENV environment variable to select configuration (e.g., 'development', 'production')
    config_name = os.environ.get('FLASK_ENV', 'development')
    app = create_app(config_name)
    return app

if __name__ == '__main__':
    app = create_application()
    
    logger.info("Starting Network Security Monitor Dashboard")
    logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    # Run the application using the Flask-SocketIO development server
    socketio.run(
        app,
        host='0.0.0.0',
        port=5001, # Using port 5001 to avoid conflicts on macOS
        debug=app.config.get('DEBUG', False),
        # --- IMPORTANT ---
        # Disabling the reloader is crucial. The reloader runs the app in a subprocess,
        # which would cause our background packet capture service to start twice.
        use_reloader=False
    )
