import sys
import os

# --- IMPORTANT FIX ---
# Add the project's root directory to the Python path.
# This allows the script to find and import the 'app' module,
# which is located in the root directory.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
# You might not need to import models directly if you are just creating tables
# from app.models import Packet, Alert, NetworkStats, BlockedIP

def init_database():
    """
    Initializes the database by creating an application context,
    dropping all existing tables, and creating new ones based on the models.
    """
    # Create a Flask app instance to establish an application context
    app = create_app()
    
    # The app_context is necessary for database operations
    with app.app_context():
        print("Dropping all existing tables...")
        # Drop all tables (useful for development, be careful in production)
        db.drop_all()
        
        print("Creating all tables based on models...")
        # Create all tables defined in your models.py
        db.create_all()
        
        print("Database has been initialized successfully!")

if __name__ == '__main__':
    # This block runs when the script is executed directly
    init_database()
