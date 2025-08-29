import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///network_monitor.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network monitoring settings
    CAPTURE_INTERFACE = os.environ.get('CAPTURE_INTERFACE') or 'eth0'
    CAPTURE_FILTER = os.environ.get('CAPTURE_FILTER') or ''
    PACKET_BUFFER_SIZE = 10000
    
    # Alert settings
    ALERT_EMAIL_ENABLED = False
    ALERT_THRESHOLD_HIGH = 1000  # packets per second
    ALERT_THRESHOLD_MEDIUM = 500
    
    # Data retention
    DATA_RETENTION_DAYS = 7
    CLEANUP_INTERVAL_HOURS = 24
    
    # Redis for caching and background tasks
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'

class DevelopmentConfig(Config):
    DEBUG = True
    CAPTURE_INTERFACE = 'lo'  # Use loopback for development

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}