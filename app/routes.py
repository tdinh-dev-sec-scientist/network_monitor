from flask import Blueprint, render_template, jsonify, request
from datetime import datetime, timedelta
# --- EDIT: Import the 'text' function for modern raw SQL execution ---
from sqlalchemy import text
from app import db, socketio
from app.models import Packet, Alert, NetworkStats, BlockedIP
# --- REMOVED: Do not import capture/processor into the web app ---
# from packet_capture.capture import get_capture_instance
# from packet_capture.processor import get_processor_instance
import logging
import os
import psutil # Ensure you have 'pip install psutil'

logger = logging.getLogger(__name__)

# Create blueprints
main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

# --- Main dashboard routes ---
@main_bp.route('/')
def dashboard():
    return render_template('dashboard.html')

@main_bp.route('/alerts')
def alerts_page():
    return render_template('alerts.html')

@main_bp.route('/statistics')
def statistics_page():
    return render_template('statistics.html')

# --- API Routes ---
# Note: The '/stats/realtime' endpoint was removed as it depends on the processor instance.
# Real-time data should be pushed from the processor via SocketIO, not pulled via an API call.

@api_bp.route('/stats/history')
def get_historical_stats():
    """Get historical network statistics"""
    try:
        hours = request.args.get('hours', 24, type=int)
        interval = request.args.get('interval', 'minute')
        start_time = datetime.now() - timedelta(hours=hours)
        
        stats = db.session.scalars(
            db.select(NetworkStats).filter(
                NetworkStats.timestamp >= start_time,
                NetworkStats.interval_type == interval
            ).order_by(NetworkStats.timestamp)
        ).all()
        
        return jsonify([stat.to_dict() for stat in stats])
    except Exception as e:
        logger.error(f"Error getting historical stats: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/alerts/active')
def get_active_alerts():
    """Get all active alerts"""
    try:
        alerts = db.session.scalars(
            db.select(Alert).filter_by(resolved=False).order_by(Alert.timestamp.desc())
        ).all()
        return jsonify([alert.to_dict() for alert in alerts])
    except Exception as e:
        logger.error(f"Error getting active alerts: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
    try:
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
            
        alert.resolved = True
        alert.resolved_at = datetime.now()
        alert.resolved_by = request.json.get('resolved_by', 'System')
        
        db.session.commit()
        socketio.emit('alert_resolved', alert.to_dict())
        return jsonify(alert.to_dict())
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/traffic/recent')
def get_recent_traffic():
    """Get recent packet traffic"""
    try:
        minutes = request.args.get('minutes', 5, type=int)
        limit = request.args.get('limit', 100, type=int)
        start_time = datetime.now() - timedelta(minutes=minutes)
        
        packets = db.session.scalars(
            db.select(Packet).filter(Packet.timestamp >= start_time)
            .order_by(Packet.timestamp.desc()).limit(limit)
        ).all()
        
        return jsonify([packet.to_dict() for packet in packets])
    except Exception as e:
        logger.error(f"Error getting recent traffic: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/traffic/top-talkers')
def get_top_talkers():
    """Get top talking IP addresses"""
    try:
        hours = request.args.get('hours', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        start_time = datetime.now() - timedelta(hours=hours)
        
        # --- FIX: Use modern, safe raw SQL execution with SQLAlchemy 2.0 style ---
        query = text("""
            SELECT src_ip, COUNT(*) as packet_count, SUM(packet_size) as total_bytes
            FROM packets 
            WHERE timestamp >= :start_time
            GROUP BY src_ip 
            ORDER BY packet_count DESC 
            LIMIT :limit
        """)
        
        result = db.session.execute(query, {"start_time": start_time, "limit": limit})
        
        top_talkers = [
            {'ip': row.src_ip, 'packet_count': row.packet_count, 'total_bytes': row.total_bytes}
            for row in result
        ]
        
        return jsonify(top_talkers)
    except Exception as e:
        logger.error(f"Error getting top talkers: {e}")
        return jsonify({'error': str(e)}), 500

# --- REMOVED: Control endpoints are dangerous and should not be in a web app ---

@api_bp.route('/system/status')
def get_system_status():
    """Get general system status information"""
    try:
        status = {
            'system_memory_percent': psutil.virtual_memory().percent,
            'system_cpu_percent': psutil.cpu_percent(interval=None), # non-blocking
            'disk_usage_percent': psutil.disk_usage('/').percent,
            'database_size_mb': get_database_size()
        }
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'error': str(e)}), 500

def get_database_size():
    """Get database size in MB (for SQLite)"""
    try:
        # This is a simplified example; a robust solution would handle other DB types
        from app import create_app
        app = create_app()
        db_path = app.config.get('SQLALCHEMY_DATABASE_URI', '').replace('sqlite:///', '')
        if os.path.exists(db_path):
            return round(os.path.getsize(db_path) / (1024 * 1024), 2)
        return 0
    except Exception:
        return 0

# --- SocketIO event handlers ---
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected to SocketIO')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected from SocketIO')
