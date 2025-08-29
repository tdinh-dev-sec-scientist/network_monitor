from datetime import datetime
from app import db
import json
from sqlalchemy import Index

class Packet(db.Model):
    __tablename__ = 'packets'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10), index=True)
    packet_size = db.Column(db.Integer)
    flags = db.Column(db.String(20))
    payload_size = db.Column(db.Integer)
    
    def to_dict(self):
        return {
            'id': self.id, 'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
            'src_port': self.src_port, 'dst_port': self.dst_port,
            'protocol': self.protocol, 'packet_size': self.packet_size,
            'flags': self.flags, 'payload_size': self.payload_size
        }

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    alert_type = db.Column(db.String(50), index=True)
    severity = db.Column(db.String(10), index=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    src_ip = db.Column(db.String(45))
    resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.String(100))
    extra_data = db.Column(db.Text)  # JSON string for additional data
    
    def to_dict(self):
        # --- MORE ROBUST FIX: Safely parse JSON data, handling non-string types ---
        # This try-except block now catches both JSONDecodeError for bad JSON strings
        # and TypeError if the data is not a string at all.
        metadata = {}
        if self.extra_data:
            try:
                # Ensure the data is a string before trying to load it
                if not isinstance(self.extra_data, str):
                    raise TypeError("Data is not a string")
                metadata = json.loads(self.extra_data)
            except (json.JSONDecodeError, TypeError) as e:
                # If parsing fails for any reason, return an error message.
                metadata = {
                    "error": f"Invalid data format in database: {e}",
                    "raw_data": str(self.extra_data)
                }

        return {
            'id': self.id, 'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type, 'severity': self.severity,
            'title': self.title, 'description': self.description,
            'src_ip': self.src_ip, 'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'alert_metadata': metadata
        }

class NetworkStats(db.Model):
    __tablename__ = 'network_stats'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    interval_type = db.Column(db.String(10), index=True)
    total_packets = db.Column(db.Integer, default=0)
    total_bytes = db.Column(db.BigInteger, default=0)
    tcp_packets = db.Column(db.Integer, default=0)
    udp_packets = db.Column(db.Integer, default=0)
    icmp_packets = db.Column(db.Integer, default=0)
    unique_src_ips = db.Column(db.Integer, default=0)
    unique_dst_ips = db.Column(db.Integer, default=0)
    top_src_ip = db.Column(db.String(45))
    top_dst_ip = db.Column(db.String(45))
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(), 'interval_type': self.interval_type,
            'top_src_ip': self.top_src_ip, 'top_dst_ip': self.top_dst_ip,
            'total_packets': self.total_packets, 'total_bytes': self.total_bytes,
            'tcp_packets': self.tcp_packets, 'udp_packets': self.udp_packets,
            'icmp_packets': self.icmp_packets, 'unique_src_ips': self.unique_src_ips,
            'unique_dst_ips': self.unique_dst_ips
        }

class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, index=True)
    reason = db.Column(db.String(200))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_until = db.Column(db.DateTime)
    alert_count = db.Column(db.Integer, default=1)
    
    def to_dict(self):
        return {
            'ip_address': self.ip_address, 'reason': self.reason,
            'blocked_at': self.blocked_at.isoformat(),
            'blocked_until': self.blocked_until.isoformat() if self.blocked_until else None,
            'alert_count': self.alert_count
        }
