import sys
import os
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging

# Add project root to Python path to find 'app' module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import db, socketio
from app.models import NetworkStats, Alert

logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self):
        self.stats_buffer = defaultdict(lambda: {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'ports': defaultdict(int)
        })
        self.real_time_stats = {
            'packets_per_second': deque(maxlen=60),
            'bytes_per_second': deque(maxlen=60),
            'protocol_distribution': defaultdict(int),
            'top_talkers': defaultdict(int)
        }
        self.is_processing = False
        self.stats_thread = None

    def start_processing(self):
        """Start statistics processing"""
        if self.is_processing:
            return
        self.is_processing = True
        self.stats_thread = threading.Thread(target=self._stats_loop)
        self.stats_thread.daemon = True
        self.stats_thread.start()
        logger.info("Started packet processing")

    def stop_processing(self):
        """Stop statistics processing"""
        self.is_processing = False
        if self.stats_thread:
            self.stats_thread.join(timeout=5)
        logger.info("Stopped packet processing")

    def process_packet(self, packet_info):
        """Process a single packet for statistics"""
        current_minute = datetime.now().replace(second=0, microsecond=0)
        minute_stats = self.stats_buffer[current_minute]
        minute_stats['total_packets'] += 1
        minute_stats['total_bytes'] += packet_info.get('packet_size', 0)
        minute_stats['protocols'][packet_info.get('protocol', 'Unknown')] += 1
        minute_stats['src_ips'][packet_info.get('src_ip', 'Unknown')] += 1
        minute_stats['dst_ips'][packet_info.get('dst_ip', 'Unknown')] += 1
        if packet_info.get('dst_port'):
            minute_stats['ports'][packet_info['dst_port']] += 1
        self._update_realtime_stats(packet_info)

    def _update_realtime_stats(self, packet_info):
        """Update real-time statistics"""
        current_second = int(time.time())
        if not self.real_time_stats['packets_per_second'] or \
           self.real_time_stats['packets_per_second'][-1][0] != current_second:
            self.real_time_stats['packets_per_second'].append([current_second, 0])
            self.real_time_stats['bytes_per_second'].append([current_second, 0])
        self.real_time_stats['packets_per_second'][-1][1] += 1
        self.real_time_stats['bytes_per_second'][-1][1] += packet_info.get('packet_size', 0)
        protocol = packet_info.get('protocol', 'Unknown')
        self.real_time_stats['protocol_distribution'][protocol] += 1
        src_ip = packet_info.get('src_ip', 'Unknown')
        self.real_time_stats['top_talkers'][src_ip] += 1

    def _stats_loop(self):
        """Main statistics processing loop"""
        last_minute_save = datetime.now().replace(second=0, microsecond=0)
        last_realtime_emit = time.time()
        while self.is_processing:
            try:
                current_time = datetime.now()
                current_minute = current_time.replace(second=0, microsecond=0)
                if current_minute > last_minute_save:
                    self._save_minute_stats(last_minute_save)
                    last_minute_save = current_minute
                if time.time() - last_realtime_emit > 2:
                    self._emit_realtime_stats()
                    last_realtime_emit = time.time()
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in stats loop: {e}")
                time.sleep(5)

    def _save_minute_stats(self, minute_timestamp):
        """Save minute statistics to database"""
        if minute_timestamp not in self.stats_buffer:
            return
        try:
            from app import create_app
            app = create_app()
            with app.app_context():
                stats = self.stats_buffer.pop(minute_timestamp)
                top_src_ip = max(stats['src_ips'].items(), key=lambda x: x[1])[0] if stats['src_ips'] else None
                top_dst_ip = max(stats['dst_ips'].items(), key=lambda x: x[1])[0] if stats['dst_ips'] else None
                network_stat = NetworkStats(
                    timestamp=minute_timestamp,
                    interval_type='minute',
                    total_packets=stats['total_packets'],
                    total_bytes=stats['total_bytes'],
                    tcp_packets=stats['protocols'].get('TCP', 0),
                    udp_packets=stats['protocols'].get('UDP', 0),
                    icmp_packets=stats['protocols'].get('ICMP', 0),
                    unique_src_ips=len(stats['src_ips']),
                    unique_dst_ips=len(stats['dst_ips']),
                    top_src_ip=top_src_ip,
                    top_dst_ip=top_dst_ip
                )
                db.session.add(network_stat)
                db.session.commit()
                logger.debug(f"Saved minute stats for {minute_timestamp}")
        except Exception as e:
            logger.error(f"Error saving minute stats: {e}")
            db.session.rollback()

    def _emit_realtime_stats(self):
        """Emit real-time statistics via SocketIO"""
        try:
            # This logic can be simplified for clarity
            packets_timeline = list(self.real_time_stats['packets_per_second'])
            if not packets_timeline:
                return
            
            recent_packets = [p[1] for p in packets_timeline[-5:]]
            current_pps = sum(recent_packets) / len(recent_packets) if recent_packets else 0

            bytes_timeline = list(self.real_time_stats['bytes_per_second'])
            recent_bytes = [b[1] for b in bytes_timeline[-5:]]
            current_bps = sum(recent_bytes) / len(recent_bytes) if recent_bytes else 0

            top_protocols = dict(sorted(self.real_time_stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True)[:5])
            top_talkers = dict(sorted(self.real_time_stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:10])

            stats_data = {
                'timestamp': datetime.now().isoformat(),
                'packets_per_second': current_pps,
                'bytes_per_second': current_bps,
                'protocol_distribution': top_protocols,
                'top_talkers': top_talkers,
                'packets_timeline': packets_timeline[-30:],
                'bytes_timeline': bytes_timeline[-30:]
            }
            socketio.emit('realtime_stats', stats_data)
        except Exception as e:
            logger.error(f"Error emitting real-time stats: {e}")

# Global processor instance
processor_instance = None
def get_processor_instance():
    """Get singleton processor instance"""
    global processor_instance
    if processor_instance is None:
        processor_instance = PacketProcessor()
    return processor_instance
