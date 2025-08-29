import sys
import os
import threading
import time
from datetime import datetime, timedelta # Import timedelta
from collections import defaultdict, deque
import logging
import json
import redis

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import db, create_app
from app.models import NetworkStats, Alert
from anomaly_detection.detector import AnomalyDetector

logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self):
        self.stats_buffer = defaultdict(lambda: {
            'total_packets': 0, 'total_bytes': 0,
            'protocols': defaultdict(int), 'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int), 'ports': defaultdict(int)
        })
        self.real_time_stats = {
            'packets_per_second': deque(maxlen=60), 'bytes_per_second': deque(maxlen=60),
            'protocol_distribution': defaultdict(int), 'top_talkers': defaultdict(int)
        }
        self.is_processing = False
        self.stats_thread = None
        
        app = create_app()
        self.redis_client = redis.from_url(app.config['REDIS_URL'])
        self.anomaly_detector = AnomalyDetector(config=app.config)
        logger.info("Anomaly detector and Redis client initialized.")

    def start_processing(self):
        if self.is_processing: return
        self.is_processing = True
        self.stats_thread = threading.Thread(target=self._stats_loop)
        self.stats_thread.daemon = True
        self.stats_thread.start()
        logger.info("Started packet processing")

    def stop_processing(self):
        self.is_processing = False
        if self.stats_thread: self.stats_thread.join(timeout=5)
        logger.info("Stopped packet processing")

    def process_packet(self, packet_info):
        # Update stats
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

        # Check for port scanning anomaly
        scan_alert = self.anomaly_detector.detect_port_scan(packet_info)
        if scan_alert:
            self._handle_alerts([scan_alert])

    def _update_realtime_stats(self, packet_info):
        current_second = int(time.time())
        if not self.real_time_stats['packets_per_second'] or \
           self.real_time_stats['packets_per_second'][-1][0] != current_second:
            self.real_time_stats['packets_per_second'].append([current_second, 0])
            self.real_time_stats['bytes_per_second'].append([current_second, 0])
        self.real_time_stats['packets_per_second'][-1][1] += 1
        self.real_time_stats['bytes_per_second'][-1][1] += packet_info.get('packet_size', 0)
        self.real_time_stats['protocol_distribution'][packet_info.get('protocol', 'Unknown')] += 1
        self.real_time_stats['top_talkers'][packet_info.get('src_ip', 'Unknown')] += 1

    def _stats_loop(self):
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
                    self._publish_realtime_stats()
                    last_realtime_emit = time.time()
                    
                    packets_timeline = list(self.real_time_stats['packets_per_second'])
                    if packets_timeline:
                        recent_packets = [p[1] for p in packets_timeline[-5:]]
                        current_pps = sum(recent_packets) / len(recent_packets) if recent_packets else 0
                        spike_alert = self.anomaly_detector.detect_traffic_spike(current_pps)
                        if spike_alert:
                            self._handle_alerts([spike_alert])
                
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in stats loop: {e}")
                time.sleep(5)

    def _handle_alerts(self, alerts):
        """
        Saves alerts to the database after checking for duplicates,
        and publishes a notification to Redis.
        """
        if not alerts: return
        
        # --- NEW: Alert Deduplication Logic ---
        new_alerts_to_save = []
        try:
            app = create_app()
            with app.app_context():
                for alert in alerts:
                    # Check for a similar, recent, unresolved alert
                    cooldown_period = datetime.now() - timedelta(minutes=5)
                    
                    existing_alert = db.session.scalars(
                        db.select(Alert).filter(
                            Alert.alert_type == alert.alert_type,
                            Alert.src_ip == alert.src_ip,
                            Alert.resolved == False,
                            Alert.timestamp >= cooldown_period
                        ).limit(1)
                    ).first()

                    if not existing_alert:
                        # If no recent duplicate is found, add it to the list to be saved
                        new_alerts_to_save.append(alert)
                    else:
                        logger.info(f"Duplicate alert detected and suppressed: {alert.title}")

                if new_alerts_to_save:
                    db.session.add_all(new_alerts_to_save)
                    db.session.commit()
                    logger.info(f"Saved {len(new_alerts_to_save)} new alert(s) to the database.")
                    # Publish a generic notification
                    self.redis_client.publish('new_alert', json.dumps({'message': 'New alert(s) generated.'}))

        except Exception as e:
            logger.error(f"Error saving or publishing alerts: {e}")
            db.session.rollback()

    def _save_minute_stats(self, minute_timestamp):
        if minute_timestamp not in self.stats_buffer: return
        try:
            app = create_app()
            with app.app_context():
                stats = self.stats_buffer.pop(minute_timestamp)
                top_src_ip = max(stats['src_ips'].items(), key=lambda x: x[1])[0] if stats['src_ips'] else None
                top_dst_ip = max(stats['dst_ips'].items(), key=lambda x: x[1])[0] if stats['dst_ips'] else None
                network_stat = NetworkStats(
                    timestamp=minute_timestamp, interval_type='minute',
                    total_packets=stats['total_packets'], total_bytes=stats['total_bytes'],
                    tcp_packets=stats['protocols'].get('TCP', 0), udp_packets=stats['protocols'].get('UDP', 0),
                    icmp_packets=stats['protocols'].get('ICMP', 0), unique_src_ips=len(stats['src_ips']),
                    unique_dst_ips=len(stats['dst_ips']), top_src_ip=top_src_ip, top_dst_ip=top_dst_ip
                )
                db.session.add(network_stat)
                db.session.commit()
                logger.debug(f"Saved minute stats for {minute_timestamp}")
        except Exception as e:
            logger.error(f"Error saving minute stats: {e}")
            db.session.rollback()

    def _publish_realtime_stats(self):
        try:
            packets_timeline = list(self.real_time_stats['packets_per_second'])
            if not packets_timeline: return
            recent_packets = [p[1] for p in packets_timeline[-5:]]
            current_pps = sum(recent_packets) / len(recent_packets) if recent_packets else 0
            bytes_timeline = list(self.real_time_stats['bytes_per_second'])
            recent_bytes = [b[1] for b in bytes_timeline[-5:]]
            current_bps = sum(recent_bytes) / len(recent_bytes) if recent_bytes else 0
            top_protocols = dict(sorted(self.real_time_stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True)[:5])
            top_talkers = dict(sorted(self.real_time_stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:10])
            stats_data = {
                'timestamp': datetime.now().isoformat(),
                'packets_per_second': current_pps, 'bytes_per_second': current_bps,
                'protocol_distribution': top_protocols, 'top_talkers': top_talkers,
                'packets_timeline': packets_timeline[-30:], 'bytes_timeline': bytes_timeline[-30:]
            }
            self.redis_client.publish('realtime_stats', json.dumps(stats_data))
        except Exception as e:
            logger.error(f"Error publishing real-time stats to Redis: {e}")
