import sys
import os
from collections import deque, defaultdict
from datetime import datetime, timedelta
import numpy as np
import json

# Add project root to Python path to find 'app' module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.models import Alert

class AnomalyDetector:
    """
    Detects network anomalies based on statistical and behavioral analysis.
    """
    def __init__(self, config):
        self.config = config
        
        # For traffic spike detection: store packets per second for the last 60 seconds
        self.pps_history = deque(maxlen=60)
        
        # For port scan detection
        # Structure: { 'src_ip': {'timestamp': datetime, 'ports': {port1, port2, ...}} }
        self.port_scan_tracker = defaultdict(lambda: {'timestamp': datetime.now(), 'ports': set()})
        self.PORT_SCAN_THRESHOLD = 15  # 15 unique ports
        self.PORT_SCAN_WINDOW = timedelta(seconds=10) # in 10 seconds

    def detect_traffic_spike(self, current_pps):
        """
        Detects if the current traffic volume is a significant spike based on
        standard deviation from the historical average.
        """
        self.pps_history.append(current_pps)
        
        # Require a minimum amount of data to be statistically relevant
        if len(self.pps_history) < 30:
            return None
            
        historical_avg = np.mean(self.pps_history)
        std_dev = np.std(self.pps_history)
        
        # A spike is defined as traffic > 3 standard deviations above the mean
        threshold = historical_avg + (3 * std_dev)
        
        # Trigger alert if current traffic exceeds the dynamic threshold and a minimum static threshold
        if current_pps > threshold and current_pps > self.config.get('ALERT_THRESHOLD_MEDIUM', 500):
            # A cooldown mechanism could be added here to prevent alert spam
            return Alert(
                alert_type='Traffic Spike',
                severity='HIGH',
                title=f"High Traffic Volume Detected: {int(current_pps)} pps",
                description=f"Network traffic spiked to {int(current_pps)} packets/second, exceeding the threshold of {int(threshold)} pps (avg: {int(historical_avg)} pps).",
                extra_data=json.dumps({
                    'current_pps': current_pps,
                    'average_pps': historical_avg,
                    'std_dev': std_dev
                })
            )
        return None

    def detect_port_scan(self, packet_info):
        """
        Detects if a source IP is connecting to many unique ports in a short time window.
        """
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')

        if not src_ip or not dst_port or packet_info.get('protocol') != 'TCP':
            return None

        tracker = self.port_scan_tracker[src_ip]
        now = datetime.now()

        # Reset the tracker for this IP if the time window has expired
        if now - tracker['timestamp'] > self.PORT_SCAN_WINDOW:
            tracker['timestamp'] = now
            tracker['ports'].clear()
        
        tracker['ports'].add(dst_port)
        
        if len(tracker['ports']) >= self.PORT_SCAN_THRESHOLD:
            scanned_ports = list(tracker['ports'])
            # Clear tracker for this IP immediately to prevent alert spam
            del self.port_scan_tracker[src_ip]
            
            return Alert(
                alert_type='Port Scan',
                severity='MEDIUM',
                title=f"Potential Port Scan from {src_ip}",
                description=f"IP address {src_ip} contacted {len(scanned_ports)} unique ports in a short time window.",
                src_ip=src_ip,
                extra_data=json.dumps({
                    'scanned_ports_sample': scanned_ports[:20] # Store a sample of ports
                })
            )
        return None
