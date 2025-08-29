import sys
import os
import threading
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
import queue

# --- FIX: Add project root to Python path to find 'app' module ---
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import db, socketio
from app.models import Packet

logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self, processor, interface='eth0', filter_str='', buffer_size=1000):
        self.interface = interface
        self.filter_str = filter_str
        self.buffer_size = buffer_size
        
        # --- EDIT: Use threading.Event for a more reliable stop signal ---
        self.stop_event = threading.Event()
        
        self.capture_thread = None
        self.packet_queue = queue.Queue(maxsize=buffer_size)
        self.processor_thread = None
        self.stats = {
            'total_packets': 0,
            'packets_per_second': 0,
            'last_update': datetime.now()
        }
        self.packet_processor = processor

    def start_capture(self):
        """Start packet capture in separate thread"""
        if self.capture_thread and self.capture_thread.is_alive():
            logger.warning("Capture already running")
            return

        # --- EDIT: Reset the stop event before starting ---
        self.stop_event.clear()
        
        self.processor_thread = threading.Thread(target=self._process_packets_for_db)
        self.processor_thread.daemon = True
        self.processor_thread.start()

        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()

        logger.info(f"Started packet capture on interface {self.interface}")

    def stop_capture(self):
        """Stop packet capture"""
        logger.info("Setting stop event for capture...")
        # --- EDIT: Set the event to signal all threads to stop ---
        self.stop_event.set()
        
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        if self.processor_thread:
            self.processor_thread.join(timeout=2)
        logger.info("Stopped packet capture threads.")

    def _capture_loop(self):
        """
        Main capture loop.
        --- EDIT: Use Scapy's `stop_filter` for immediate and reliable stopping. ---
        """
        logger.info("Capture loop started.")
        try:
            # This will block until the stop_event is set.
            # The stop_filter is checked after each packet, making it very responsive.
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=self.filter_str,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Error in capture loop: {e}")
        finally:
            # Ensure the stop event is set if the loop exits unexpectedly
            self.stop_event.set()
            logger.info("Capture loop finished.")


    def _packet_handler(self, packet):
        """Handle captured packet"""
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                if not self.packet_queue.full():
                    self.packet_queue.put(packet_info)
                else:
                    logger.warning("Packet queue full, dropping packet for DB save")

                if self.packet_processor:
                    self.packet_processor.process_packet(packet_info)

                self.stats['total_packets'] += 1
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        packet_info = {
            'timestamp': datetime.now(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': 'OTHER',
            'packet_size': len(packet),
            'payload_size': len(ip_layer.payload)
        }

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_info.update({
                'protocol': 'TCP',
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'flags': ",".join(tcp_layer.sprintf('%TCP.flags%').split())
            })
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_info.update({
                'protocol': 'UDP',
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport,
                'flags': ''
            })
        elif packet.haslayer(ICMP):
            packet_info.update({
                'protocol': 'ICMP',
                'src_port': None,
                'dst_port': None,
                'flags': ''
            })

        return packet_info

    def _process_packets_for_db(self):
        """Process packets from queue and save to database"""
        packet_batch = []
        batch_size = 50
        last_save = time.time()

        # --- EDIT: Loop as long as the capture is not stopped OR the queue is not empty ---
        while not self.stop_event.is_set() or not self.packet_queue.empty():
            try:
                # Use a timeout to avoid blocking indefinitely
                packet_info = self.packet_queue.get(timeout=1)
                packet_batch.append(packet_info)
                self.packet_queue.task_done()

                if len(packet_batch) >= batch_size or (time.time() - last_save) > 5:
                    self._save_packet_batch(packet_batch)
                    packet_batch = []
                    last_save = time.time()

            except queue.Empty:
                # This is normal if no packets are coming in.
                # The loop condition will handle exiting.
                continue
            except Exception as e:
                logger.error(f"Error in packet processor: {e}")
        
        # Save any remaining packets after the loop finishes
        if packet_batch:
            logger.info(f"Saving last batch of {len(packet_batch)} packets.")
            self._save_packet_batch(packet_batch)


    def _save_packet_batch(self, packet_batch):
        """Save batch of packets to database"""
        if not packet_batch:
            return

        try:
            from app import create_app
            app = create_app()
            with app.app_context():
                packets = [Packet(**info) for info in packet_batch]
                db.session.bulk_save_objects(packets)
                db.session.commit()

                socketio.emit('packet_update', {
                    'count': len(packet_batch),
                    'latest_packet': packet_batch[-1] if packet_batch else None
                })
                logger.debug(f"Saved {len(packet_batch)} packets to database")

        except Exception as e:
            from app import db as app_db
            logger.error(f"Error saving packets: {e}")
            app_db.session.rollback()
