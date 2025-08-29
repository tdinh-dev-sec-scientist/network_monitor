import sys
import os
import time
import logging

# --- FIX: Add project root to Python path ---
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from packet_capture.capture import PacketCapture
from packet_capture.processor import PacketProcessor

# Configure basic logging for the test
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def test_integration():
    """
    Test the integration between PacketCapture and PacketProcessor.
    """
    print("--- Starting Integration Test ---")
    
    # 1. Initialize the processor
    processor = PacketProcessor()
    
    # 2. Initialize the capture module and PASS the processor to it
    # Use a common interface like 'en0' for WiFi on macOS or 'eth0' on Linux.
    # 'lo0' on macOS for loopback.
    # You might need to change this depending on your OS.
    capture = PacketCapture(processor=processor, interface='lo0', filter_str='')
    
    # 3. Start processing threads
    processor.start_processing()
    
    # 4. Start capturing for a short duration
    capture.start_capture()
    print("Capturing packets for 10 seconds...")
    time.sleep(10)
    
    # 5. Stop capturing and processing
    print("Stopping capture...")
    capture.stop_capture()
    print("Stopping processor...")
    processor.stop_processing()
    
    print("\n--- Test Results ---")
    print(f"Total packets captured: {capture.stats['total_packets']}")
    
    # Check if the processor received data
    final_stats = processor.real_time_stats
    print(f"Total protocols tracked by processor: {len(final_stats['protocol_distribution'])}")
    print(f"Top talkers tracked by processor: {final_stats['top_talkers']}")
    print("--- Test Finished ---")

if __name__ == '__main__':
    # Note: You might need to run this script with sudo/administrator privileges
    # to allow packet sniffing on network interfaces.
    test_integration()
