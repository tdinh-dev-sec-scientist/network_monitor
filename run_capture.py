# Create this new file in the root directory of your project

import sys
import os
import time
import logging

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from packet_capture.capture import PacketCapture
from packet_capture.processor import PacketProcessor

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def main():
    """
    Main function to start and manage the packet capture service.
    """
    print("--- Starting Network Capture Service ---")
    
    # 1. Initialize the processor
    processor = PacketProcessor()
    
    # 2. Initialize the capture module and pass the processor to it
    # IMPORTANT: Change 'lo0' to your actual network interface if needed (e.g., 'en0', 'eth0')
    capture = PacketCapture(processor=processor, interface='lo0')
    
    # 3. Start processing threads
    processor.start_processing()
    
    # 4. Start capturing
    capture.start_capture()
    
    print("Capture service is running. Press Ctrl+C to stop.")
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutdown signal received.")
    finally:
        # 5. Stop services gracefully
        print("Stopping capture...")
        capture.stop_capture()
        print("Stopping processor...")
        processor.stop_processing()
        print("--- Capture Service Stopped ---")

if __name__ == '__main__':
    # You will need to run this script with sudo/administrator privileges
    main()
