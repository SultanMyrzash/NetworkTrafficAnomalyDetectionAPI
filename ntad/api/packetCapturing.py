import threading
import time
from scapy.all import sniff
from api.ml.fakeml import analyze_packet, system_status

# Store last 10 analyzed packets
last_packets = []

# Process and store analyzed packets
def process_packet(packet):
    """Stores captured packets but waits for ML analysis every 3 sec."""
    global last_packets

    # Extract basic packet info
    packet_info = {
        "src": packet.src if hasattr(packet, "src") else "Unknown",
        "dst": packet.dst if hasattr(packet, "dst") else "Unknown",
        "proto": packet.proto if hasattr(packet, "proto") else "Unknown",
        "raw_data": str(packet.summary())  # Store full summary for later use
    }

    # Store raw captured packets for ML to analyze
    if len(last_packets) >= 10:
        last_packets.pop(0)
    last_packets.append(packet_info)

# Background listener: Runs forever, captures packets
def capture_traffic():
    sniff(prn=process_packet, store=0)  # Runs indefinitely

# Background analyzer: Runs every 3 sec, processes last packets
def analyze_traffic():
    while True:
        if last_packets:
            for packet in last_packets:
                packet["status"] = analyze_packet(packet)  # Fake ML analysis
        time.sleep(3)

# Start both threads
threading.Thread(target=capture_traffic, daemon=True).start()
threading.Thread(target=analyze_traffic, daemon=True).start()
