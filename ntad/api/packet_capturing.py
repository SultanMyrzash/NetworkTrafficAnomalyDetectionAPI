import threading
import time
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import numpy as np

# Define required features for the ML model
REQUIRED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
]

# Store all packets from the last n seconds
traffic_buffer = []
flow_stats = defaultdict(lambda: {
    'fwd_packets': [],
    'bwd_packets': [],
    'start_time': None,
    'last_time': None
})
buffer_lock = threading.Lock()

def process_packet(packet):
    """Stores captured packets with all required features for ML analysis."""
    timestamp = time.time()

    try:
        # Basic packet info
        packet_info = {
            "timestamp": timestamp,
            "src": packet[IP].src if IP in packet else "Unknown",
            "dst": packet[IP].dst if IP in packet else "Unknown",
            "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0),
            "proto": packet[IP].proto if IP in packet else 0,
            "length": len(packet),
            "raw_data": str(packet.summary())
        }

        # Flow identification
        flow_id = f"{packet_info['src']}:{packet_info['dst']}:{packet_info['dst_port']}"
        
        with buffer_lock:
            # Update flow statistics
            if flow_stats[flow_id]['start_time'] is None:
                flow_stats[flow_id]['start_time'] = timestamp
            
            flow_stats[flow_id]['last_time'] = timestamp
            
            # Determine forward/backward packets
            if packet_info['src'] < packet_info['dst']:
                flow_stats[flow_id]['fwd_packets'].append(packet_info)
            else:
                flow_stats[flow_id]['bwd_packets'].append(packet_info)

            # Calculate flow features
            packet_info.update({
                "flow_duration": timestamp - flow_stats[flow_id]['start_time'],
                "total_fwd_packets": len(flow_stats[flow_id]['fwd_packets']),
                "total_bwd_packets": len(flow_stats[flow_id]['bwd_packets']),
                "total_fwd_length": sum(p['length'] for p in flow_stats[flow_id]['fwd_packets']),
                "total_bwd_length": sum(p['length'] for p in flow_stats[flow_id]['bwd_packets']),
                "fwd_length_stats": calculate_stats([p['length'] for p in flow_stats[flow_id]['fwd_packets']]),
                "bwd_length_stats": calculate_stats([p['length'] for p in flow_stats[flow_id]['bwd_packets']]),
                # Add TCP flags if available
                "tcp_flags": get_tcp_flags(packet) if TCP in packet else {},
            })

            # Store packet with all features
            traffic_buffer.append(packet_info)
            
            # Clean old packets
            current_time = time.time()
            traffic_buffer[:] = [p for p in traffic_buffer if current_time - p["timestamp"] <= 10] # n
            
            # Clean old flow statistics
            for flow_id in list(flow_stats.keys()):
                if current_time - flow_stats[flow_id]['last_time'] > 10: # n
                    del flow_stats[flow_id]

    except Exception as e:
        print(f"Error processing packet: {e}")

def calculate_stats(values):
    """Calculate statistical features (max, min, mean, std)."""
    if not values:
        return {"max": 0, "min": 0, "mean": 0, "std": 0}
    return {
        "max": max(values),
        "min": min(values),
        "mean": np.mean(values),
        "std": np.std(values) if len(values) > 1 else 0
    }

def get_tcp_flags(packet):
    """Extract TCP flags from packet."""
    flags = {}
    if TCP in packet:
        flags.update({
            "FIN": packet[TCP].flags.F,
            "SYN": packet[TCP].flags.S,
            "RST": packet[TCP].flags.R,
            "PSH": packet[TCP].flags.P,
            "ACK": packet[TCP].flags.A,
            "URG": packet[TCP].flags.U,
        })
    return flags

# ... rest of the existing code ...

def continuous_sniff():
    """Continuously captures packets without resetting the buffer."""
    print("🚀 Packet Sniffing Started!")  # Debugging
    while True:
        sniff(prn=process_packet, store=0, count=10)  # Capture packets in small batches

# Start sniffing in a separate thread (Fixes issue with buffer resetting)
sniff_thread = threading.Thread(target=continuous_sniff, daemon=True)
sniff_thread.start()

# Debugging function to print buffer contents every 5 sec
# def debug_traffic_buffer():
#     while True:
#         with buffer_lock:
#             print(f"📦 Buffer Size: {len(traffic_buffer)} | Latest Packets: {traffic_buffer[-3:]}")  # Show last 3 packets
#         time.sleep(5)

# debug_thread = threading.Thread(target=debug_traffic_buffer, daemon=True)
# debug_thread.start()
