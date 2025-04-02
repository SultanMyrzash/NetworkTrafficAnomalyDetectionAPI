#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, Ether
import pandas as pd
import numpy as np
import time
import threading
import os
import statistics
import ipaddress
from collections import defaultdict
import logging
import argparse
import signal
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('packet_capturing.log')
    ]
)
logger = logging.getLogger(__name__)

# Global variables
flows = defaultdict(lambda: {"packets": [], "fwd_packets": [], "bwd_packets": [], 
                             "start_time": None, "last_save_time": time.time()})
CSV_FILENAME = "captured_network_data.csv"
SAVE_INTERVAL = 5  # seconds
FLOW_TIMEOUT = 120  # seconds to keep inactive flows
ACTIVE_TIMEOUT = 60  # seconds before terminating long flows
FLOW_WINDOW = 300  # Only use flows from last 5 minutes for detection
running = True
lock = threading.Lock()

# Define the column names exactly as in the dataset
COLUMN_NAMES = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Avg Packet Size", 
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init Fwd Win Bytes", "Init Bwd Win Bytes", "Fwd Act Data Packets",
    "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

def is_forward(src_ip, dst_ip):
    """Determine if a packet is going in the forward direction based on IP addresses"""
    try:
        src_int = int(ipaddress.IPv4Address(src_ip))
        dst_int = int(ipaddress.IPv4Address(dst_ip))
        return src_int < dst_int
    except:
        # Fallback for IPv6 or other issues
        return src_ip < dst_ip

def safe_division(x, y):
    """Safely divide numbers, return 0 if division by zero"""
    return x / y if y else 0

def safe_stat(value_list, stat_func, default=0):
    """Safely calculate statistics"""
    try:
        if not value_list:
            return default
        return stat_func(value_list)
    except:
        return default

def packet_handler(packet):
    """Process each captured packet and organize into flows"""
    if not running:
        return
    
    if not (IP in packet and (TCP in packet or UDP in packet)):
        return
    
    timestamp = packet.time
    
    # Extract basic packet info
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        proto = 6  # TCP
        flags = packet[TCP].flags
        tcp_flags = {
            'F': 1 if flags & 0x01 else 0,  # FIN
            'S': 1 if flags & 0x02 else 0,  # SYN
            'R': 1 if flags & 0x04 else 0,  # RST
            'P': 1 if flags & 0x08 else 0,  # PSH
            'A': 1 if flags & 0x10 else 0,  # ACK
            'U': 1 if flags & 0x20 else 0,  # URG
            'E': 1 if flags & 0x40 else 0,  # ECE
            'C': 1 if flags & 0x80 else 0   # CWR
        }
        header_len = packet[TCP].dataofs * 4
        window = packet[TCP].window
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        proto = 17  # UDP
        tcp_flags = {'F': 0, 'S': 0, 'R': 0, 'P': 0, 'A': 0, 'U': 0, 'E': 0, 'C': 0}
        header_len = 8  # UDP header is always 8 bytes
        window = 0
    else:
        return
    
    # Determine forward/backward based on IP/port
    if is_forward(src_ip, dst_ip) or (src_ip == dst_ip and src_port < dst_port):
        direction = "fwd"
        flow_tuple = (src_ip, dst_ip, src_port, dst_port, proto)
    else:
        direction = "bwd"
        flow_tuple = (dst_ip, src_ip, dst_port, src_port, proto)
    
    # Get payload length
    if IP in packet:
        ip_len = packet[IP].len
        ip_hdr_len = packet[IP].ihl * 4
        payload_len = ip_len - ip_hdr_len - header_len
        if payload_len < 0:
            payload_len = 0
    else:
        payload_len = 0
    
    with lock:
        flow = flows[flow_tuple]
        
        # Initialize flow start time if this is the first packet
        if flow["start_time"] is None:
            flow["start_time"] = timestamp
        
        # Store packet information
        packet_info = {
            "timestamp": timestamp,
            "direction": direction,
            "size": payload_len,
            "header_len": header_len,
            "flags": tcp_flags,
            "window": window
        }
        
        flow["packets"].append(packet_info)
        if direction == "fwd":
            flow["fwd_packets"].append(packet_info)
        else:
            flow["bwd_packets"].append(packet_info)

def calculate_flow_features():
    """Calculate features for all current flows within the time window"""
    flow_features = []
    flows_to_remove = []
    current_time = time.time()
    window_start_time = current_time - FLOW_WINDOW  # Only include flows from last 5 minutes
    
    with lock:
        for flow_id, flow in flows.items():
            # Skip flows with too few packets
            if len(flow["packets"]) < 2:
                continue
                
            # Check if flow has been inactive and should be removed
            last_packet_time = flow["packets"][-1]["timestamp"]
            if current_time - last_packet_time > FLOW_TIMEOUT:
                flows_to_remove.append(flow_id)
                
            # Basic flow info
            proto = flow_id[4]  # Protocol from flow tuple
            
            # Sort packets by timestamp
            flow["packets"].sort(key=lambda p: p["timestamp"])
            flow["fwd_packets"].sort(key=lambda p: p["timestamp"])
            flow["bwd_packets"].sort(key=lambda p: p["timestamp"])
            
            # Calculate flow duration (in microseconds)
            first_packet = flow["packets"][0]["timestamp"]
            last_packet = flow["packets"][-1]["timestamp"]
            
            # Skip flows outside the time window
            if last_packet < window_start_time:
                continue
                
            flow_duration = (last_packet - first_packet) * 1000000  # Convert to microseconds
            if flow_duration == 0:
                flow_duration = 1  # Prevent division by zero
            
            # Count packets
            total_fwd_packets = len(flow["fwd_packets"])
            total_bwd_packets = len(flow["bwd_packets"])
            
            # Calculate packet lengths
            fwd_packet_lengths = [p["size"] for p in flow["fwd_packets"]]
            bwd_packet_lengths = [p["size"] for p in flow["bwd_packets"]]
            all_packet_lengths = [p["size"] for p in flow["packets"]]
            
            # Calculate header lengths
            fwd_header_lengths = sum(p["header_len"] for p in flow["fwd_packets"])
            bwd_header_lengths = sum(p["header_len"] for p in flow["bwd_packets"])
            
            # Fwd packet length stats
            fwd_packet_length_total = sum(fwd_packet_lengths) if fwd_packet_lengths else 0
            fwd_packet_length_max = safe_stat(fwd_packet_lengths, max, 0)
            fwd_packet_length_min = safe_stat(fwd_packet_lengths, min, 0)
            fwd_packet_length_mean = safe_stat(fwd_packet_lengths, statistics.mean, 0)
            fwd_packet_length_std = safe_stat(fwd_packet_lengths, statistics.stdev, 0) if len(fwd_packet_lengths) > 1 else 0
            
            # Bwd packet length stats
            bwd_packet_length_total = sum(bwd_packet_lengths) if bwd_packet_lengths else 0
            bwd_packet_length_max = safe_stat(bwd_packet_lengths, max, 0)
            bwd_packet_length_min = safe_stat(bwd_packet_lengths, min, 0)
            bwd_packet_length_mean = safe_stat(bwd_packet_lengths, statistics.mean, 0)
            bwd_packet_length_std = safe_stat(bwd_packet_lengths, statistics.stdev, 0) if len(bwd_packet_lengths) > 1 else 0
            
            # All packet length stats
            packet_length_min = safe_stat(all_packet_lengths, min, 0)
            packet_length_max = safe_stat(all_packet_lengths, max, 0)
            packet_length_mean = safe_stat(all_packet_lengths, statistics.mean, 0)
            packet_length_std = safe_stat(all_packet_lengths, statistics.stdev, 0) if len(all_packet_lengths) > 1 else 0
            packet_length_variance = packet_length_std ** 2
            
            # Flow bytes and packets per second
            total_bytes = fwd_packet_length_total + bwd_packet_length_total
            flow_bytes_per_sec = safe_division(total_bytes * 1000000, flow_duration)
            flow_packets_per_sec = safe_division((total_fwd_packets + total_bwd_packets) * 1000000, flow_duration)
            
            # Calculate packet inter-arrival times
            flow_iats = []
            for i in range(1, len(flow["packets"])):
                iat = (flow["packets"][i]["timestamp"] - flow["packets"][i-1]["timestamp"]) * 1000000  # microseconds
                flow_iats.append(iat)
                
            # Flow IAT stats
            flow_iat_mean = safe_stat(flow_iats, statistics.mean, 0)
            flow_iat_std = safe_stat(flow_iats, statistics.stdev, 0) if len(flow_iats) > 1 else 0
            flow_iat_max = safe_stat(flow_iats, max, 0)
            flow_iat_min = safe_stat(flow_iats, min, 0)
            
            # Forward IAT stats
            fwd_iats = []
            for i in range(1, len(flow["fwd_packets"])):
                iat = (flow["fwd_packets"][i]["timestamp"] - flow["fwd_packets"][i-1]["timestamp"]) * 1000000
                fwd_iats.append(iat)
            
            fwd_iat_total = sum(fwd_iats) if fwd_iats else 0
            fwd_iat_mean = safe_stat(fwd_iats, statistics.mean, 0)
            fwd_iat_std = safe_stat(fwd_iats, statistics.stdev, 0) if len(fwd_iats) > 1 else 0
            fwd_iat_max = safe_stat(fwd_iats, max, 0)
            fwd_iat_min = safe_stat(fwd_iats, min, 0)
            
            # Backward IAT stats
            bwd_iats = []
            for i in range(1, len(flow["bwd_packets"])):
                iat = (flow["bwd_packets"][i]["timestamp"] - flow["bwd_packets"][i-1]["timestamp"]) * 1000000
                bwd_iats.append(iat)
            
            bwd_iat_total = sum(bwd_iats) if bwd_iats else 0
            bwd_iat_mean = safe_stat(bwd_iats, statistics.mean, 0)
            bwd_iat_std = safe_stat(bwd_iats, statistics.stdev, 0) if len(bwd_iats) > 1 else 0
            bwd_iat_max = safe_stat(bwd_iats, max, 0)
            bwd_iat_min = safe_stat(bwd_iats, min, 0)
            
            # Calculate flags counts
            fwd_psh_flags = sum(p["flags"]['P'] for p in flow["fwd_packets"])
            bwd_psh_flags = sum(p["flags"]['P'] for p in flow["bwd_packets"])
            fwd_urg_flags = sum(p["flags"]['U'] for p in flow["fwd_packets"])
            bwd_urg_flags = sum(p["flags"]['U'] for p in flow["bwd_packets"])
            fin_flag_count = sum(p["flags"]['F'] for p in flow["packets"])
            syn_flag_count = sum(p["flags"]['S'] for p in flow["packets"])
            rst_flag_count = sum(p["flags"]['R'] for p in flow["packets"])
            psh_flag_count = sum(p["flags"]['P'] for p in flow["packets"])
            ack_flag_count = sum(p["flags"]['A'] for p in flow["packets"])
            urg_flag_count = sum(p["flags"]['U'] for p in flow["packets"])
            cwe_flag_count = sum(p["flags"]['C'] for p in flow["packets"])
            ece_flag_count = sum(p["flags"]['E'] for p in flow["packets"])
            
            # Calculate packet rates
            fwd_packets_per_sec = safe_division(total_fwd_packets * 1000000, flow_duration)
            bwd_packets_per_sec = safe_division(total_bwd_packets * 1000000, flow_duration)
            
            # Calculate down/up ratio
            down_up_ratio = safe_division(bwd_packet_length_total, fwd_packet_length_total)
            
            # Calculate average packet sizes
            avg_packet_size = safe_division(total_bytes, (total_fwd_packets + total_bwd_packets))
            avg_fwd_segment_size = fwd_packet_length_mean
            avg_bwd_segment_size = bwd_packet_length_mean
            
            # Bulk transfer analysis - simplified
            fwd_avg_bytes_bulk = 0
            fwd_avg_packets_bulk = 0
            fwd_avg_bulk_rate = 0
            bwd_avg_bytes_bulk = 0
            bwd_avg_packets_bulk = 0
            bwd_avg_bulk_rate = 0
            
            # Subflow features
            subflow_fwd_packets = total_fwd_packets
            subflow_fwd_bytes = fwd_packet_length_total
            subflow_bwd_packets = total_bwd_packets
            subflow_bwd_bytes = bwd_packet_length_total
            
            # Window features
            init_fwd_win_bytes = flow["fwd_packets"][0]["window"] if flow["fwd_packets"] else -1
            init_bwd_win_bytes = flow["bwd_packets"][0]["window"] if flow["bwd_packets"] else -1
            
            # Active/idle time analysis - simplified
            fwd_act_data_packets = sum(1 for p in flow["fwd_packets"] if p["size"] > 0)
            fwd_seg_size_min = fwd_packet_length_min
            active_mean = active_std = active_max = active_min = 0
            idle_mean = idle_std = idle_max = idle_min = 0
            
            # Assemble all features in the exact order
            features = [
                int(proto),  # Protocol
                flow_duration,  # Flow Duration
                total_fwd_packets,  # Total Fwd Packets
                total_bwd_packets,  # Total Backward Packets
                fwd_packet_length_total,  # Fwd Packets Length Total
                bwd_packet_length_total,  # Bwd Packets Length Total
                fwd_packet_length_max,  # Fwd Packet Length Max
                fwd_packet_length_min,  # Fwd Packet Length Min
                fwd_packet_length_mean,  # Fwd Packet Length Mean
                fwd_packet_length_std,  # Fwd Packet Length Std
                bwd_packet_length_max,  # Bwd Packet Length Max
                bwd_packet_length_min,  # Bwd Packet Length Min
                bwd_packet_length_mean,  # Bwd Packet Length Mean
                bwd_packet_length_std,  # Bwd Packet Length Std
                flow_bytes_per_sec,  # Flow Bytes/s
                flow_packets_per_sec,  # Flow Packets/s
                flow_iat_mean,  # Flow IAT Mean
                flow_iat_std,  # Flow IAT Std
                flow_iat_max,  # Flow IAT Max
                flow_iat_min,  # Flow IAT Min
                fwd_iat_total,  # Fwd IAT Total
                fwd_iat_mean,  # Fwd IAT Mean
                fwd_iat_std,  # Fwd IAT Std
                fwd_iat_max,  # Fwd IAT Max
                fwd_iat_min,  # Fwd IAT Min
                bwd_iat_total,  # Bwd IAT Total
                bwd_iat_mean,  # Bwd IAT Mean
                bwd_iat_std,  # Bwd IAT Std
                bwd_iat_max,  # Bwd IAT Max
                bwd_iat_min,  # Bwd IAT Min
                fwd_psh_flags,  # Fwd PSH Flags
                bwd_psh_flags,  # Bwd PSH Flags
                fwd_urg_flags,  # Fwd URG Flags
                bwd_urg_flags,  # Bwd URG Flags
                fwd_header_lengths,  # Fwd Header Length
                bwd_header_lengths,  # Bwd Header Length
                fwd_packets_per_sec,  # Fwd Packets/s
                bwd_packets_per_sec,  # Bwd Packets/s
                packet_length_min,  # Packet Length Min
                packet_length_max,  # Packet Length Max
                packet_length_mean,  # Packet Length Mean
                packet_length_std,  # Packet Length Std
                packet_length_variance,  # Packet Length Variance
                fin_flag_count,  # FIN Flag Count
                syn_flag_count,  # SYN Flag Count
                rst_flag_count,  # RST Flag Count
                psh_flag_count,  # PSH Flag Count
                ack_flag_count,  # ACK Flag Count
                urg_flag_count,  # URG Flag Count
                cwe_flag_count,  # CWE Flag Count
                ece_flag_count,  # ECE Flag Count
                down_up_ratio,  # Down/Up Ratio
                avg_packet_size,  # Avg Packet Size
                avg_fwd_segment_size,  # Avg Fwd Segment Size
                avg_bwd_segment_size,  # Avg Bwd Segment Size
                fwd_avg_bytes_bulk,  # Fwd Avg Bytes/Bulk
                fwd_avg_packets_bulk,  # Fwd Avg Packets/Bulk
                fwd_avg_bulk_rate,  # Fwd Avg Bulk Rate
                bwd_avg_bytes_bulk,  # Bwd Avg Bytes/Bulk
                bwd_avg_packets_bulk,  # Bwd Avg Packets/Bulk
                bwd_avg_bulk_rate,  # Bwd Avg Bulk Rate
                subflow_fwd_packets,  # Subflow Fwd Packets
                subflow_fwd_bytes,  # Subflow Fwd Bytes
                subflow_bwd_packets,  # Subflow Bwd Packets
                subflow_bwd_bytes,  # Subflow Bwd Bytes
                init_fwd_win_bytes,  # Init Fwd Win Bytes
                init_bwd_win_bytes,  # Init Bwd Win Bytes
                fwd_act_data_packets,  # Fwd Act Data Packets
                fwd_seg_size_min,  # Fwd Seg Size Min
                active_mean,  # Active Mean
                active_std,  # Active Std
                active_max,  # Active Max
                active_min,  # Active Min
                idle_mean,  # Idle Mean
                idle_std,  # Idle Std
                idle_max,  # Idle Max
                idle_min  # Idle Min
            ]
            
            # Append this flow's features
            flow_features.append(features)
            
            # For long running flows, terminate and create a new flow
            if current_time - first_packet > ACTIVE_TIMEOUT:
                flows_to_remove.append(flow_id)
        
        # Clean up removed flows
        for flow_id in flows_to_remove:
            del flows[flow_id]
            
    return flow_features

def save_to_csv(features):
    """Save extracted features to CSV file, completely replacing previous data"""
    if not features:
        return
        
    try:
        # Create DataFrame with the correct column names
        df = pd.DataFrame(features, columns=COLUMN_NAMES)
        
        # Save to CSV (overwrite mode)
        df.to_csv(CSV_FILENAME, mode='w', index=False)
        
        logger.info(f"Saved {len(features)} flow records to {CSV_FILENAME}")
    except Exception as e:
        logger.error(f"Error saving to CSV: {e}")

def periodic_save():
    """Function to periodically save captured data"""
    while running:
        try:
            time.sleep(SAVE_INTERVAL)
            features = calculate_flow_features()
            if features:
                save_to_csv(features)
        except Exception as e:
            logger.error(f"Error in periodic save: {e}")

def signal_handler(sig, frame):
    """Handle CTRL+C gracefully"""
    global running
    logger.info("Stopping capture. Final save...")
    running = False
    time.sleep(1)  # Give time for threads to stop
    features = calculate_flow_features()
    if features:
        save_to_csv(features)
    logger.info("Capture stopped.")
    sys.exit(0)

def main():
    """Main function to start packet capture and processing"""
    global CSV_FILENAME, SAVE_INTERVAL, FLOW_WINDOW
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Capture network traffic for DDoS detection')
    parser.add_argument('-i', '--interface', default=None, help='Network interface to capture packets from')
    parser.add_argument('-o', '--output', default=CSV_FILENAME, help='Output CSV file path')
    parser.add_argument('-s', '--save-interval', type=int, default=SAVE_INTERVAL, help='Interval between saves in seconds')
    parser.add_argument('-w', '--window', type=int, default=FLOW_WINDOW, help='Time window for flows (seconds)')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = infinite)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    CSV_FILENAME = args.output
    SAVE_INTERVAL = args.save_interval
    FLOW_WINDOW = args.window
    
    logger.info(f"Starting network traffic capture on {args.interface or 'default interface'}")
    logger.info(f"Saving to {CSV_FILENAME} every {SAVE_INTERVAL} seconds")
    logger.info(f"Using a {FLOW_WINDOW} second time window for analysis")
    logger.info("Press Ctrl+C to stop")
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start the periodic save thread
    save_thread = threading.Thread(target=periodic_save, daemon=True)
    save_thread.start()
    
    try:
        # Start packet capture
        sniff(
            iface=args.interface,
            prn=packet_handler,
            store=False,
            count=args.count
        )
    except KeyboardInterrupt:
        # Handle by signal handler
        pass
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
        running = False
        sys.exit(1)

if __name__ == "__main__":
    main()