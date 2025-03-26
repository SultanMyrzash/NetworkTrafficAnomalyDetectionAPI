import numpy as np
from keras.api.models import load_model
import os
import logging

class NetworkAnomalyDetector:
    def __init__(self):
        self.model = None
        self.feature_names = [
            "Destination Port", "Flow Duration", "Total Fwd Packets",
            "Total Backward Packets", "Total Length of Fwd Packets",
            "Total Length of Bwd Packets", "Fwd Packet Length Max",
            "Fwd Packet Length Min", "Fwd Packet Length Mean",
            "Fwd Packet Length Std", "Bwd Packet Length Max",
            "Bwd Packet Length Min", "Bwd Packet Length Mean",
            "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
            "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
            "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
            "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
            "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
            "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
            "Min Packet Length", "Max Packet Length", "Packet Length Mean",
            "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
            "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
            "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
            "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
            "Avg Fwd Segment Size", "Avg Bwd Segment Size",
            "Fwd Header Length", "Fwd Avg Bytes/Bulk",
            "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
            "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
            "Subflow Fwd Bytes", "Subflow Bwd Packets",
            "Subflow Bwd Bytes", "Init_Win_bytes_forward",
            "Init_Win_bytes_backward", "act_data_pkt_fwd",
            "min_seg_size_forward", "Active Mean", "Active Std",
            "Active Max", "Active Min", "Idle Mean", "Idle Std",
            "Idle Max", "Idle Min"
        ]
        self.batch_size = 32
        # DDoS detection thresholds
        self.DDOS_THRESHOLDS = {
            'HIGH_PACKET_RATE': 1000,  # packets per second
            'HIGH_SYN_RATIO': 0.7,    # 70% SYN packets
            'LOW_IAT': 0.001,         # 1ms between packets
            'HIGH_FLOW_RATE': 100000, # bytes per second
            'MIN_PACKETS_FOR_DDOS': 50 # minimum packets to consider DDoS
        }
        self.load_model()

    def load_model(self):
        """Load the trained model from the .h5 file"""
        try:
            model_path = os.path.join(os.path.dirname(__file__), 'network_anomaly_model.h5')
            self.model = load_model(model_path)
            logging.info("Model loaded successfully")
        except Exception as e:
            logging.error(f"Error loading model: {str(e)}")
            raise

    def calculate_flow_stats(self, packets):
        """Calculate flow statistics from raw packets"""
        if not packets:
            return None
            
        # Group packets by flow (src, dst, dst_port)
        flows = {}
        for packet in packets:
            flow_id = f"{packet['src']}:{packet['dst']}:{packet['dst_port']}"
            if flow_id not in flows:
                flows[flow_id] = {
                    'packets': [],
                    'start_time': float('inf'),
                    'end_time': 0,
                    'syn_count': 0,
                    'total_bytes': 0
                }
            
            flow = flows[flow_id]
            flow['packets'].append(packet)
            flow['start_time'] = min(flow['start_time'], packet['timestamp'])
            flow['end_time'] = max(flow['end_time'], packet['timestamp'])
            flow['total_bytes'] += packet['length']
            if packet.get('tcp_flags', {}).get('SYN', 0):
                flow['syn_count'] += 1
        
        # Process each flow
        flow_features = []
        for flow_id, flow in flows.items():
            packets = flow['packets']
            if len(packets) < 2:  # Skip flows with single packet
                continue
                
            # Calculate time-based features
            flow_duration = (flow['end_time'] - flow['start_time']) * 1000000  # microseconds
            if flow_duration == 0:
                flow_duration = 1
                
            # Calculate packet intervals
            timestamps = sorted([p['timestamp'] for p in packets])
            intervals = np.diff(timestamps) * 1000000  # microseconds
            
            # Basic features
            packet_lengths = [p['length'] for p in packets]
            total_length = sum(packet_lengths)
            packet_count = len(packets)
            
            # DDoS specific calculations
            packet_rate = packet_count / (flow_duration / 1000000)  # packets per second
            bytes_rate = total_length / (flow_duration / 1000000)  # bytes per second
            syn_ratio = flow['syn_count'] / packet_count
            avg_interval = np.mean(intervals) if intervals.size > 0 else float('inf')
            
            # Create feature dictionary
            features = {
                "Destination Port": packets[0]['dst_port'],
                "Flow Duration": flow_duration,
                "Total Fwd Packets": packet_count,
                "Total Backward Packets": 0,
                "Total Length of Fwd Packets": total_length,
                "Total Length of Bwd Packets": 0,
                "Fwd Packet Length Max": max(packet_lengths),
                "Fwd Packet Length Min": min(packet_lengths),
                "Fwd Packet Length Mean": np.mean(packet_lengths),
                "Fwd Packet Length Std": np.std(packet_lengths),
                "Flow Bytes/s": bytes_rate,
                "Flow Packets/s": packet_rate,
                "Flow IAT Mean": np.mean(intervals) if intervals.size > 0 else 0,
                "Flow IAT Std": np.std(intervals) if intervals.size > 0 else 0,
                "Flow IAT Max": np.max(intervals) if intervals.size > 0 else 0,
                "Flow IAT Min": np.min(intervals) if intervals.size > 0 else 0,
                "Fwd IAT Total": np.sum(intervals) if intervals.size > 0 else 0,
                "Fwd IAT Mean": np.mean(intervals) if intervals.size > 0 else 0,
                "Fwd IAT Std": np.std(intervals) if intervals.size > 0 else 0,
                "Fwd IAT Max": np.max(intervals) if intervals.size > 0 else 0,
                "Fwd IAT Min": np.min(intervals) if intervals.size > 0 else 0,
                "SYN Flag Count": flow['syn_count'],
                "ACK Flag Count": sum(1 for p in packets if p.get('tcp_flags', {}).get('ACK', 0)),
                "PSH Flag Count": sum(1 for p in packets if p.get('tcp_flags', {}).get('PSH', 0)),
                "RST Flag Count": sum(1 for p in packets if p.get('tcp_flags', {}).get('RST', 0)),
                "FIN Flag Count": sum(1 for p in packets if p.get('tcp_flags', {}).get('FIN', 0)),
                "URG Flag Count": sum(1 for p in packets if p.get('tcp_flags', {}).get('URG', 0)),
                "Fwd Header Length": 20 * packet_count,  # Minimum TCP header size
                "Min Packet Length": min(packet_lengths),
                "Max Packet Length": max(packet_lengths),
                "Packet Length Mean": np.mean(packet_lengths),
                "Packet Length Std": np.std(packet_lengths),
                "Packet Length Variance": np.var(packet_lengths),
                # DDoS specific features
                "Packet Rate": packet_rate,
                "Bytes Rate": bytes_rate,
                "SYN Ratio": syn_ratio,
                "Average Interval": avg_interval
            }
            
            # Fill remaining features with defaults
            for feature in self.feature_names:
                if feature not in features:
                    features[feature] = 0.0
                    
            flow_features.append(features)
            
        return flow_features

    def is_ddos_attack(self, flow_features):
        """Check if flow features indicate a DDoS attack"""
        if not flow_features:
            return False
            
        for features in flow_features:
            if (features['Packet Rate'] > self.DDOS_THRESHOLDS['HIGH_PACKET_RATE'] and
                features['SYN Ratio'] > self.DDOS_THRESHOLDS['HIGH_SYN_RATIO'] and
                features['Average Interval'] < self.DDOS_THRESHOLDS['LOW_IAT'] and
                features['Total Fwd Packets'] >= self.DDOS_THRESHOLDS['MIN_PACKETS_FOR_DDOS']):
                return True
        return False

    def preprocess_packets(self, packets):
        """Transform raw packets into model features"""
        try:
            flow_features = self.calculate_flow_stats(packets)
            if not flow_features:
                return np.array([])
                
            # Convert to feature vectors
            feature_vectors = []
            for features in flow_features:
                vector = []
                for feature in self.feature_names:
                    vector.append(float(features.get(feature, 0)))
                feature_vectors.append(vector)
                
            return np.array(feature_vectors)
            
        except Exception as e:
            logging.error(f"Error preprocessing packets: {str(e)}")
            raise

    def analyze_batch(self, packets):
        """Analyze multiple packets efficiently in batches"""
        try:
            if not packets:
                return {
                    'total_packets': 0,
                    'anomaly_count': 0,
                    'anomaly_rate': 0,
                    'status': 'normal',
                    'predictions': []
                }

            # Calculate flow features
            flow_features = self.calculate_flow_stats(packets)
            if not flow_features:
                return {
                    'total_packets': len(packets),
                    'anomaly_count': 0,
                    'anomaly_rate': 0,
                    'status': 'normal',
                    'predictions': []
                }

            # Check for DDoS attack patterns
            ddos_detected = self.is_ddos_attack(flow_features)

            # Preprocess for model prediction
            processed_data = self.preprocess_packets(packets)
            if len(processed_data) == 0:
                return {
                    'total_packets': len(packets),
                    'anomaly_count': 0,
                    'anomaly_rate': 0,
                    'status': 'normal',
                    'predictions': []
                }

            # Make predictions
            predictions = self.model.predict(processed_data, batch_size=self.batch_size, verbose=0)
            predictions = predictions.flatten()

            # Combine model predictions with DDoS detection
            anomaly_mask = (predictions > 0.3) | ddos_detected
            anomaly_count = np.sum(anomaly_mask)
            total_flows = len(processed_data)
            anomaly_rate = float(anomaly_count) / total_flows

            return {
                'total_packets': len(packets),
                'total_flows': total_flows,
                'anomaly_count': int(anomaly_count),
                'anomaly_rate': float(anomaly_rate),
                'status': 'alert' if (anomaly_rate > 0.2 or ddos_detected) else 'normal',
                'predictions': predictions.tolist(),
                'ddos_detected': ddos_detected
            }

        except Exception as e:
            logging.error(f"Error analyzing batch: {str(e)}")
            return {
                'error': str(e),
                'status': 'error'
            }

# Create a singleton instance
anomaly_detector = NetworkAnomalyDetector()