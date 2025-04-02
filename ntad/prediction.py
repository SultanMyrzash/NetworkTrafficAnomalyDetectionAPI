import pandas as pd
import numpy as np
import os
import joblib
import tensorflow as tf
import time
import argparse
import json
from datetime import datetime

def predict_ddos(data_path='captured_network_data.csv', 
                model_path='ddos_detection_model.keras', 
                scaler_path='scaler.joblib', 
                encoders_path='label_encoders.joblib',
                output_path=None,
                threshold=0.5):
    """
    Predict DDoS attack types and classes from captured network data
    
    Args:
        data_path: Path to the CSV with captured network data
        model_path: Path to saved model
        scaler_path: Path to saved scaler
        encoders_path: Path to saved label encoders
        output_path: Path to save results (optional)
        threshold: Confidence threshold for attack classification
    
    Returns:
        Dictionary with prediction results
    """
    start_time = time.time()
    
    # Check if files exist
    for path, name in [(data_path, "Data"), (model_path, "Model"), 
                       (scaler_path, "Scaler"), (encoders_path, "Encoders")]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"{name} file not found: {path}")
    
    # Load model and preprocessing objects
    print(f"Loading model from {model_path}")
    model = tf.keras.models.load_model(model_path)
    
    print(f"Loading scaler from {scaler_path}")
    scaler = joblib.load(scaler_path)
    
    print(f"Loading label encoders from {encoders_path}")
    encoders = joblib.load(encoders_path)
    
    # Load data
    print(f"Loading data from {data_path}")
    df = pd.read_csv(data_path)
    
    # Check if data is empty
    if len(df) == 0:
        print("Warning: Empty data file!")
        return {"error": "Empty data file", "flows_analyzed": 0}
    
    print(f"Loaded {len(df)} network flows")
    
    # Make a copy for results
    df_results = df.copy()
    
    # Check and report on data columns
    expected_columns = 77  # 77 traffic feature columns
    if len(df.columns) != expected_columns:
        print(f"Warning: Expected {expected_columns} columns, but found {len(df.columns)}")
        print("This might affect prediction accuracy")
    
    # Scale the features
    print("Preprocessing data...")
    X_scaled = scaler.transform(df)
    
    # Make predictions
    print("Making predictions...")
    raw_predictions = model.predict(X_scaled)
    
    # Get attack type and binary class predictions
    attack_type_probs = raw_predictions[0]
    binary_class_probs = raw_predictions[1]
    
    # Convert to labels
    attack_type_indices = np.argmax(attack_type_probs, axis=1)
    binary_class_indices = np.argmax(binary_class_probs, axis=1)
    
    attack_types = encoders['label_encoder_type'].inverse_transform(attack_type_indices)
    binary_classes = encoders['label_encoder_binary'].inverse_transform(binary_class_indices)
    
    # Get confidence scores
    attack_type_confidence = np.max(attack_type_probs, axis=1)
    binary_class_confidence = np.max(binary_class_probs, axis=1)
    
    # Add predictions to results dataframe
    df_results['predicted_attack_type'] = attack_types
    df_results['attack_type_confidence'] = attack_type_confidence
    df_results['predicted_class'] = binary_classes
    df_results['class_confidence'] = binary_class_confidence
    
    # Filter attacks with confidence above threshold
    high_confidence_attacks = df_results[
        (df_results['predicted_class'] == 'Attack') & 
        (df_results['class_confidence'] >= threshold)
    ]
    
    # Generate summary statistics
    total_flows = len(df_results)
    attack_flows = len(df_results[df_results['predicted_class'] == 'Attack'])
    benign_flows = total_flows - attack_flows
    attack_percentage = (attack_flows / total_flows * 100) if total_flows > 0 else 0
    
    # Count attack types
    attack_type_counts = df_results[df_results['predicted_class'] == 'Attack']['predicted_attack_type'].value_counts().to_dict()
    
    # Highlight high confidence attacks
    high_conf_counts = high_confidence_attacks['predicted_attack_type'].value_counts().to_dict()
    
    # Create results dictionary
    results = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "analysis_time_seconds": round(time.time() - start_time, 2),
        "flows_analyzed": total_flows,
        "detection_summary": {
            "benign_flows": benign_flows,
            "attack_flows": attack_flows,
            "attack_percentage": round(attack_percentage, 2)
        },
        "attack_types": attack_type_counts,
        "high_confidence_attacks": high_conf_counts,
        "threshold_used": threshold
    }
    
    # Save detailed results if output path is provided
    if output_path:
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Save full results to CSV
        df_results.to_csv(output_path, index=False)
        print(f"Detailed results saved to {output_path}")
        
        # Also save a JSON summary
        json_path = os.path.splitext(output_path)[0] + '_summary.json'
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Summary results saved to {json_path}")
    
    # Print summary
    print("\n========= DETECTION RESULTS =========")
    print(f"Total flows analyzed: {total_flows}")
    print(f"Benign flows: {benign_flows} ({round(benign_flows/total_flows*100, 2)}%)")
    print(f"Attack flows: {attack_flows} ({round(attack_flows/total_flows*100, 2)}%)")
    
    if attack_flows > 0:
        print("\nAttack types detected:")
        for attack_type, count in attack_type_counts.items():
            percentage = round(count/attack_flows*100, 2)
            print(f"  {attack_type}: {count} flows ({percentage}%)")
        
        print(f"\nHigh confidence attacks (confidence >= {threshold}):")
        for attack_type, count in high_conf_counts.items():
            print(f"  {attack_type}: {count} flows")
    
    # Check for potential false positives
    if attack_percentage > 80:
        print("\nWARNING: Very high percentage of traffic classified as attacks.")
        print("This may indicate false positives or an ongoing large-scale attack.")
    
    print("=======================================")
    
    return results

def continuous_monitoring(interval=5, **kwargs):
    """
    Continuously monitor and predict on new network data
    
    Args:
        interval: Time between predictions in seconds
        **kwargs: Additional arguments to pass to predict_ddos
    """
    print(f"Starting continuous monitoring (every {interval} seconds)")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            try:
                # Generate timestamp for this prediction run
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                
                # Update output path if provided
                if 'output_path' in kwargs:
                    base_path = kwargs['output_path']
                    kwargs['output_path'] = f"{os.path.splitext(base_path)[0]}_{timestamp}.csv"
                
                # Run prediction
                predict_ddos(**kwargs)
                
            except Exception as e:
                print(f"Error during prediction: {e}")
            
            # Wait for next interval
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\nContinuous monitoring stopped.")

def main():
    """Parse command line arguments and run prediction"""
    parser = argparse.ArgumentParser(description='Predict DDoS attacks from captured network data')
    parser.add_argument('--data', default='captured_network_data.csv', 
                        help='Path to captured network data CSV file')
    parser.add_argument('--model', default='ddos_detection_model.keras',
                        help='Path to trained model file')
    parser.add_argument('--scaler', default='scaler.joblib',
                        help='Path to fitted scaler file')
    parser.add_argument('--encoders', default='label_encoders.joblib',
                        help='Path to label encoders file')
    parser.add_argument('--output', default=None,
                        help='Path to save detailed results (optional)')
    parser.add_argument('--threshold', type=float, default=0.8,
                        help='Confidence threshold for attack classification (0-1)')
    parser.add_argument('--continuous', action='store_true',
                        help='Enable continuous monitoring')
    parser.add_argument('--interval', type=int, default=5,
                        help='Interval between predictions in continuous mode (seconds)')
    
    args = parser.parse_args()
    
    if args.continuous:
        continuous_monitoring(
            interval=args.interval,
            data_path=args.data,
            model_path=args.model,
            scaler_path=args.scaler,
            encoders_path=args.encoders,
            output_path=args.output,
            threshold=args.threshold
        )
    else:
        predict_ddos(
            data_path=args.data,
            model_path=args.model,
            scaler_path=args.scaler,
            encoders_path=args.encoders,
            output_path=args.output,
            threshold=args.threshold
        )

if __name__ == "__main__":
    main()