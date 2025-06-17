import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import logging
import json

class AnomalyDetector:
    def __init__(self, config: Dict[str, Any], mongo_handler):
        self.config = config
        self.mongo_handler = mongo_handler
        self.logger = logging.getLogger(__name__)
        
        # Model configuration
        self.anomaly_config = config.get('anomaly_detection', {})
        self.enabled = self.anomaly_config.get('enabled', True)
        self.model_type = self.anomaly_config.get('model_type', 'isolation_forest')
        self.contamination = self.anomaly_config.get('contamination', 0.1)
        self.retrain_interval = self.anomaly_config.get('retrain_interval', 3600)
        
        # Model and preprocessing components
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = []
        self.is_model_trained = False
        self.last_training_time = None
        
        # Model file paths
        self.model_dir = 'models'
        self.model_file = os.path.join(self.model_dir, 'anomaly_model.joblib')
        self.scaler_file = os.path.join(self.model_dir, 'scaler.joblib')
        self.encoders_file = os.path.join(self.model_dir, 'label_encoders.joblib')
        self.features_file = os.path.join(self.model_dir, 'feature_columns.json')
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Feature extraction configuration
        self.categorical_features = ['protocol', 'src_ip', 'dst_ip']
        self.numerical_features = [
            'size', 'src_port', 'dst_port', 'payload_size', 'ttl',
            'hour', 'day_of_week', 'packet_rate', 'unique_ports',
            'connection_count', 'payload_entropy'
        ]
        
        # Load existing model if available
        self.load_model()
        
        # Training data buffer
        self.training_buffer = []
        self.buffer_size = 10000
    
    def extract_features(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from packet data for anomaly detection"""
        try:
            features = {}
            
            # Basic packet features
            features['size'] = packet_data.get('size', 0)
            features['payload_size'] = packet_data.get('payload_size', 0)
            features['ttl'] = packet_data.get('ttl', 0)
            features['src_port'] = packet_data.get('src_port', 0) or 0
            features['dst_port'] = packet_data.get('dst_port', 0) or 0
            
            # Protocol
            features['protocol'] = packet_data.get('protocol', 'UNKNOWN')
            
            # IP addresses (will be encoded)
            features['src_ip'] = packet_data.get('src_ip', '0.0.0.0') or '0.0.0.0'
            features['dst_ip'] = packet_data.get('dst_ip', '0.0.0.0') or '0.0.0.0'
            
            # Time-based features
            timestamp = packet_data.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.utcnow()
            
            features['hour'] = timestamp.hour
            features['day_of_week'] = timestamp.weekday()
            
            # Calculate payload entropy
            features['payload_entropy'] = self._calculate_entropy(
                packet_data.get('payload_sample', '')
            )
            
            # Statistical features (calculated from recent traffic)
            features.update(self._calculate_statistical_features(packet_data))
            
            return features
        
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return {}
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0.0
            
            # Convert hex string to bytes if needed
            if isinstance(data, str) and len(data) % 2 == 0:
                try:
                    data = bytes.fromhex(data)
                except ValueError:
                    data = data.encode('utf-8')
            elif isinstance(data, str):
                data = data.encode('utf-8')
            
            # Calculate byte frequency
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * np.log2(probability)
            
            return entropy
        
        except Exception as e:
            self.logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    def _calculate_statistical_features(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate statistical features from recent traffic"""
        try:
            features = {}
            
            # Get recent packets (last 5 minutes)
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=5)
            
            recent_packets = self.mongo_handler.get_packets(
                limit=1000,
                filters={'timestamp': {'$gte': start_time, '$lte': end_time}}
            )
            
            if not recent_packets:
                features.update({
                    'packet_rate': 0,
                    'unique_ports': 0,
                    'connection_count': 0
                })
                return features
            
            # Packet rate (packets per minute)
            time_window = (end_time - start_time).total_seconds() / 60
            features['packet_rate'] = len(recent_packets) / max(time_window, 1)
            
            # Unique destination ports
            unique_ports = set()
            connections = set()
            
            for packet in recent_packets:
                dst_port = packet.get('dst_port')
                if dst_port:
                    unique_ports.add(dst_port)
                
                src_ip = packet.get('src_ip')
                dst_ip = packet.get('dst_ip')
                if src_ip and dst_ip:
                    connections.add(f"{src_ip}->{dst_ip}")
            
            features['unique_ports'] = len(unique_ports)
            features['connection_count'] = len(connections)
            
            return features
        
        except Exception as e:
            self.logger.error(f"Error calculating statistical features: {e}")
            return {
                'packet_rate': 0,
                'unique_ports': 0,
                'connection_count': 0
            }
    
    def prepare_training_data(self, limit: int = 10000) -> Optional[pd.DataFrame]:
        """Prepare training data from stored packets"""
        try:
            # Get recent packets for training
            packets = self.mongo_handler.get_packets(limit=limit)
            
            if len(packets) < 100:
                self.logger.warning("Insufficient data for training (need at least 100 packets)")
                return None
            
            # Extract features from all packets
            training_data = []
            for packet in packets:
                features = self.extract_features(packet)
                if features:
                    training_data.append(features)
            
            if not training_data:
                self.logger.error("No valid features extracted from training data")
                return None
            
            df = pd.DataFrame(training_data)
            
            # Handle missing values
            df = df.fillna(0)
            
            self.logger.info(f"Prepared training data with {len(df)} samples and {len(df.columns)} features")
            return df
        
        except Exception as e:
            self.logger.error(f"Error preparing training data: {e}")
            return None
    
    def train_model(self, training_data: pd.DataFrame = None) -> bool:
        """Train the anomaly detection model"""
        try:
            if not self.enabled:
                self.logger.info("Anomaly detection is disabled")
                return False
            
            if training_data is None:
                training_data = self.prepare_training_data()
            
            if training_data is None or training_data.empty:
                self.logger.error("No training data available")
                return False
            
            self.logger.info("Starting anomaly detection model training...")
            
            # Store feature columns
            self.feature_columns = list(training_data.columns)
            
            # Encode categorical features
            for feature in self.categorical_features:
                if feature in training_data.columns:
                    if feature not in self.label_encoders:
                        self.label_encoders[feature] = LabelEncoder()
                    
                    training_data[feature] = self.label_encoders[feature].fit_transform(
                        training_data[feature].astype(str)
                    )
            
            # Scale numerical features
            X = training_data[self.feature_columns].values
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model based on configuration
            if self.model_type == 'isolation_forest':
                self.model = IsolationForest(
                    contamination=self.contamination,
                    random_state=42,
                    n_jobs=-1
                )
                self.model.fit(X_scaled)
            
            else:
                self.logger.error(f"Unsupported model type: {self.model_type}")
                return False
            
            self.is_model_trained = True
            self.last_training_time = datetime.utcnow()
            
            # Save the model
            self.save_model()
            
            self.logger.info(f"Model training completed. Model type: {self.model_type}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            return False
    
    def save_model(self):
        """Save the trained model and preprocessing components"""
        try:
            if self.model is not None:
                joblib.dump(self.model, self.model_file)
            
            joblib.dump(self.scaler, self.scaler_file)
            joblib.dump(self.label_encoders, self.encoders_file)
            
            with open(self.features_file, 'w') as f:
                json.dump(self.feature_columns, f)
            
            self.logger.info("Model saved successfully")
        
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def load_model(self) -> bool:
        """Load previously trained model and preprocessing components"""
        try:
            if not all(os.path.exists(f) for f in [self.model_file, self.scaler_file, self.encoders_file, self.features_file]):
                self.logger.info("No existing model found")
                return False
            
            self.model = joblib.load(self.model_file)
            self.scaler = joblib.load(self.scaler_file)
            self.label_encoders = joblib.load(self.encoders_file)
            
            with open(self.features_file, 'r') as f:
                self.feature_columns = json.load(f)
            
            self.is_model_trained = True
            self.last_training_time = datetime.fromtimestamp(os.path.getmtime(self.model_file))
            
            self.logger.info("Model loaded successfully")
            return True
        
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False
    
    def is_anomaly(self, packet_data: Dict[str, Any]) -> bool:
        """Check if packet is anomalous"""
        try:
            if not self.enabled or not self.is_model_trained:
                return False
            
            # Check if model needs retraining
            if self._needs_retraining():
                self.logger.info("Model needs retraining")
                # Add to training buffer for next training cycle
                self.training_buffer.append(packet_data)
                if len(self.training_buffer) >= self.buffer_size:
                    self._retrain_model()
            
            # Extract features
            features = self.extract_features(packet_data)
            if not features:
                return False
            
            # Predict anomaly
            anomaly_score = self.get_anomaly_score(packet_data)
            return anomaly_score < 0  # Isolation Forest returns negative scores for anomalies
        
        except Exception as e:
            self.logger.error(f"Error checking anomaly: {e}")
            return False
    
    def get_anomaly_score(self, packet_data: Dict[str, Any]) -> float:
        """Get anomaly score for packet"""
        try:
            if not self.enabled or not self.is_model_trained:
                return 0.0
            
            # Extract and prepare features
            features = self.extract_features(packet_data)
            if not features:
                return 0.0
            
            # Convert to DataFrame for consistent processing
            df = pd.DataFrame([features])
            
            # Handle missing columns
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0
            
            # Reorder columns to match training data
            df = df[self.feature_columns]
            
            # Encode categorical features
            for feature in self.categorical_features:
                if feature in df.columns and feature in self.label_encoders:
                    try:
                        df[feature] = self.label_encoders[feature].transform(
                            df[feature].astype(str)
                        )
                    except ValueError:
                        # Handle unseen categories
                        df[feature] = 0
            
            # Scale features
            X = df.values
            X_scaled = self.scaler.transform(X)
            
            # Get anomaly score
            scores = self.model.decision_function(X_scaled)
            return scores[0]
        
        except Exception as e:
            self.logger.error(f"Error getting anomaly score: {e}")
            return 0.0
    
    def _needs_retraining(self) -> bool:
        """Check if model needs retraining"""
        if not self.last_training_time:
            return True
        
        time_since_training = (datetime.utcnow() - self.last_training_time).total_seconds()
        return time_since_training > self.retrain_interval
    
    def _retrain_model(self):
        """Retrain model with buffered data"""
        try:
            if len(self.training_buffer) < 100:
                return
            
            self.logger.info("Retraining model with new data...")
            
            # Get fresh training data
            fresh_data = self.prepare_training_data()
            if fresh_data is not None:
                self.train_model(fresh_data)
                self.training_buffer = []  # Clear buffer after training
        
        except Exception as e:
            self.logger.error(f"Error retraining model: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            'enabled': self.enabled,
            'model_type': self.model_type,
            'is_trained': self.is_model_trained,
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'contamination': self.contamination,
            'feature_count': len(self.feature_columns),
            'feature_columns': self.feature_columns,
            'needs_retraining': self._needs_retraining()
        }
    
    def get_anomaly_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get anomaly detection statistics"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            anomalies = self.mongo_handler.get_anomalies(
                filters={'timestamp': {'$gte': start_time, '$lte': end_time}}
            )
            
            total_packets = len(self.mongo_handler.get_packets(
                filters={'timestamp': {'$gte': start_time, '$lte': end_time}}
            ))
            
            anomaly_rate = (len(anomalies) / max(total_packets, 1)) * 100
            
            # Group anomalies by hour
            hourly_anomalies = {}
            for anomaly in anomalies:
                timestamp = anomaly.get('timestamp')
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                hour = timestamp.hour
                hourly_anomalies[hour] = hourly_anomalies.get(hour, 0) + 1
            
            return {
                'total_anomalies': len(anomalies),
                'total_packets': total_packets,
                'anomaly_rate': anomaly_rate,
                'hourly_breakdown': hourly_anomalies,
                'time_period': f"{hours} hours"
            }
        
        except Exception as e:
            self.logger.error(f"Error getting anomaly statistics: {e}")
            return {}
    
    def enable(self):
        """Enable anomaly detection"""
        self.enabled = True
        self.logger.info("Anomaly detection enabled")
    
    def disable(self):
        """Disable anomaly detection"""
        self.enabled = False
        self.logger.info("Anomaly detection disabled")
    
    def is_trained(self) -> bool:
        """Check if model is trained and ready"""
        return self.is_model_trained and self.model is not None
    
    def force_retrain(self) -> bool:
        """Force model retraining"""
        self.logger.info("Forcing model retraining...")
        return self.train_model()
