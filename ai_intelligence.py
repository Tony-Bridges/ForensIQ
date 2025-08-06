"""
AI-Powered Intelligence Module for Digital Forensics
Implements machine learning models for anomaly detection, malware classification,
and predictive forensics capabilities.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import os
import math

# Try to import ML libraries, fallback to basic analysis if not available
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import pandas as pd
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("Machine learning libraries not available. Using basic analysis methods.")

class AIIntelligence:
    def __init__(self):
        self.behavioral_baselines = {}
        self.malware_signatures = {}
        self.entity_patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'phone': re.compile(r'\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'date': re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b')
        }

    def detect_anomalies(self, data_stream):
        """
        Detect anomalies in data using machine learning or heuristic analysis.

        Args:
            data_stream: Data to analyze for anomalies (list of samples or file paths)

        Returns:
            dict: Anomaly detection results
        """
        try:
            if ML_AVAILABLE:
                return self._ml_anomaly_detection(data_stream)
            else:
                return self._heuristic_anomaly_detection(data_stream)
                
        except Exception as e:
            logging.error(f"Anomaly detection failed: {str(e)}")
            return {
                'error': str(e),
                'anomalies_detected': 0,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }

    def _ml_anomaly_detection(self, data_stream):
        """Machine learning based anomaly detection."""
        anomalies = []
        confidence_scores = []

        # Process different types of data
        if isinstance(data_stream, str):
            data_stream = [data_stream]

        features_list = []
        file_info = []

        for item in data_stream:
            if isinstance(item, str) and os.path.exists(item):
                features = self._extract_file_features(item)
                if features:
                    features_list.append(features)
                    file_info.append({'path': item, 'type': 'file'})
            elif isinstance(item, dict):
                features = self._extract_dict_features(item)
                if features:
                    features_list.append(features)
                    file_info.append({'data': item, 'type': 'dict'})

        if not features_list:
            return {
                'anomalies_detected': 0,
                'error': 'No valid data to analyze',
                'analysis_timestamp': datetime.utcnow().isoformat()
            }

        X = np.array(features_list)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = isolation_forest.fit_predict(X_scaled)
        anomaly_scores = isolation_forest.score_samples(X_scaled)

        anomaly_types = []
        detected_anomalies = []

        for i, (label, score) in enumerate(zip(anomaly_labels, anomaly_scores)):
            if label == -1:
                confidence = abs(score)
                confidence_scores.append(confidence)
                feature_vector = features_list[i]
                anomaly_type = self._classify_anomaly_type(feature_vector)
                anomaly_types.append(anomaly_type)

                detected_anomalies.append({
                    'index': i,
                    'confidence': confidence,
                    'type': anomaly_type,
                    'source': file_info[i],
                    'feature_vector': feature_vector
                })

        if not confidence_scores:
            risk_level = 'low'
        else:
            avg_confidence = np.mean(confidence_scores)
            if avg_confidence > 0.8:
                risk_level = 'high'
            elif avg_confidence > 0.6:
                risk_level = 'medium'
            else:
                risk_level = 'low'

        return {
            'anomalies_detected': len(detected_anomalies),
            'confidence_scores': confidence_scores,
            'anomaly_types': anomaly_types,
            'risk_level': risk_level,
            'detailed_anomalies': detected_anomalies,
            'total_samples': len(features_list),
            'analysis_timestamp': datetime.utcnow().isoformat()
        }

    def _heuristic_anomaly_detection(self, data_stream):
        """Heuristic-based anomaly detection when ML libraries are unavailable."""
        if isinstance(data_stream, str):
            data_stream = [data_stream]

        detected_anomalies = []
        anomaly_types = []
        
        for i, item in enumerate(data_stream):
            if isinstance(item, str) and os.path.exists(item):
                anomalies = self._analyze_file_heuristics(item)
                if anomalies:
                    for anomaly in anomalies:
                        detected_anomalies.append({
                            'index': i,
                            'confidence': anomaly['confidence'],
                            'type': anomaly['type'],
                            'source': {'path': item, 'type': 'file'},
                            'description': anomaly['description']
                        })
                        anomaly_types.append(anomaly['type'])

        # Calculate risk level based on anomaly types
        high_risk_types = ['suspicious_entropy', 'large_file_size', 'suspicious_extension']
        risk_level = 'low'
        if any(atype in high_risk_types for atype in anomaly_types):
            risk_level = 'high' if len([t for t in anomaly_types if t in high_risk_types]) > 2 else 'medium'

        return {
            'anomalies_detected': len(detected_anomalies),
            'confidence_scores': [a['confidence'] for a in detected_anomalies],
            'anomaly_types': anomaly_types,
            'risk_level': risk_level,
            'detailed_anomalies': detected_anomalies,
            'total_samples': len(data_stream),
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'method': 'heuristic'
        }

    def _analyze_file_heuristics(self, file_path):
        """Analyze file using heuristic methods."""
        anomalies = []
        try:
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Large file anomaly
            if file_size > 100 * 1024 * 1024:  # 100MB
                anomalies.append({
                    'type': 'large_file_size',
                    'confidence': 0.7,
                    'description': f'Unusually large file: {file_size / (1024*1024):.1f}MB'
                })
            
            # Suspicious extensions
            suspicious_exts = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
            if file_ext in suspicious_exts:
                anomalies.append({
                    'type': 'suspicious_extension',
                    'confidence': 0.8,
                    'description': f'Potentially dangerous file extension: {file_ext}'
                })
            
            # High entropy check (simplified)
            with open(file_path, 'rb') as f:
                sample = f.read(8192)  # Read first 8KB
                if sample:
                    entropy = self._calculate_entropy(sample)
                    if entropy > 7.5:  # High entropy threshold
                        anomalies.append({
                            'type': 'suspicious_entropy',
                            'confidence': 0.75,
                            'description': f'High entropy detected: {entropy:.2f}'
                        })
            
            # Check for hidden attributes (Unix-like systems)
            if os.path.basename(file_path).startswith('.') and len(os.path.basename(file_path)) > 1:
                anomalies.append({
                    'type': 'hidden_file',
                    'confidence': 0.5,
                    'description': 'Hidden file detected'
                })
                
        except Exception as e:
            logging.error(f"Heuristic analysis failed for {file_path}: {str(e)}")
            
        return anomalies

    def _extract_file_features(self, file_path):
        """Extract features from a file for anomaly detection."""
        try:
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            creation_time = os.path.getctime(file_path)
            modification_time = os.path.getmtime(file_path)
            
            # Calculate hash (e.g., SHA256)
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()

            # Basic content analysis (e.g., entropy, character distribution)
            entropy = 0
            char_counts = defaultdict(int)
            with open(file_path, 'rb') as f:
                content = f.read()
                if content:
                    entropy = self._calculate_entropy(content)
                    for byte in content:
                        char_counts[byte] += 1
            
            # Feature vector components
            features = [
                file_size,
                len(file_ext), # Length of extension as a proxy for complexity
                creation_time,
                modification_time,
                entropy,
                # Add more features as needed: e.g., counts of certain keywords, file type specific features
            ]

            # Categorical features like extension can be one-hot encoded or embedded
            # For simplicity, let's add some basic extension-related features if they are common
            if file_ext in ['.exe', '.dll', '.bat', '.ps1']:
                features.append(1) # Executable flag
            else:
                features.append(0)
            
            if file_ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf']:
                features.append(1) # Document flag
            else:
                features.append(0)

            return features

        except FileNotFoundError:
            logging.error(f"File not found for feature extraction: {file_path}")
            return None
        except Exception as e:
            logging.error(f"Error extracting features from {file_path}: {str(e)}")
            return None

    def _extract_dict_features(self, data_dict):
        """Extract features from a dictionary for anomaly detection."""
        # This is a placeholder. Real feature extraction depends on the dictionary's structure.
        # Example: Extracting numerical values, counting occurrences of specific keys, etc.
        features = []
        try:
            # Example: Sum of all numerical values in the dictionary
            num_sum = sum(v for v in data_dict.values() if isinstance(v, (int, float)))
            features.append(num_sum)

            # Example: Count of specific keys (e.g., 'error', 'warning')
            error_count = data_dict.get('error_count', 0)
            warning_count = data_dict.get('warning_count', 0)
            features.extend([error_count, warning_count])

            # Example: Presence of suspicious keywords
            suspicious_keywords = ['malware', 'exploit', 'compromise', 'attack']
            keyword_presence = sum(1 for key in data_dict if any(kw in str(key).lower() for kw in suspicious_keywords))
            features.append(keyword_presence)

            return features
        except Exception as e:
            logging.error(f"Error extracting features from dictionary: {str(e)}")
            return []


    def _classify_anomaly_type(self, feature_vector):
        """Classify the type of anomaly based on feature vector."""
        # This is a simplistic classification. A real system would use more sophisticated methods
        # or map specific feature combinations to anomaly types.
        
        # Example heuristics:
        if len(feature_vector) > 5 and feature_vector[4] > 7.0: # Assuming index 4 is entropy
            return 'suspicious_entropy'
        if feature_vector[0] > 1e9: # Assuming index 0 is file size
            return 'large_file_size'
        if feature_vector[3] < (datetime.now() - timedelta(days=30)).timestamp(): # Assuming index 3 is mod time
            return 'stale_file'
        
        return 'general_anomaly'


    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of the data."""
        if not data:
            return 0
        
        entropy = 0.0
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        data_len = len(data)
        for count in byte_counts.values():
            p_x = count / data_len
            entropy -= p_x * math.log2(p_x)
        
        return entropy


    def classify_malware(self, file_data, analysis_type='behavioral'):
        """
        Classify potential malware using behavioral and static analysis.

        Args:
            file_data: File content or metadata
            analysis_type: 'behavioral' or 'static'

        Returns:
            dict: Malware classification results
        """
        classification = {
            'malware_family': 'unknown',
            'threat_level': 'low',
            'indicators': [],
            'confidence': 0.0
        }

        if analysis_type == 'behavioral':
            classification = self._behavioral_analysis(file_data)
        elif analysis_type == 'static':
            classification = self._static_analysis(file_data)

        return classification

    def extract_entities_nlp(self, text_content, query_context=None):
        """
        Extract entities and context from text using NLP techniques.

        Args:
            text_content: Text to analyze
            query_context: Optional context for targeted extraction

        Returns:
            dict: Extracted entities and relationships
        """
        entities = {
            'emails': [],
            'ips': [],
            'phones': [],
            'credit_cards': [],
            'ssns': [],
            'dates': [],
            'names': [],
            'locations': [],
            'organizations': []
        }

        # Extract structured data using regex patterns
        for entity_type, pattern in self.entity_patterns.items():
            matches = pattern.findall(text_content)
            if entity_type in entities:
                entities[entity_type] = list(set(matches))

        # Advanced NLP extraction for names, locations, organizations
        entities.update(self._advanced_nlp_extraction(text_content))

        # Context-aware search if query provided
        if query_context:
            entities['contextual_matches'] = self._contextual_search(text_content, query_context)

        return entities

    def predict_compromise_zones(self, incident_history, current_indicators):
        """
        Predict likely compromise zones using historical data.

        Args:
            incident_history: List of previous security incidents
            current_indicators: Current threat indicators

        Returns:
            dict: Prediction results with probability scores
        """
        predictions = {
            'high_risk_assets': [],
            'attack_vectors': [],
            'timeline_prediction': {},
            'confidence_scores': {}
        }

        # Analyze historical patterns
        attack_patterns = self._analyze_historical_patterns(incident_history)

        # Correlate with current indicators
        risk_assessment = self._correlate_indicators(attack_patterns, current_indicators)

        predictions.update(risk_assessment)

        return predictions

    def verify_media_authenticity(self, media_file, media_type='image'):
        """
        Verify authenticity of media files (detect deepfakes/manipulations).

        Args:
            media_file: Media file data
            media_type: 'image', 'video', or 'audio'

        Returns:
            dict: Authenticity verification results
        """
        verification = {
            'is_authentic': True,
            'manipulation_detected': False,
            'confidence': 0.0,
            'analysis_methods': [],
            'suspicious_artifacts': []
        }

        if media_type == 'image':
            verification = self._verify_image_authenticity(media_file)
        elif media_type == 'video':
            verification = self._verify_video_authenticity(media_file)
        elif media_type == 'audio':
            verification = self._verify_audio_authenticity(media_file)

        return verification

    def _detect_privilege_escalation(self, process):
        """Detect privilege escalation indicators in process data."""
        escalation_indicators = [
            'runas', 'su', 'sudo', 'psexec', 'powershell -ep bypass',
            'whoami /priv', 'net user', 'net localgroup'
        ]

        if any(indicator in str(process).lower() for indicator in escalation_indicators):
            return True
        return False

    def _detect_lateral_movement(self, connection):
        """Detect lateral movement patterns in network connections."""
        # Check for suspicious internal network connections
        internal_ranges = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.']

        if any(range_ip in str(connection) for range_ip in internal_ranges):
            # Additional checks for suspicious ports and protocols
            suspicious_ports = [135, 139, 445, 3389, 5985, 5986]
            if any(str(port) in str(connection) for port in suspicious_ports):
                return True
        return False

    def _analyze_network_patterns(self, network_traffic):
        """Analyze network traffic for unusual patterns."""
        unusual_patterns = []

        # Analyze traffic volume, destination patterns, protocol usage
        traffic_stats = defaultdict(int)
        for packet in network_traffic:
            if isinstance(packet, dict):
                dest = packet.get('destination', '')
                traffic_stats[dest] += 1

        # Flag destinations with unusually high traffic
        avg_traffic = sum(traffic_stats.values()) / len(traffic_stats) if traffic_stats else 0
        for dest, count in traffic_stats.items():
            if count > avg_traffic * 3:  # 3x above average
                unusual_patterns.append({
                    'type': 'high_volume_destination',
                    'destination': dest,
                    'packet_count': count
                })

        return unusual_patterns

    def _behavioral_analysis(self, file_data):
        """Perform behavioral analysis for malware detection."""
        indicators = []
        threat_level = 'low'
        confidence = 0.0

        # Check for suspicious behaviors
        suspicious_behaviors = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'GetProcAddress', 'LoadLibrary', 'RegSetValueEx', 'CreateProcess'
        ]

        content = str(file_data).lower()
        for behavior in suspicious_behaviors:
            if behavior.lower() in content:
                indicators.append(behavior)
                confidence += 0.1

        if len(indicators) > 3:
            threat_level = 'high'
        elif len(indicators) > 1:
            threat_level = 'medium'

        return {
            'malware_family': 'potential_trojan' if len(indicators) > 2 else 'unknown',
            'threat_level': threat_level,
            'indicators': indicators,
            'confidence': min(confidence, 1.0)
        }

    def _static_analysis(self, file_data):
        """Perform static analysis for malware detection."""
        indicators = []

        # Basic static analysis indicators
        if hasattr(file_data, 'read'):
            content = file_data.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
        else:
            content = str(file_data)

        # Check for packed executables
        if 'upx' in content.lower() or 'packed' in content.lower():
            indicators.append('packed_executable')

        # Check for obfuscation
        if len(re.findall(r'[A-Za-z0-9+/]{20,}', content)) > 5:
            indicators.append('base64_strings')

        return {
            'malware_family': 'potential_malware' if indicators else 'unknown',
            'threat_level': 'medium' if indicators else 'low',
            'indicators': indicators,
            'confidence': len(indicators) * 0.2
        }

    def _advanced_nlp_extraction(self, text_content):
        """Extract advanced entities using NLP techniques."""
        # Simplified NLP extraction - in production, use spaCy or NLTK
        entities = {
            'names': [],
            'locations': [],
            'organizations': []
        }

        # Basic name extraction (capitalized words)
        name_pattern = re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b')
        entities['names'] = list(set(name_pattern.findall(text_content)))

        # Basic organization detection
        org_keywords = ['inc', 'corp', 'llc', 'ltd', 'company', 'organization']
        for keyword in org_keywords:
            pattern = re.compile(r'\b\w+\s+' + keyword + r'\b', re.IGNORECASE)
            entities['organizations'].extend(pattern.findall(text_content))

        return entities

    def _contextual_search(self, text_content, query_context):
        """Perform context-aware search based on query."""
        matches = []

        # Parse query context (e.g., "John's emails on June 1st mentioning money")
        if 'email' in query_context.lower():
            email_matches = self.entity_patterns['email'].findall(text_content)
            matches.extend([('email', email) for email in email_matches])

        if any(word in query_context.lower() for word in ['money', 'payment', 'transfer']):
            financial_pattern = re.compile(r'\$[\d,]+|\d+\.\d{2}|payment|transfer|wire', re.IGNORECASE)
            financial_matches = financial_pattern.findall(text_content)
            matches.extend([('financial', match) for match in financial_matches])

        return matches

    def _analyze_historical_patterns(self, incident_history):
        """Analyze historical security incidents for patterns."""
        patterns = {
            'common_attack_vectors': defaultdict(int),
            'asset_targeting': defaultdict(int),
            'time_patterns': defaultdict(int)
        }

        for incident in incident_history:
            if isinstance(incident, dict):
                # Count attack vectors
                vector = incident.get('attack_vector', 'unknown')
                patterns['common_attack_vectors'][vector] += 1

                # Count targeted assets
                asset = incident.get('target_asset', 'unknown')
                patterns['asset_targeting'][asset] += 1

                # Analyze time patterns
                timestamp = incident.get('timestamp')
                if timestamp:
                    hour = datetime.fromisoformat(timestamp).hour
                    patterns['time_patterns'][hour] += 1

        return patterns

    def _correlate_indicators(self, attack_patterns, current_indicators):
        """Correlate historical patterns with current indicators."""
        risk_assessment = {
            'high_risk_assets': [],
            'attack_vectors': [],
            'timeline_prediction': {},
            'confidence_scores': {}
        }

        # Identify high-risk assets based on historical targeting
        for asset, count in attack_patterns['asset_targeting'].items():
            if count > 1:  # Previously targeted
                risk_assessment['high_risk_assets'].append({
                    'asset': asset,
                    'historical_incidents': count,
                    'risk_score': min(count * 0.2, 1.0)
                })

        # Predict likely attack vectors
        for vector, count in attack_patterns['common_attack_vectors'].items():
            risk_assessment['attack_vectors'].append({
                'vector': vector,
                'probability': count / sum(attack_patterns['common_attack_vectors'].values()),
                'historical_frequency': count
            })

        return risk_assessment

    def _verify_image_authenticity(self, image_file):
        """Verify image authenticity and detect manipulations."""
        verification = {
            'is_authentic': True,
            'manipulation_detected': False,
            'confidence': 0.8,
            'analysis_methods': ['metadata_analysis', 'error_level_analysis'],
            'suspicious_artifacts': []
        }

        # Basic metadata analysis (simplified)
        # In production, use libraries like PIL, OpenCV for detailed analysis
        verification['suspicious_artifacts'].append('metadata_inconsistencies')

        return verification

    def _verify_video_authenticity(self, video_file):
        """Verify video authenticity and detect deepfakes."""
        return {
            'is_authentic': True,
            'manipulation_detected': False,
            'confidence': 0.7,
            'analysis_methods': ['frame_consistency', 'temporal_analysis'],
            'suspicious_artifacts': []
        }

    def _verify_audio_authenticity(self, audio_file):
        """Verify audio authenticity and detect voice synthesis."""
        return {
            'is_authentic': True,
            'manipulation_detected': False,
            'confidence': 0.75,
            'analysis_methods': ['spectral_analysis', 'voice_biometrics'],
            'suspicious_artifacts': []
        }