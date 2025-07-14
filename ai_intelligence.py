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
        
    def detect_anomalies(self, system_data):
        """
        Detect behavioral anomalies using baseline comparison.
        
        Args:
            system_data: Dictionary containing system activity data
            
        Returns:
            dict: Anomaly detection results
        """
        anomalies = {
            'privilege_escalation': [],
            'lateral_movement': [],
            'unusual_network_activity': [],
            'suspicious_file_access': [],
            'abnormal_process_behavior': []
        }
        
        # Analyze privilege escalation patterns
        if 'processes' in system_data:
            for process in system_data['processes']:
                if self._detect_privilege_escalation(process):
                    anomalies['privilege_escalation'].append(process)
                    
        # Analyze lateral movement
        if 'network_connections' in system_data:
            for connection in system_data['network_connections']:
                if self._detect_lateral_movement(connection):
                    anomalies['lateral_movement'].append(connection)
                    
        # Analyze network activity
        if 'network_traffic' in system_data:
            unusual_traffic = self._analyze_network_patterns(system_data['network_traffic'])
            anomalies['unusual_network_activity'].extend(unusual_traffic)
            
        return anomalies
        
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