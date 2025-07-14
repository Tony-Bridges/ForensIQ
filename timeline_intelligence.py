"""
Timeline Intelligence and Correlation Engine
Cross-source timeline reconstruction and event correlation across multiple data sources.
"""
import json
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import re

class TimelineIntelligence:
    def __init__(self):
        self.supported_sources = [
            'mft', 'filesystem', 'registry', 'event_logs', 'browser_history',
            'email', 'network_logs', 'usb_events', 'memory_dumps', 'application_logs'
        ]
        self.event_types = [
            'file_creation', 'file_modification', 'file_deletion', 'file_access',
            'process_execution', 'network_connection', 'registry_modification',
            'user_login', 'usb_insertion', 'email_sent', 'email_received',
            'web_visit', 'download', 'application_start', 'system_event'
        ]
        
    def correlate_timeline(self, data_sources, correlation_rules=None):
        """
        Correlate events across multiple data sources to build unified timeline.
        
        Args:
            data_sources: Dictionary of data sources with their events
            correlation_rules: Rules for event correlation
            
        Returns:
            dict: Correlated timeline results
        """
        if correlation_rules is None:
            correlation_rules = self._get_default_correlation_rules()
            
        correlation_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'unified_timeline': [],
            'correlation_findings': [],
            'suspicious_patterns': [],
            'data_source_summary': {},
            'time_range': {},
            'event_clusters': [],
            'anomalies': [],
            'confidence_scores': {}
        }
        
        try:
            # Normalize and merge events from all sources
            all_events = self._normalize_events(data_sources)
            
            # Create unified timeline
            correlation_results['unified_timeline'] = self._create_unified_timeline(all_events)
            
            # Apply correlation rules
            correlation_results['correlation_findings'] = self._apply_correlation_rules(
                all_events, correlation_rules
            )
            
            # Detect suspicious patterns
            correlation_results['suspicious_patterns'] = self._detect_suspicious_patterns(all_events)
            
            # Create event clusters
            correlation_results['event_clusters'] = self._create_event_clusters(all_events)
            
            # Detect temporal anomalies
            correlation_results['anomalies'] = self._detect_temporal_anomalies(all_events)
            
            # Calculate summary statistics
            correlation_results['data_source_summary'] = self._calculate_source_summary(data_sources)
            correlation_results['time_range'] = self._calculate_time_range(all_events)
            correlation_results['confidence_scores'] = self._calculate_confidence_scores(
                correlation_results
            )
            
        except Exception as e:
            logging.error(f"Timeline correlation failed: {str(e)}")
            correlation_results['error'] = str(e)
            
        return correlation_results
        
    def analyze_attack_chain(self, timeline_events, attack_patterns=None):
        """
        Analyze timeline for attack chain reconstruction.
        
        Args:
            timeline_events: List of timeline events
            attack_patterns: Known attack patterns to match
            
        Returns:
            dict: Attack chain analysis results
        """
        if attack_patterns is None:
            attack_patterns = self._get_default_attack_patterns()
            
        attack_analysis = {
            'timestamp': datetime.utcnow().isoformat(),
            'attack_chains': [],
            'attack_stages': {},
            'indicators_of_compromise': [],
            'lateral_movement': [],
            'persistence_mechanisms': [],
            'data_exfiltration_events': [],
            'timeline_gaps': [],
            'confidence_assessment': {}
        }
        
        try:
            # Identify attack stages
            attack_analysis['attack_stages'] = self._identify_attack_stages(timeline_events)
            
            # Reconstruct attack chains
            attack_analysis['attack_chains'] = self._reconstruct_attack_chains(
                timeline_events, attack_patterns
            )
            
            # Extract indicators of compromise
            attack_analysis['indicators_of_compromise'] = self._extract_iocs(timeline_events)
            
            # Detect lateral movement
            attack_analysis['lateral_movement'] = self._detect_lateral_movement(timeline_events)
            
            # Identify persistence mechanisms
            attack_analysis['persistence_mechanisms'] = self._identify_persistence(timeline_events)
            
            # Detect data exfiltration
            attack_analysis['data_exfiltration_events'] = self._detect_exfiltration_events(
                timeline_events
            )
            
            # Identify timeline gaps
            attack_analysis['timeline_gaps'] = self._identify_timeline_gaps(timeline_events)
            
        except Exception as e:
            logging.error(f"Attack chain analysis failed: {str(e)}")
            attack_analysis['error'] = str(e)
            
        return attack_analysis
        
    def reconstruct_user_activity(self, user_events, user_id=None):
        """
        Reconstruct detailed user activity timeline.
        
        Args:
            user_events: Events associated with specific user
            user_id: User identifier
            
        Returns:
            dict: User activity reconstruction
        """
        user_activity = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'activity_timeline': [],
            'behavior_patterns': {},
            'application_usage': {},
            'file_interactions': [],
            'network_activity': [],
            'anomalous_behavior': [],
            'working_hours_analysis': {},
            'productivity_metrics': {}
        }
        
        try:
            # Create detailed activity timeline
            user_activity['activity_timeline'] = self._create_user_timeline(user_events)
            
            # Analyze behavior patterns
            user_activity['behavior_patterns'] = self._analyze_user_behavior(user_events)
            
            # Analyze application usage
            user_activity['application_usage'] = self._analyze_application_usage(user_events)
            
            # Extract file interactions
            user_activity['file_interactions'] = self._extract_file_interactions(user_events)
            
            # Analyze network activity
            user_activity['network_activity'] = self._analyze_user_network_activity(user_events)
            
            # Detect anomalous behavior
            user_activity['anomalous_behavior'] = self._detect_user_anomalies(user_events)
            
            # Analyze working hours
            user_activity['working_hours_analysis'] = self._analyze_working_hours(user_events)
            
        except Exception as e:
            logging.error(f"User activity reconstruction failed: {str(e)}")
            user_activity['error'] = str(e)
            
        return user_activity
        
    def _normalize_events(self, data_sources):
        """Normalize events from different sources into common format."""
        normalized_events = []
        
        for source_name, source_data in data_sources.items():
            for event in source_data.get('events', []):
                normalized_event = {
                    'timestamp': event.get('timestamp', datetime.utcnow().isoformat()),
                    'source': source_name,
                    'event_type': event.get('type', 'unknown'),
                    'description': event.get('description', ''),
                    'details': event.get('details', {}),
                    'confidence': event.get('confidence', 0.8),
                    'severity': event.get('severity', 'medium')
                }
                normalized_events.append(normalized_event)
                
        # Sort by timestamp
        normalized_events.sort(key=lambda x: x['timestamp'])
        return normalized_events
        
    def _create_unified_timeline(self, events):
        """Create unified timeline from normalized events."""
        timeline = []
        
        for i, event in enumerate(events):
            timeline_entry = {
                'sequence_id': i + 1,
                'timestamp': event['timestamp'],
                'source': event['source'],
                'event_type': event['event_type'],
                'description': event['description'],
                'details': event['details'],
                'related_events': self._find_related_events(event, events),
                'confidence': event['confidence']
            }
            timeline.append(timeline_entry)
            
        return timeline
        
    def _apply_correlation_rules(self, events, correlation_rules):
        """Apply correlation rules to identify related events."""
        correlations = []
        
        for rule in correlation_rules:
            matches = self._find_rule_matches(events, rule)
            if matches:
                correlation = {
                    'rule_name': rule['name'],
                    'rule_description': rule['description'],
                    'matched_events': matches,
                    'correlation_strength': len(matches) / rule.get('min_events', 1),
                    'temporal_window': rule.get('time_window', '1h'),
                    'confidence': rule.get('confidence', 0.7)
                }
                correlations.append(correlation)
                
        return correlations
        
    def _detect_suspicious_patterns(self, events):
        """Detect suspicious patterns in timeline."""
        patterns = []
        
        # Rapid file creation pattern
        file_creation_events = [e for e in events if e['event_type'] == 'file_creation']
        if len(file_creation_events) > 100:  # Many files created quickly
            patterns.append({
                'pattern_type': 'rapid_file_creation',
                'description': f'{len(file_creation_events)} files created in short time',
                'events': file_creation_events[:10],  # Sample events
                'severity': 'high',
                'confidence': 0.8
            })
            
        # Off-hours activity pattern
        off_hours_events = self._find_off_hours_events(events)
        if len(off_hours_events) > 20:
            patterns.append({
                'pattern_type': 'off_hours_activity',
                'description': f'Significant activity during off-hours',
                'events': off_hours_events[:10],
                'severity': 'medium',
                'confidence': 0.6
            })
            
        # Data staging pattern
        staging_events = self._find_data_staging_events(events)
        if staging_events:
            patterns.append({
                'pattern_type': 'data_staging',
                'description': 'Files moved to staging area before transfer',
                'events': staging_events,
                'severity': 'high',
                'confidence': 0.9
            })
            
        return patterns
        
    def _create_event_clusters(self, events):
        """Create clusters of related events."""
        clusters = []
        processed_events = set()
        
        for i, event in enumerate(events):
            if i in processed_events:
                continue
                
            cluster_events = [event]
            processed_events.add(i)
            
            # Find events within time window
            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            time_window = timedelta(minutes=30)
            
            for j, other_event in enumerate(events[i+1:], i+1):
                if j in processed_events:
                    continue
                    
                other_time = datetime.fromisoformat(other_event['timestamp'].replace('Z', '+00:00'))
                
                if abs(event_time - other_time) <= time_window:
                    if self._events_related(event, other_event):
                        cluster_events.append(other_event)
                        processed_events.add(j)
                        
            if len(cluster_events) > 1:
                cluster = {
                    'cluster_id': len(clusters) + 1,
                    'start_time': min(e['timestamp'] for e in cluster_events),
                    'end_time': max(e['timestamp'] for e in cluster_events),
                    'event_count': len(cluster_events),
                    'events': cluster_events,
                    'cluster_type': self._determine_cluster_type(cluster_events)
                }
                clusters.append(cluster)
                
        return clusters
        
    def _detect_temporal_anomalies(self, events):
        """Detect temporal anomalies in event patterns."""
        anomalies = []
        
        # Group events by hour
        hourly_counts = defaultdict(int)
        for event in events:
            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            hour_key = event_time.strftime('%Y-%m-%d %H:00')
            hourly_counts[hour_key] += 1
            
        # Find hours with unusual activity
        if hourly_counts:
            avg_count = sum(hourly_counts.values()) / len(hourly_counts)
            threshold = avg_count * 3  # 3x average
            
            for hour, count in hourly_counts.items():
                if count > threshold:
                    anomalies.append({
                        'anomaly_type': 'activity_spike',
                        'timestamp': hour,
                        'event_count': count,
                        'average_count': avg_count,
                        'severity': 'high' if count > avg_count * 5 else 'medium'
                    })
                    
        # Detect large time gaps
        event_times = sorted([
            datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) 
            for e in events
        ])
        
        for i in range(1, len(event_times)):
            gap = event_times[i] - event_times[i-1]
            if gap.total_seconds() > 3600:  # 1 hour gap
                anomalies.append({
                    'anomaly_type': 'time_gap',
                    'start_time': event_times[i-1].isoformat(),
                    'end_time': event_times[i].isoformat(),
                    'gap_duration': str(gap),
                    'severity': 'low'
                })
                
        return anomalies
        
    def _get_default_correlation_rules(self):
        """Get default correlation rules."""
        return [
            {
                'name': 'malware_execution_pattern',
                'description': 'Process execution followed by network activity',
                'conditions': [
                    {'event_type': 'process_execution'},
                    {'event_type': 'network_connection', 'time_offset': 300}  # Within 5 minutes
                ],
                'min_events': 2,
                'time_window': '5m',
                'confidence': 0.8
            },
            {
                'name': 'data_exfiltration_pattern',
                'description': 'File access followed by network transfer',
                'conditions': [
                    {'event_type': 'file_access'},
                    {'event_type': 'network_connection', 'time_offset': 600}  # Within 10 minutes
                ],
                'min_events': 2,
                'time_window': '10m',
                'confidence': 0.7
            },
            {
                'name': 'privilege_escalation_pattern',
                'description': 'Failed login attempts followed by successful admin login',
                'conditions': [
                    {'event_type': 'user_login', 'status': 'failed'},
                    {'event_type': 'user_login', 'status': 'success', 'privilege': 'admin'}
                ],
                'min_events': 2,
                'time_window': '30m',
                'confidence': 0.9
            }
        ]
        
    def _get_default_attack_patterns(self):
        """Get default attack patterns for analysis."""
        return [
            {
                'name': 'reconnaissance',
                'stages': ['network_scan', 'port_scan', 'service_enumeration'],
                'indicators': ['multiple_failed_connections', 'unusual_dns_queries']
            },
            {
                'name': 'lateral_movement',
                'stages': ['credential_theft', 'remote_access', 'privilege_escalation'],
                'indicators': ['admin_login_unusual_time', 'remote_admin_tools']
            },
            {
                'name': 'data_exfiltration',
                'stages': ['data_discovery', 'data_staging', 'data_transfer'],
                'indicators': ['large_file_transfers', 'unusual_network_destinations']
            }
        ]
        
    # Additional helper methods would be implemented here for completeness
    def _find_related_events(self, event, events):
        """Find events related to the given event."""
        return []  # Simplified implementation
        
    def _find_rule_matches(self, events, rule):
        """Find events matching the correlation rule."""
        return []  # Simplified implementation
        
    def _find_off_hours_events(self, events):
        """Find events occurring during off-hours."""
        off_hours_events = []
        for event in events:
            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            hour = event_time.hour
            if hour < 6 or hour > 22:  # Before 6 AM or after 10 PM
                off_hours_events.append(event)
        return off_hours_events
        
    def _find_data_staging_events(self, events):
        """Find events indicating data staging activity."""
        staging_events = []
        temp_dirs = ['/tmp', 'C:\\temp', 'C:\\Users\\Public']
        
        for event in events:
            if event['event_type'] == 'file_creation':
                file_path = event.get('details', {}).get('file_path', '')
                if any(temp_dir in file_path for temp_dir in temp_dirs):
                    staging_events.append(event)
                    
        return staging_events
        
    def _events_related(self, event1, event2):
        """Determine if two events are related."""
        # Simple relatedness check based on event types and details
        related_pairs = [
            ('file_creation', 'file_modification'),
            ('process_execution', 'network_connection'),
            ('user_login', 'file_access')
        ]
        
        event_pair = (event1['event_type'], event2['event_type'])
        return event_pair in related_pairs or event_pair[::-1] in related_pairs
        
    def _determine_cluster_type(self, cluster_events):
        """Determine the type of event cluster."""
        event_types = [e['event_type'] for e in cluster_events]
        
        if 'process_execution' in event_types and 'network_connection' in event_types:
            return 'malware_activity'
        elif 'file_creation' in event_types and 'file_modification' in event_types:
            return 'file_activity'
        elif 'user_login' in event_types:
            return 'user_activity'
        else:
            return 'mixed_activity'
            
    def _calculate_source_summary(self, data_sources):
        """Calculate summary statistics for data sources."""
        summary = {}
        for source_name, source_data in data_sources.items():
            event_count = len(source_data.get('events', []))
            summary[source_name] = {
                'event_count': event_count,
                'time_range': source_data.get('time_range', 'unknown'),
                'data_quality': source_data.get('quality', 'medium')
            }
        return summary
        
    def _calculate_time_range(self, events):
        """Calculate overall time range of events."""
        if not events:
            return {'start': None, 'end': None, 'duration': None}
            
        timestamps = [e['timestamp'] for e in events]
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        duration = end_dt - start_dt
        
        return {
            'start': start_time,
            'end': end_time,
            'duration': str(duration)
        }
        
    def _calculate_confidence_scores(self, correlation_results):
        """Calculate confidence scores for the analysis."""
        scores = {}
        
        # Timeline completeness score
        total_sources = len(correlation_results.get('data_source_summary', {}))
        if total_sources > 0:
            scores['timeline_completeness'] = min(total_sources / 5.0, 1.0)  # Max 5 sources
        else:
            scores['timeline_completeness'] = 0.0
            
        # Correlation confidence
        correlations = correlation_results.get('correlation_findings', [])
        if correlations:
            avg_correlation_confidence = sum(c.get('confidence', 0) for c in correlations) / len(correlations)
            scores['correlation_confidence'] = avg_correlation_confidence
        else:
            scores['correlation_confidence'] = 0.0
            
        # Overall analysis confidence
        scores['overall_confidence'] = (
            scores['timeline_completeness'] * 0.4 +
            scores['correlation_confidence'] * 0.6
        )
        
        return scores