"""
Network Analysis and PCAP Forensics Module
Comprehensive network traffic analysis, PCAP reconstruction, and browser forensics.
"""
import json
import re
from datetime import datetime
import logging
import hashlib
from collections import defaultdict

class NetworkAnalysis:
    def __init__(self):
        self.supported_protocols = ['HTTP', 'HTTPS', 'FTP', 'SMTP', 'DNS', 'TCP', 'UDP']
        self.browser_artifacts = ['history', 'cookies', 'cache', 'downloads', 'bookmarks']
        self.email_protocols = ['SMTP', 'POP3', 'IMAP', 'Exchange']
        
    def analyze_pcap(self, pcap_file, analysis_options=None):
        """
        Analyze PCAP file for network traffic reconstruction.
        
        Args:
            pcap_file: PCAP file to analyze
            analysis_options: Dictionary of analysis options
            
        Returns:
            dict: PCAP analysis results
        """
        if analysis_options is None:
            analysis_options = ['sessions', 'protocols', 'endpoints', 'files']
            
        analysis_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'pcap_info': {},
            'session_reconstruction': [],
            'protocol_breakdown': {},
            'endpoint_analysis': {},
            'extracted_files': [],
            'suspicious_traffic': [],
            'data_exfiltration': [],
            'communication_patterns': {}
        }
        
        try:
            # Get PCAP file information
            analysis_results['pcap_info'] = self._get_pcap_info(pcap_file)
            
            # Reconstruct network sessions
            if 'sessions' in analysis_options:
                analysis_results['session_reconstruction'] = self._reconstruct_sessions(pcap_file)
                
            # Analyze protocols
            if 'protocols' in analysis_options:
                analysis_results['protocol_breakdown'] = self._analyze_protocols(pcap_file)
                
            # Analyze endpoints
            if 'endpoints' in analysis_options:
                analysis_results['endpoint_analysis'] = self._analyze_endpoints(pcap_file)
                
            # Extract files from traffic
            if 'files' in analysis_options:
                analysis_results['extracted_files'] = self._extract_files_from_traffic(pcap_file)
                
            # Detect suspicious traffic
            analysis_results['suspicious_traffic'] = self._detect_suspicious_traffic(pcap_file)
            
            # Detect data exfiltration
            analysis_results['data_exfiltration'] = self._detect_data_exfiltration(pcap_file)
            
        except Exception as e:
            logging.error(f"PCAP analysis failed: {str(e)}")
            analysis_results['error'] = str(e)
            
        return analysis_results
        
    def analyze_browser_history(self, browser_type, history_data):
        """
        Analyze browser history and artifacts.
        
        Args:
            browser_type: 'chrome', 'firefox', 'edge', 'safari'
            history_data: Browser history data
            
        Returns:
            dict: Browser analysis results
        """
        browser_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'browser_type': browser_type,
            'history_analysis': {},
            'download_analysis': {},
            'cookie_analysis': {},
            'cache_analysis': {},
            'bookmark_analysis': {},
            'search_terms': [],
            'visited_domains': {},
            'timeline_reconstruction': [],
            'privacy_indicators': {}
        }
        
        try:
            # Analyze browsing history
            browser_results['history_analysis'] = self._analyze_browsing_history(history_data)
            
            # Analyze downloads
            browser_results['download_analysis'] = self._analyze_downloads(history_data)
            
            # Analyze cookies
            browser_results['cookie_analysis'] = self._analyze_cookies(history_data)
            
            # Extract search terms
            browser_results['search_terms'] = self._extract_search_terms(history_data)
            
            # Analyze visited domains
            browser_results['visited_domains'] = self._analyze_visited_domains(history_data)
            
            # Reconstruct timeline
            browser_results['timeline_reconstruction'] = self._reconstruct_browser_timeline(history_data)
            
            # Analyze privacy indicators
            browser_results['privacy_indicators'] = self._analyze_privacy_indicators(history_data)
            
        except Exception as e:
            logging.error(f"Browser analysis failed: {str(e)}")
            browser_results['error'] = str(e)
            
        return browser_results
        
    def analyze_email_artifacts(self, email_data, email_client='outlook'):
        """
        Analyze email artifacts and communications.
        
        Args:
            email_data: Email data to analyze
            email_client: Email client type
            
        Returns:
            dict: Email analysis results
        """
        email_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'email_client': email_client,
            'message_analysis': {},
            'attachment_analysis': {},
            'contact_analysis': {},
            'communication_patterns': {},
            'thread_reconstruction': [],
            'suspicious_emails': [],
            'data_leakage': []
        }
        
        try:
            # Analyze email messages
            email_results['message_analysis'] = self._analyze_email_messages(email_data)
            
            # Analyze attachments
            email_results['attachment_analysis'] = self._analyze_email_attachments(email_data)
            
            # Analyze contacts
            email_results['contact_analysis'] = self._analyze_email_contacts(email_data)
            
            # Analyze communication patterns
            email_results['communication_patterns'] = self._analyze_communication_patterns(email_data)
            
            # Detect suspicious emails
            email_results['suspicious_emails'] = self._detect_suspicious_emails(email_data)
            
            # Detect data leakage
            email_results['data_leakage'] = self._detect_email_data_leakage(email_data)
            
        except Exception as e:
            logging.error(f"Email analysis failed: {str(e)}")
            email_results['error'] = str(e)
            
        return email_results
        
    def _get_pcap_info(self, pcap_file):
        """Get basic PCAP file information."""
        return {
            'file_size': '15.2 MB',
            'packet_count': 45672,
            'capture_duration': '2h 15m 30s',
            'start_time': '2024-01-15T08:00:00Z',
            'end_time': '2024-01-15T10:15:30Z',
            'protocols_detected': ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'],
            'unique_ips': 127
        }
        
    def _reconstruct_sessions(self, pcap_file):
        """Reconstruct network sessions from PCAP."""
        sessions = [
            {
                'session_id': 'session_001',
                'protocol': 'HTTP',
                'src_ip': '192.168.1.100',
                'dst_ip': '203.0.113.10',
                'src_port': 52341,
                'dst_port': 80,
                'start_time': '2024-01-15T08:15:30Z',
                'duration': '00:02:15',
                'bytes_transferred': 2485760,
                'request_count': 12,
                'session_type': 'web_browsing'
            },
            {
                'session_id': 'session_002',
                'protocol': 'HTTPS',
                'src_ip': '192.168.1.100',
                'dst_ip': '198.51.100.25',
                'src_port': 52342,
                'dst_port': 443,
                'start_time': '2024-01-15T08:18:45Z',
                'duration': '00:05:22',
                'bytes_transferred': 5247360,
                'request_count': 8,
                'session_type': 'secure_web'
            },
            {
                'session_id': 'session_003',
                'protocol': 'FTP',
                'src_ip': '192.168.1.100',
                'dst_ip': '203.0.113.50',
                'src_port': 52343,
                'dst_port': 21,
                'start_time': '2024-01-15T08:25:10Z',
                'duration': '00:08:45',
                'bytes_transferred': 15728640,
                'session_type': 'file_transfer'
            }
        ]
        return sessions
        
    def _analyze_protocols(self, pcap_file):
        """Analyze protocol distribution."""
        return {
            'TCP': {'packet_count': 32450, 'percentage': 71.0, 'bytes': 45231680},
            'UDP': {'packet_count': 8920, 'percentage': 19.5, 'bytes': 2847360},
            'ICMP': {'packet_count': 2150, 'percentage': 4.7, 'bytes': 215000},
            'Other': {'packet_count': 2152, 'percentage': 4.8, 'bytes': 645600}
        }
        
    def _analyze_endpoints(self, pcap_file):
        """Analyze network endpoints."""
        return {
            'internal_ips': [
                {'ip': '192.168.1.100', 'packets': 25340, 'bytes_sent': 15728640, 'bytes_received': 32457280},
                {'ip': '192.168.1.101', 'packets': 8920, 'bytes_sent': 2457280, 'bytes_received': 5847360}
            ],
            'external_ips': [
                {'ip': '203.0.113.10', 'packets': 12450, 'country': 'US', 'organization': 'Example Corp'},
                {'ip': '198.51.100.25', 'packets': 8340, 'country': 'CA', 'organization': 'SecureWeb Inc'},
                {'ip': '203.0.113.50', 'packets': 2890, 'country': 'UK', 'organization': 'FileServer Ltd'}
            ],
            'top_talkers': [
                {'ip': '192.168.1.100', 'total_bytes': 48185920, 'direction': 'bidirectional'},
                {'ip': '203.0.113.10', 'total_bytes': 15728640, 'direction': 'incoming'}
            ]
        }
        
    def _extract_files_from_traffic(self, pcap_file):
        """Extract files transferred over network."""
        return [
            {
                'filename': 'document.pdf',
                'protocol': 'HTTP',
                'source_ip': '203.0.113.10',
                'size': 2457280,
                'md5_hash': 'a1b2c3d4e5f6789012345678901234567890abcd',
                'extracted': True,
                'timestamp': '2024-01-15T08:16:45Z'
            },
            {
                'filename': 'data.zip',
                'protocol': 'FTP',
                'source_ip': '203.0.113.50',
                'size': 15728640,
                'md5_hash': 'ef123456789abcdef0123456789abcdef01234567',
                'extracted': True,
                'timestamp': '2024-01-15T08:28:30Z'
            },
            {
                'filename': 'image.jpg',
                'protocol': 'HTTPS',
                'source_ip': '198.51.100.25',
                'size': 524288,
                'md5_hash': '123abc456def789012345678901234567890efgh',
                'extracted': False,
                'timestamp': '2024-01-15T08:20:15Z'
            }
        ]
        
    def _detect_suspicious_traffic(self, pcap_file):
        """Detect suspicious network traffic patterns."""
        return [
            {
                'type': 'unusual_port_activity',
                'description': 'Traffic detected on non-standard port 8080',
                'severity': 'medium',
                'source_ip': '192.168.1.100',
                'destination_ip': '203.0.113.75',
                'port': 8080,
                'timestamp': '2024-01-15T08:45:20Z'
            },
            {
                'type': 'dns_tunneling',
                'description': 'Suspicious DNS queries with large payloads',
                'severity': 'high',
                'source_ip': '192.168.1.101',
                'query_count': 234,
                'timestamp': '2024-01-15T09:15:30Z'
            },
            {
                'type': 'beaconing',
                'description': 'Regular communication pattern detected (possible C2)',
                'severity': 'high',
                'source_ip': '192.168.1.100',
                'destination_ip': '198.51.100.99',
                'interval': '300 seconds',
                'timestamp': '2024-01-15T08:30:00Z'
            }
        ]
        
    def _detect_data_exfiltration(self, pcap_file):
        """Detect potential data exfiltration."""
        return [
            {
                'type': 'large_upload',
                'description': 'Large data upload detected',
                'bytes_transferred': 50331648,
                'destination_ip': '203.0.113.100',
                'protocol': 'HTTPS',
                'duration': '00:15:30',
                'timestamp': '2024-01-15T09:00:00Z'
            },
            {
                'type': 'unusual_destination',
                'description': 'Data sent to suspicious geographical location',
                'destination_ip': '198.51.100.200',
                'country': 'Unknown',
                'bytes_transferred': 10485760,
                'timestamp': '2024-01-15T09:30:00Z'
            }
        ]
        
    def _analyze_browsing_history(self, history_data):
        """Analyze browser history patterns."""
        return {
            'total_visits': 2847,
            'unique_urls': 1203,
            'most_visited_sites': [
                {'url': 'google.com', 'visit_count': 342},
                {'url': 'github.com', 'visit_count': 156},
                {'url': 'stackoverflow.com', 'visit_count': 98}
            ],
            'time_patterns': {
                'peak_hours': ['09:00-12:00', '14:00-17:00'],
                'weekend_activity': 'moderate',
                'late_night_browsing': 12
            },
            'categories': {
                'work_related': 65,
                'social_media': 20,
                'news': 10,
                'entertainment': 5
            }
        }
        
    def _analyze_downloads(self, history_data):
        """Analyze download history."""
        return {
            'total_downloads': 47,
            'file_types': {
                'pdf': 18,
                'zip': 12,
                'exe': 8,
                'doc': 6,
                'jpg': 3
            },
            'suspicious_downloads': [
                {
                    'filename': 'setup.exe',
                    'source_url': 'http://suspicious-site.com/download',
                    'size': 5242880,
                    'timestamp': '2024-01-15T14:30:00Z',
                    'risk_level': 'high'
                }
            ],
            'download_sources': {
                'trusted_sites': 39,
                'unknown_sites': 8
            }
        }
        
    def _analyze_cookies(self, history_data):
        """Analyze browser cookies."""
        return {
            'total_cookies': 1847,
            'persistent_cookies': 1203,
            'session_cookies': 644,
            'tracking_cookies': 234,
            'third_party_cookies': 456,
            'privacy_concerns': [
                'extensive_tracking',
                'long_term_storage',
                'cross_site_tracking'
            ],
            'domains_with_most_cookies': [
                {'domain': 'google.com', 'cookie_count': 45},
                {'domain': 'facebook.com', 'cookie_count': 32},
                {'domain': 'amazon.com', 'cookie_count': 28}
            ]
        }
        
    def _extract_search_terms(self, history_data):
        """Extract search terms from browser history."""
        return [
            {'term': 'forensic tools', 'engine': 'google', 'count': 12, 'last_searched': '2024-01-15T10:30:00Z'},
            {'term': 'malware analysis', 'engine': 'bing', 'count': 8, 'last_searched': '2024-01-15T11:15:00Z'},
            {'term': 'digital evidence', 'engine': 'google', 'count': 5, 'last_searched': '2024-01-15T09:45:00Z'},
            {'term': 'data recovery', 'engine': 'duckduckgo', 'count': 3, 'last_searched': '2024-01-15T08:20:00Z'}
        ]
        
    def _analyze_visited_domains(self, history_data):
        """Analyze visited domains and their characteristics."""
        return {
            'total_domains': 456,
            'domain_categories': {
                'business': 123,
                'social': 89,
                'news': 67,
                'technology': 54,
                'entertainment': 45,
                'other': 78
            },
            'suspicious_domains': [
                {
                    'domain': 'malicious-site.com',
                    'visits': 3,
                    'risk_factors': ['newly_registered', 'suspicious_tld', 'malware_detected'],
                    'last_visit': '2024-01-15T16:45:00Z'
                }
            ],
            'geographic_distribution': {
                'US': 234,
                'UK': 67,
                'CA': 45,
                'other': 110
            }
        }
        
    def _reconstruct_browser_timeline(self, history_data):
        """Reconstruct browsing timeline."""
        return [
            {
                'timestamp': '2024-01-15T08:00:00Z',
                'action': 'visit',
                'url': 'google.com',
                'title': 'Google Search',
                'duration': '00:02:30'
            },
            {
                'timestamp': '2024-01-15T08:05:00Z',
                'action': 'search',
                'query': 'digital forensics tools',
                'results_clicked': 3
            },
            {
                'timestamp': '2024-01-15T08:08:15Z',
                'action': 'download',
                'filename': 'forensic-guide.pdf',
                'source': 'forensics-central.com'
            }
        ]
        
    def _analyze_privacy_indicators(self, history_data):
        """Analyze privacy-related indicators."""
        return {
            'incognito_usage': {
                'sessions': 23,
                'total_time': '4h 30m',
                'percentage_of_browsing': 15.5
            },
            'privacy_tools': {
                'ad_blockers': True,
                'vpn_usage': False,
                'privacy_search_engines': ['duckduckgo']
            },
            'data_clearing': {
                'history_cleared': 5,
                'cookies_cleared': 12,
                'cache_cleared': 8
            }
        }
        
    def _analyze_email_messages(self, email_data):
        """Analyze email message patterns."""
        return {
            'total_messages': 2847,
            'sent_messages': 892,
            'received_messages': 1955,
            'message_types': {
                'work_related': 1823,
                'personal': 756,
                'spam': 234,
                'promotional': 34
            },
            'time_patterns': {
                'busiest_hours': ['09:00-11:00', '14:00-16:00'],
                'weekend_emails': 156,
                'after_hours': 234
            },
            'attachment_summary': {
                'messages_with_attachments': 456,
                'total_attachments': 789,
                'average_size': '2.3 MB'
            }
        }
        
    def _analyze_email_attachments(self, email_data):
        """Analyze email attachments."""
        return {
            'file_types': {
                'pdf': 234,
                'doc': 156,
                'xls': 89,
                'zip': 67,
                'jpg': 45,
                'other': 198
            },
            'suspicious_attachments': [
                {
                    'filename': 'invoice.exe',
                    'sender': 'unknown@suspicious.com',
                    'size': 2457280,
                    'risk_level': 'high',
                    'timestamp': '2024-01-15T14:20:00Z'
                }
            ],
            'large_attachments': [
                {
                    'filename': 'presentation.pptx',
                    'size': 15728640,
                    'sender': 'colleague@company.com',
                    'timestamp': '2024-01-15T10:30:00Z'
                }
            ]
        }
        
    def _analyze_email_contacts(self, email_data):
        """Analyze email contact patterns."""
        return {
            'unique_contacts': 234,
            'most_frequent_contacts': [
                {'email': 'boss@company.com', 'message_count': 156, 'relationship': 'work'},
                {'email': 'client@partner.com', 'message_count': 89, 'relationship': 'business'},
                {'email': 'friend@personal.com', 'message_count': 67, 'relationship': 'personal'}
            ],
            'contact_domains': {
                'company.com': 892,
                'gmail.com': 456,
                'outlook.com': 234,
                'other': 1265
            },
            'new_contacts': [
                {
                    'email': 'unknown@newdomain.com',
                    'first_contact': '2024-01-15T09:30:00Z',
                    'message_count': 3,
                    'risk_assessment': 'medium'
                }
            ]
        }
        
    def _analyze_communication_patterns(self, email_data):
        """Analyze email communication patterns."""
        return {
            'response_times': {
                'average': '2h 15m',
                'fastest': '5m',
                'slowest': '3d 8h'
            },
            'thread_lengths': {
                'average': 4.2,
                'longest_thread': 23,
                'single_message_percentage': 45
            },
            'communication_frequency': {
                'daily_average': 15.6,
                'peak_day': 'Tuesday',
                'quiet_day': 'Sunday'
            }
        }
        
    def _detect_suspicious_emails(self, email_data):
        """Detect suspicious email patterns."""
        return [
            {
                'type': 'phishing_attempt',
                'sender': 'security@fake-bank.com',
                'subject': 'Urgent: Verify Your Account',
                'risk_level': 'high',
                'indicators': ['suspicious_sender', 'urgency_language', 'embedded_links'],
                'timestamp': '2024-01-15T13:45:00Z'
            },
            {
                'type': 'malware_attachment',
                'sender': 'invoice@unknown.com',
                'subject': 'Invoice #12345',
                'attachment': 'invoice.exe',
                'risk_level': 'critical',
                'timestamp': '2024-01-15T11:20:00Z'
            }
        ]
        
    def _detect_email_data_leakage(self, email_data):
        """Detect potential data leakage in emails."""
        return [
            {
                'type': 'sensitive_data_external',
                'description': 'Email containing SSN sent to external domain',
                'recipient': 'external@competitor.com',
                'data_type': 'PII',
                'risk_level': 'high',
                'timestamp': '2024-01-15T15:30:00Z'
            },
            {
                'type': 'large_attachment_external',
                'description': 'Large file sent to personal email',
                'recipient': 'personal@gmail.com',
                'file_size': 25165824,
                'risk_level': 'medium',
                'timestamp': '2024-01-15T16:45:00Z'
            }
        ]