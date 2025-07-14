"""
Search and Regex Matching Module
Deep scan capabilities for regex/keyword search across disk images, memory dumps, and files.
"""
import re
import json
from datetime import datetime
import logging
import mmap
import os
from collections import defaultdict

class SearchRegex:
    def __init__(self):
        self.pii_patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'mac_address': r'\b[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}\b'
        }
        
        self.credential_patterns = {
            'password_field': r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'"]+)',
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*[\'"]?([a-zA-Z0-9]{20,})',
            'token': r'(?i)(token|auth[_-]?token)\s*[=:]\s*[\'"]?([a-zA-Z0-9]{16,})',
            'private_key': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}'
        }
        
        self.network_patterns = {
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b',
            'ftp_url': r'ftp://[^\s<>"{}|\\^`\[\]]+',
            'bitcoin_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'ethereum_address': r'\b0x[a-fA-F0-9]{40}\b'
        }
        
    def deep_scan_disk_image(self, disk_image_path, search_patterns, scan_options=None):
        """
        Perform deep scan of disk image for patterns.
        
        Args:
            disk_image_path: Path to disk image file
            search_patterns: Dictionary of patterns to search for
            scan_options: Scan configuration options
            
        Returns:
            dict: Deep scan results
        """
        if scan_options is None:
            scan_options = {
                'include_deleted': True,
                'scan_slack_space': True,
                'max_file_size': 100 * 1024 * 1024,  # 100MB
                'case_sensitive': False
            }
            
        scan_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'disk_image': disk_image_path,
            'scan_options': scan_options,
            'patterns_searched': list(search_patterns.keys()),
            'matches': {},
            'file_matches': [],
            'slack_space_matches': [],
            'deleted_file_matches': [],
            'statistics': {},
            'scan_duration': None
        }
        
        try:
            scan_start = datetime.utcnow()
            
            # Analyze disk image structure
            disk_info = self._analyze_disk_structure(disk_image_path)
            scan_results['disk_info'] = disk_info
            
            # Scan allocated files
            allocated_matches = self._scan_allocated_files(disk_image_path, search_patterns, scan_options)
            scan_results['file_matches'] = allocated_matches
            
            # Scan slack space
            if scan_options.get('scan_slack_space', True):
                slack_matches = self._scan_slack_space(disk_image_path, search_patterns, scan_options)
                scan_results['slack_space_matches'] = slack_matches
                
            # Scan deleted files
            if scan_options.get('include_deleted', True):
                deleted_matches = self._scan_deleted_files(disk_image_path, search_patterns, scan_options)
                scan_results['deleted_file_matches'] = deleted_matches
                
            # Aggregate all matches
            all_matches = defaultdict(list)
            for source in [allocated_matches, slack_matches, deleted_matches]:
                for pattern, matches in source.items():
                    all_matches[pattern].extend(matches)
                    
            scan_results['matches'] = dict(all_matches)
            
            # Calculate statistics
            scan_end = datetime.utcnow()
            scan_results['scan_duration'] = str(scan_end - scan_start)
            scan_results['statistics'] = self._calculate_scan_statistics(scan_results)
            
        except Exception as e:
            logging.error(f"Deep disk scan failed: {str(e)}")
            scan_results['error'] = str(e)
            
        return scan_results
        
    def search_memory_dump(self, memory_dump_path, search_patterns, search_options=None):
        """
        Search memory dump for specific patterns.
        
        Args:
            memory_dump_path: Path to memory dump file
            search_patterns: Dictionary of patterns to search for
            search_options: Search configuration options
            
        Returns:
            dict: Memory search results
        """
        if search_options is None:
            search_options = {
                'case_sensitive': False,
                'context_bytes': 64,
                'max_matches_per_pattern': 1000
            }
            
        search_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'memory_dump': memory_dump_path,
            'search_options': search_options,
            'patterns_searched': list(search_patterns.keys()),
            'matches': {},
            'memory_regions': [],
            'process_matches': {},
            'statistics': {}
        }
        
        try:
            # Get memory dump info
            dump_info = self._analyze_memory_dump(memory_dump_path)
            search_results['dump_info'] = dump_info
            
            # Search memory dump
            memory_matches = self._search_memory_patterns(memory_dump_path, search_patterns, search_options)
            search_results['matches'] = memory_matches
            
            # Map matches to memory regions
            search_results['memory_regions'] = self._map_memory_regions(memory_matches)
            
            # Map matches to processes (if possible)
            search_results['process_matches'] = self._map_process_matches(memory_matches)
            
            # Calculate statistics
            search_results['statistics'] = self._calculate_memory_statistics(search_results)
            
        except Exception as e:
            logging.error(f"Memory dump search failed: {str(e)}")
            search_results['error'] = str(e)
            
        return search_results
        
    def search_pii_data(self, data_source, scan_depth='standard'):
        """
        Search for Personally Identifiable Information (PII).
        
        Args:
            data_source: Data source to search (file, directory, disk image)
            scan_depth: 'quick', 'standard', or 'deep'
            
        Returns:
            dict: PII search results
        """
        pii_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'data_source': data_source,
            'scan_depth': scan_depth,
            'pii_found': {},
            'risk_assessment': {},
            'gdpr_compliance': {},
            'recommendations': []
        }
        
        try:
            # Search for each PII type
            for pii_type, pattern in self.pii_patterns.items():
                matches = self._search_pattern_in_source(data_source, {pii_type: pattern})
                if matches:
                    pii_results['pii_found'][pii_type] = matches[pii_type]
                    
            # Assess risk based on PII found
            pii_results['risk_assessment'] = self._assess_pii_risk(pii_results['pii_found'])
            
            # GDPR compliance check
            pii_results['gdpr_compliance'] = self._check_gdpr_compliance(pii_results['pii_found'])
            
            # Generate recommendations
            pii_results['recommendations'] = self._generate_pii_recommendations(pii_results)
            
        except Exception as e:
            logging.error(f"PII search failed: {str(e)}")
            pii_results['error'] = str(e)
            
        return pii_results
        
    def search_credentials(self, data_source, credential_types=None):
        """
        Search for credentials and sensitive authentication data.
        
        Args:
            data_source: Data source to search
            credential_types: Types of credentials to search for
            
        Returns:
            dict: Credential search results
        """
        if credential_types is None:
            credential_types = list(self.credential_patterns.keys())
            
        credential_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'data_source': data_source,
            'credential_types_searched': credential_types,
            'credentials_found': {},
            'security_assessment': {},
            'exposure_risk': {}
        }
        
        try:
            # Search for each credential type
            patterns_to_search = {
                cred_type: self.credential_patterns[cred_type] 
                for cred_type in credential_types 
                if cred_type in self.credential_patterns
            }
            
            matches = self._search_pattern_in_source(data_source, patterns_to_search)
            credential_results['credentials_found'] = matches
            
            # Assess security risk
            credential_results['security_assessment'] = self._assess_credential_security(matches)
            
            # Assess exposure risk
            credential_results['exposure_risk'] = self._assess_exposure_risk(matches, data_source)
            
        except Exception as e:
            logging.error(f"Credential search failed: {str(e)}")
            credential_results['error'] = str(e)
            
        return credential_results
        
    def custom_regex_search(self, data_source, custom_patterns, search_options=None):
        """
        Perform custom regex search with user-defined patterns.
        
        Args:
            data_source: Data source to search
            custom_patterns: Dictionary of custom regex patterns
            search_options: Search configuration options
            
        Returns:
            dict: Custom search results
        """
        if search_options is None:
            search_options = {
                'case_sensitive': False,
                'multiline': True,
                'context_chars': 100,
                'max_matches': 10000
            }
            
        custom_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'data_source': data_source,
            'search_options': search_options,
            'custom_patterns': custom_patterns,
            'matches': {},
            'pattern_statistics': {},
            'performance_metrics': {}
        }
        
        try:
            search_start = datetime.utcnow()
            
            # Perform custom pattern search
            matches = self._search_pattern_in_source(data_source, custom_patterns, search_options)
            custom_results['matches'] = matches
            
            # Calculate pattern statistics
            custom_results['pattern_statistics'] = self._calculate_pattern_statistics(matches)
            
            # Performance metrics
            search_end = datetime.utcnow()
            custom_results['performance_metrics'] = {
                'search_duration': str(search_end - search_start),
                'patterns_processed': len(custom_patterns),
                'total_matches': sum(len(m) for m in matches.values())
            }
            
        except Exception as e:
            logging.error(f"Custom regex search failed: {str(e)}")
            custom_results['error'] = str(e)
            
        return custom_results
        
    def _analyze_disk_structure(self, disk_image_path):
        """Analyze disk image structure."""
        # Simulated disk analysis
        return {
            'disk_size': '500 GB',
            'filesystem': 'NTFS',
            'partition_count': 3,
            'allocated_space': '350 GB',
            'free_space': '150 GB',
            'slack_space': '2.5 GB',
            'deleted_files_estimated': 15000
        }
        
    def _scan_allocated_files(self, disk_image_path, patterns, options):
        """Scan allocated files in disk image."""
        # Simulated file scanning
        matches = defaultdict(list)
        
        for pattern_name in patterns.keys():
            if pattern_name in ['email', 'phone', 'ip_address']:
                matches[pattern_name] = [
                    {
                        'match': 'user@example.com' if pattern_name == 'email' else '192.168.1.100',
                        'file_path': f'/Users/John/Documents/file_{pattern_name}.txt',
                        'offset': 1024,
                        'context': f'Found {pattern_name} in document context...',
                        'timestamp': '2024-01-15T10:30:00Z'
                    }
                ]
                
        return dict(matches)
        
    def _scan_slack_space(self, disk_image_path, patterns, options):
        """Scan slack space for patterns."""
        # Simulated slack space scanning
        matches = defaultdict(list)
        
        for pattern_name in patterns.keys():
            if pattern_name in ['password_field', 'credit_card']:
                matches[pattern_name] = [
                    {
                        'match': 'password=secret123' if pattern_name == 'password_field' else '4532-1234-5678-9012',
                        'cluster': 1024,
                        'sector': 2048,
                        'offset': 512,
                        'context': f'Slack space contains {pattern_name}...',
                        'confidence': 0.8
                    }
                ]
                
        return dict(matches)
        
    def _scan_deleted_files(self, disk_image_path, patterns, options):
        """Scan deleted files for patterns."""
        # Simulated deleted file scanning
        matches = defaultdict(list)
        
        for pattern_name in patterns.keys():
            if pattern_name in ['ssn', 'api_key']:
                matches[pattern_name] = [
                    {
                        'match': '123-45-6789' if pattern_name == 'ssn' else 'sk_test_1234567890abcdef',
                        'deleted_file': f'deleted_file_{pattern_name}.txt',
                        'inode': 12345,
                        'deletion_time': '2024-01-10T14:20:00Z',
                        'recovery_confidence': 0.9
                    }
                ]
                
        return dict(matches)
        
    def _analyze_memory_dump(self, memory_dump_path):
        """Analyze memory dump file."""
        return {
            'dump_size': '8 GB',
            'dump_type': 'full_memory_dump',
            'os_version': 'Windows 10',
            'architecture': 'x64',
            'process_count': 145,
            'acquisition_time': '2024-01-15T10:30:00Z'
        }
        
    def _search_memory_patterns(self, memory_dump_path, patterns, options):
        """Search patterns in memory dump."""
        # Simulated memory pattern search
        matches = defaultdict(list)
        
        for pattern_name, pattern in patterns.items():
            if pattern_name in ['password_field', 'url', 'ip_address']:
                matches[pattern_name] = [
                    {
                        'match': 'password=memorypass' if pattern_name == 'password_field' else 'http://malicious.com',
                        'memory_address': '0x7FF000001000',
                        'process_id': 1234,
                        'process_name': 'chrome.exe',
                        'context': f'Memory context for {pattern_name}...',
                        'confidence': 0.9
                    }
                ]
                
        return dict(matches)
        
    def _search_pattern_in_source(self, data_source, patterns, options=None):
        """Generic pattern search in data source."""
        if options is None:
            options = {'case_sensitive': False}
            
        matches = defaultdict(list)
        
        # Simulated pattern matching
        for pattern_name, pattern in patterns.items():
            # Simulate different match types based on pattern
            if 'email' in pattern_name:
                sample_matches = ['user@example.com', 'admin@company.org', 'test@domain.net']
            elif 'password' in pattern_name:
                sample_matches = ['password=secret123', 'pwd=admin', 'passwd=user123']
            elif 'ssn' in pattern_name:
                sample_matches = ['123-45-6789', '987-65-4321']
            elif 'credit_card' in pattern_name:
                sample_matches = ['4532-1234-5678-9012', '5555-4444-3333-2222']
            elif 'ip' in pattern_name:
                sample_matches = ['192.168.1.100', '10.0.0.1', '203.0.113.50']
            else:
                sample_matches = [f'sample_match_for_{pattern_name}']
                
            for i, match in enumerate(sample_matches[:3]):  # Limit to 3 matches
                matches[pattern_name].append({
                    'match': match,
                    'location': f'{data_source}:offset_{i * 1024}',
                    'line_number': i + 1,
                    'context': f'Context around {match} in {data_source}',
                    'confidence': 0.8 + (i * 0.1)
                })
                
        return dict(matches)
        
    def _assess_pii_risk(self, pii_found):
        """Assess risk level based on PII found."""
        risk_score = 0
        risk_factors = []
        
        # Weight different PII types
        pii_weights = {
            'ssn': 40,
            'credit_card': 35,
            'email': 10,
            'phone': 15,
            'ip_address': 5,
            'mac_address': 5
        }
        
        for pii_type, matches in pii_found.items():
            weight = pii_weights.get(pii_type, 10)
            count = len(matches)
            risk_score += weight * min(count, 10)  # Cap impact per type
            
            if count > 0:
                risk_factors.append(f'{pii_type}_detected')
                
        # Determine risk level
        if risk_score >= 200:
            risk_level = 'critical'
        elif risk_score >= 100:
            risk_level = 'high'
        elif risk_score >= 50:
            risk_level = 'medium'
        elif risk_score >= 20:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
            
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'total_pii_items': sum(len(matches) for matches in pii_found.values())
        }
        
    def _check_gdpr_compliance(self, pii_found):
        """Check GDPR compliance based on PII found."""
        gdpr_relevant = ['email', 'phone', 'ip_address']
        gdpr_violations = []
        
        for pii_type in gdpr_relevant:
            if pii_type in pii_found and len(pii_found[pii_type]) > 0:
                gdpr_violations.append({
                    'pii_type': pii_type,
                    'count': len(pii_found[pii_type]),
                    'violation_type': 'unencrypted_storage',
                    'severity': 'high' if pii_type in ['email', 'phone'] else 'medium'
                })
                
        compliance_status = 'non_compliant' if gdpr_violations else 'compliant'
        
        return {
            'compliance_status': compliance_status,
            'violations': gdpr_violations,
            'recommendations': [
                'Encrypt PII data at rest',
                'Implement data retention policies',
                'Ensure proper consent management'
            ] if gdpr_violations else []
        }
        
    def _calculate_scan_statistics(self, scan_results):
        """Calculate statistics for disk scan."""
        total_matches = sum(len(matches) for matches in scan_results['matches'].values())
        patterns_with_matches = len([p for p, m in scan_results['matches'].items() if m])
        
        return {
            'total_matches': total_matches,
            'patterns_with_matches': patterns_with_matches,
            'patterns_without_matches': len(scan_results['patterns_searched']) - patterns_with_matches,
            'file_matches_count': len(scan_results['file_matches']),
            'slack_matches_count': len(scan_results['slack_space_matches']),
            'deleted_matches_count': len(scan_results['deleted_file_matches'])
        }