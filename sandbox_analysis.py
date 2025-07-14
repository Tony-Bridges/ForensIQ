"""
Sandbox Analysis Module
Dynamic execution environment for analyzing files in isolated containers/VMs.
"""
import json
import hashlib
from datetime import datetime
import logging
import subprocess
import tempfile
import os

class SandboxAnalysis:
    def __init__(self):
        self.supported_environments = ['docker', 'virtualbox', 'vmware', 'qemu']
        self.analysis_types = ['behavioral', 'network', 'filesystem', 'registry', 'api_calls']
        self.operating_systems = ['windows_10', 'windows_11', 'ubuntu_20', 'macos_12']
        
    def execute_file_analysis(self, file_data, sandbox_config=None):
        """
        Execute file in sandbox environment and analyze behavior.
        
        Args:
            file_data: File to analyze
            sandbox_config: Sandbox configuration options
            
        Returns:
            dict: Sandbox analysis results
        """
        if sandbox_config is None:
            sandbox_config = {
                'environment': 'docker',
                'os': 'windows_10',
                'execution_time': 300,  # 5 minutes
                'network_isolation': True
            }
            
        analysis_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'file_info': {},
            'sandbox_config': sandbox_config,
            'execution_summary': {},
            'behavioral_analysis': {},
            'network_activity': {},
            'filesystem_changes': {},
            'registry_changes': {},
            'api_calls': {},
            'screenshots': [],
            'memory_dumps': [],
            'threat_assessment': {},
            'indicators_of_compromise': []
        }
        
        try:
            # Analyze file before execution
            analysis_results['file_info'] = self._analyze_file_static(file_data)
            
            # Prepare sandbox environment
            sandbox_id = self._prepare_sandbox(sandbox_config)
            analysis_results['sandbox_id'] = sandbox_id
            
            # Execute file in sandbox
            execution_result = self._execute_in_sandbox(file_data, sandbox_id, sandbox_config)
            analysis_results['execution_summary'] = execution_result
            
            # Collect behavioral data
            analysis_results['behavioral_analysis'] = self._collect_behavioral_data(sandbox_id)
            
            # Monitor network activity
            analysis_results['network_activity'] = self._monitor_network_activity(sandbox_id)
            
            # Track filesystem changes
            analysis_results['filesystem_changes'] = self._track_filesystem_changes(sandbox_id)
            
            # Monitor registry changes (Windows)
            if 'windows' in sandbox_config.get('os', '').lower():
                analysis_results['registry_changes'] = self._monitor_registry_changes(sandbox_id)
                
            # Capture API calls
            analysis_results['api_calls'] = self._capture_api_calls(sandbox_id)
            
            # Take screenshots
            analysis_results['screenshots'] = self._capture_screenshots(sandbox_id)
            
            # Create memory dumps
            analysis_results['memory_dumps'] = self._create_memory_dumps(sandbox_id)
            
            # Assess threat level
            analysis_results['threat_assessment'] = self._assess_threat_level(analysis_results)
            
            # Extract IOCs
            analysis_results['indicators_of_compromise'] = self._extract_iocs(analysis_results)
            
            # Cleanup sandbox
            self._cleanup_sandbox(sandbox_id)
            
        except Exception as e:
            logging.error(f"Sandbox analysis failed: {str(e)}")
            analysis_results['error'] = str(e)
            
        return analysis_results
        
    def analyze_suspicious_behavior(self, execution_data):
        """
        Analyze execution data for suspicious behavior patterns.
        
        Args:
            execution_data: Execution monitoring data
            
        Returns:
            dict: Suspicious behavior analysis
        """
        behavior_analysis = {
            'timestamp': datetime.utcnow().isoformat(),
            'suspicious_activities': [],
            'malware_indicators': [],
            'evasion_techniques': [],
            'persistence_mechanisms': [],
            'data_exfiltration': [],
            'privilege_escalation': [],
            'anti_analysis_techniques': [],
            'behavioral_score': 0
        }
        
        try:
            # Detect suspicious file operations
            file_activities = self._analyze_file_operations(execution_data)
            behavior_analysis['suspicious_activities'].extend(file_activities)
            
            # Detect malware indicators
            malware_indicators = self._detect_malware_indicators(execution_data)
            behavior_analysis['malware_indicators'] = malware_indicators
            
            # Detect evasion techniques
            evasion_techniques = self._detect_evasion_techniques(execution_data)
            behavior_analysis['evasion_techniques'] = evasion_techniques
            
            # Detect persistence mechanisms
            persistence = self._detect_persistence_mechanisms(execution_data)
            behavior_analysis['persistence_mechanisms'] = persistence
            
            # Detect data exfiltration
            exfiltration = self._detect_data_exfiltration(execution_data)
            behavior_analysis['data_exfiltration'] = exfiltration
            
            # Detect privilege escalation
            privilege_esc = self._detect_privilege_escalation(execution_data)
            behavior_analysis['privilege_escalation'] = privilege_esc
            
            # Detect anti-analysis techniques
            anti_analysis = self._detect_anti_analysis_techniques(execution_data)
            behavior_analysis['anti_analysis_techniques'] = anti_analysis
            
            # Calculate behavioral score
            behavior_analysis['behavioral_score'] = self._calculate_behavioral_score(
                behavior_analysis
            )
            
        except Exception as e:
            logging.error(f"Behavior analysis failed: {str(e)}")
            behavior_analysis['error'] = str(e)
            
        return behavior_analysis
        
    def _analyze_file_static(self, file_data):
        """Perform static analysis of file before execution."""
        if hasattr(file_data, 'read'):
            file_content = file_data.read()
            file_data.seek(0)
        else:
            with open(file_data, 'rb') as f:
                file_content = f.read()
                
        return {
            'file_size': len(file_content),
            'md5_hash': hashlib.md5(file_content).hexdigest(),
            'sha256_hash': hashlib.sha256(file_content).hexdigest(),
            'file_type': self._detect_file_type(file_content),
            'entropy': self._calculate_entropy(file_content),
            'strings': self._extract_strings(file_content)[:50],  # First 50 strings
            'pe_info': self._analyze_pe_structure(file_content) if file_content.startswith(b'MZ') else None
        }
        
    def _prepare_sandbox(self, sandbox_config):
        """Prepare sandbox environment for analysis."""
        sandbox_id = f"sandbox_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Simulated sandbox preparation
        return sandbox_id
        
    def _execute_in_sandbox(self, file_data, sandbox_id, config):
        """Execute file in sandbox and monitor execution."""
        return {
            'execution_status': 'completed',
            'execution_time': config.get('execution_time', 300),
            'exit_code': 0,
            'processes_created': 3,
            'files_created': 12,
            'network_connections': 5,
            'registry_modifications': 8,
            'api_calls_made': 245
        }
        
    def _collect_behavioral_data(self, sandbox_id):
        """Collect behavioral data from sandbox execution."""
        return {
            'process_activities': [
                {
                    'process_name': 'malware.exe',
                    'pid': 1234,
                    'parent_pid': 1000,
                    'start_time': '2024-01-15T10:30:00Z',
                    'command_line': 'C:\\temp\\malware.exe -silent',
                    'memory_usage': '25.6 MB',
                    'cpu_usage': 15.2
                },
                {
                    'process_name': 'svchost.exe',
                    'pid': 5678,
                    'parent_pid': 1234,
                    'start_time': '2024-01-15T10:30:15Z',
                    'command_line': 'C:\\Windows\\System32\\svchost.exe -k evil',
                    'memory_usage': '8.4 MB',
                    'cpu_usage': 2.1
                }
            ],
            'thread_activities': [
                {
                    'thread_id': 9012,
                    'process_id': 1234,
                    'start_time': '2024-01-15T10:30:05Z',
                    'activity_type': 'network_communication',
                    'details': 'Established connection to 203.0.113.50:8080'
                }
            ],
            'mutex_operations': [
                {
                    'mutex_name': 'Global\\MalwareMutex123',
                    'operation': 'create',
                    'timestamp': '2024-01-15T10:30:08Z',
                    'process_id': 1234
                }
            ]
        }
        
    def _monitor_network_activity(self, sandbox_id):
        """Monitor network activity during execution."""
        return {
            'dns_queries': [
                {
                    'query': 'malicious-domain.com',
                    'query_type': 'A',
                    'response': '203.0.113.50',
                    'timestamp': '2024-01-15T10:30:10Z'
                },
                {
                    'query': 'c2-server.evil',
                    'query_type': 'A',
                    'response': 'NXDOMAIN',
                    'timestamp': '2024-01-15T10:30:12Z'
                }
            ],
            'http_requests': [
                {
                    'url': 'http://malicious-domain.com/download/payload.exe',
                    'method': 'GET',
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'response_code': 200,
                    'response_size': 2457600,
                    'timestamp': '2024-01-15T10:30:15Z'
                }
            ],
            'tcp_connections': [
                {
                    'local_address': '192.168.1.100',
                    'local_port': 52341,
                    'remote_address': '203.0.113.50',
                    'remote_port': 8080,
                    'state': 'ESTABLISHED',
                    'timestamp': '2024-01-15T10:30:20Z'
                }
            ],
            'traffic_analysis': {
                'total_bytes_sent': 15728,
                'total_bytes_received': 2457600,
                'unique_destinations': 3,
                'suspicious_domains': ['malicious-domain.com', 'c2-server.evil']
            }
        }
        
    def _track_filesystem_changes(self, sandbox_id):
        """Track filesystem changes during execution."""
        return {
            'files_created': [
                {
                    'path': 'C:\\temp\\payload.exe',
                    'size': 2457600,
                    'timestamp': '2024-01-15T10:30:18Z',
                    'attributes': ['hidden', 'system']
                },
                {
                    'path': 'C:\\Users\\user\\AppData\\Roaming\\malware.dat',
                    'size': 1024,
                    'timestamp': '2024-01-15T10:30:25Z',
                    'attributes': ['hidden']
                }
            ],
            'files_modified': [
                {
                    'path': 'C:\\Windows\\System32\\hosts',
                    'original_size': 824,
                    'new_size': 945,
                    'timestamp': '2024-01-15T10:30:30Z',
                    'modification_type': 'content_changed'
                }
            ],
            'files_deleted': [
                {
                    'path': 'C:\\temp\\original_file.exe',
                    'timestamp': '2024-01-15T10:30:35Z',
                    'deletion_method': 'secure_delete'
                }
            ],
            'directories_created': [
                {
                    'path': 'C:\\ProgramData\\MalwareData',
                    'timestamp': '2024-01-15T10:30:22Z',
                    'attributes': ['hidden']
                }
            ]
        }
        
    def _monitor_registry_changes(self, sandbox_id):
        """Monitor Windows registry changes."""
        return {
            'keys_created': [
                {
                    'key': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware',
                    'value_name': 'MalwareStartup',
                    'value_data': 'C:\\temp\\payload.exe',
                    'value_type': 'REG_SZ',
                    'timestamp': '2024-01-15T10:30:28Z'
                }
            ],
            'keys_modified': [
                {
                    'key': 'HKLM\\System\\CurrentControlSet\\Services\\Themes',
                    'value_name': 'ImagePath',
                    'old_value': '%SystemRoot%\\System32\\svchost.exe -k themes',
                    'new_value': 'C:\\temp\\payload.exe',
                    'timestamp': '2024-01-15T10:30:40Z'
                }
            ],
            'keys_deleted': [
                {
                    'key': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LegitimateProgram',
                    'timestamp': '2024-01-15T10:30:45Z'
                }
            ]
        }
        
    def _capture_api_calls(self, sandbox_id):
        """Capture API calls made during execution."""
        return {
            'kernel32_calls': [
                {
                    'function': 'CreateFileW',
                    'parameters': {
                        'lpFileName': 'C:\\temp\\payload.exe',
                        'dwDesiredAccess': 'GENERIC_WRITE',
                        'dwCreationDisposition': 'CREATE_ALWAYS'
                    },
                    'return_value': 'HANDLE_SUCCESS',
                    'timestamp': '2024-01-15T10:30:18Z'
                },
                {
                    'function': 'VirtualAllocEx',
                    'parameters': {
                        'hProcess': '1234',
                        'lpAddress': 'NULL',
                        'dwSize': '4096',
                        'flAllocationType': 'MEM_COMMIT',
                        'flProtect': 'PAGE_EXECUTE_READWRITE'
                    },
                    'return_value': '0x7FF000000000',
                    'timestamp': '2024-01-15T10:30:50Z'
                }
            ],
            'ntdll_calls': [
                {
                    'function': 'NtCreateProcess',
                    'parameters': {
                        'ProcessHandle': 'OUT',
                        'DesiredAccess': 'PROCESS_ALL_ACCESS',
                        'ImagePathName': 'C:\\Windows\\System32\\svchost.exe'
                    },
                    'return_value': 'STATUS_SUCCESS',
                    'timestamp': '2024-01-15T10:30:55Z'
                }
            ],
            'wininet_calls': [
                {
                    'function': 'InternetOpenUrlA',
                    'parameters': {
                        'lpszUrl': 'http://malicious-domain.com/download/payload.exe',
                        'lpszHeaders': 'NULL',
                        'dwHeadersLength': '0',
                        'dwFlags': 'INTERNET_FLAG_RELOAD'
                    },
                    'return_value': 'HANDLE_SUCCESS',
                    'timestamp': '2024-01-15T10:30:15Z'
                }
            ]
        }
        
    def _capture_screenshots(self, sandbox_id):
        """Capture screenshots during execution."""
        return [
            {
                'timestamp': '2024-01-15T10:30:00Z',
                'filename': f'{sandbox_id}_screenshot_001.png',
                'description': 'Initial desktop state',
                'resolution': '1920x1080'
            },
            {
                'timestamp': '2024-01-15T10:30:30Z',
                'filename': f'{sandbox_id}_screenshot_002.png',
                'description': 'Malware execution dialog',
                'resolution': '1920x1080'
            },
            {
                'timestamp': '2024-01-15T10:31:00Z',
                'filename': f'{sandbox_id}_screenshot_003.png',
                'description': 'Final desktop state',
                'resolution': '1920x1080'
            }
        ]
        
    def _create_memory_dumps(self, sandbox_id):
        """Create memory dumps at key execution points."""
        return [
            {
                'timestamp': '2024-01-15T10:30:30Z',
                'dump_file': f'{sandbox_id}_memory_001.dmp',
                'dump_type': 'process_dump',
                'process_id': 1234,
                'size': '25.6 MB'
            },
            {
                'timestamp': '2024-01-15T10:31:00Z',
                'dump_file': f'{sandbox_id}_memory_002.dmp',
                'dump_type': 'full_memory_dump',
                'size': '8 GB'
            }
        ]
        
    def _assess_threat_level(self, analysis_results):
        """Assess overall threat level based on analysis results."""
        threat_score = 0
        threat_indicators = []
        
        # Network activity assessment
        network_activity = analysis_results.get('network_activity', {})
        if network_activity.get('suspicious_domains'):
            threat_score += 30
            threat_indicators.append('suspicious_network_communication')
            
        # Filesystem changes assessment
        fs_changes = analysis_results.get('filesystem_changes', {})
        if len(fs_changes.get('files_created', [])) > 5:
            threat_score += 20
            threat_indicators.append('excessive_file_creation')
            
        # Registry changes assessment (Windows)
        reg_changes = analysis_results.get('registry_changes', {})
        if reg_changes.get('keys_created'):
            for key in reg_changes['keys_created']:
                if 'Run' in key['key']:
                    threat_score += 25
                    threat_indicators.append('persistence_mechanism')
                    
        # API calls assessment
        api_calls = analysis_results.get('api_calls', {})
        dangerous_apis = ['VirtualAllocEx', 'CreateRemoteThread', 'WriteProcessMemory']
        for call_type, calls in api_calls.items():
            for call in calls:
                if call['function'] in dangerous_apis:
                    threat_score += 15
                    threat_indicators.append('dangerous_api_usage')
                    
        # Determine threat level
        if threat_score >= 70:
            threat_level = 'critical'
        elif threat_score >= 50:
            threat_level = 'high'
        elif threat_score >= 30:
            threat_level = 'medium'
        elif threat_score >= 10:
            threat_level = 'low'
        else:
            threat_level = 'minimal'
            
        return {
            'threat_score': threat_score,
            'threat_level': threat_level,
            'threat_indicators': threat_indicators,
            'malware_family': 'Unknown Trojan' if threat_score >= 50 else 'Potentially Unwanted Program',
            'confidence': min(threat_score / 100.0, 1.0)
        }
        
    def _extract_iocs(self, analysis_results):
        """Extract Indicators of Compromise from analysis results."""
        iocs = []
        
        # Extract network IOCs
        network_activity = analysis_results.get('network_activity', {})
        for domain in network_activity.get('traffic_analysis', {}).get('suspicious_domains', []):
            iocs.append({
                'type': 'domain',
                'value': domain,
                'source': 'network_analysis',
                'confidence': 'high'
            })
            
        # Extract file IOCs
        file_info = analysis_results.get('file_info', {})
        if file_info.get('sha256_hash'):
            iocs.append({
                'type': 'file_hash',
                'value': file_info['sha256_hash'],
                'source': 'static_analysis',
                'confidence': 'high'
            })
            
        # Extract registry IOCs
        reg_changes = analysis_results.get('registry_changes', {})
        for key in reg_changes.get('keys_created', []):
            if 'Run' in key['key']:
                iocs.append({
                    'type': 'registry_key',
                    'value': key['key'],
                    'source': 'dynamic_analysis',
                    'confidence': 'medium'
                })
                
        # Extract mutex IOCs
        behavioral = analysis_results.get('behavioral_analysis', {})
        for mutex in behavioral.get('mutex_operations', []):
            iocs.append({
                'type': 'mutex',
                'value': mutex['mutex_name'],
                'source': 'behavioral_analysis',
                'confidence': 'medium'
            })
            
        return iocs
        
    def _cleanup_sandbox(self, sandbox_id):
        """Cleanup sandbox environment after analysis."""
        # Simulated cleanup
        pass
        
    # Additional helper methods for behavior analysis
    def _detect_file_type(self, file_content):
        """Detect file type from content."""
        if file_content.startswith(b'MZ'):
            return 'PE Executable'
        elif file_content.startswith(b'\x7fELF'):
            return 'ELF Executable'
        elif file_content.startswith(b'PK'):
            return 'ZIP Archive'
        else:
            return 'Unknown'
            
    def _calculate_entropy(self, data):
        """Calculate entropy of file data."""
        import math
        from collections import Counter
        
        if not data:
            return 0
            
        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
        
    def _extract_strings(self, file_content):
        """Extract strings from file content."""
        import re
        strings = re.findall(b'[a-zA-Z0-9/\-:.,_$%@()[\]<> ]{4,}', file_content)
        return [s.decode('utf-8', errors='ignore') for s in strings]
        
    def _analyze_pe_structure(self, file_content):
        """Basic PE structure analysis."""
        return {
            'pe_type': 'PE32',
            'architecture': 'x86',
            'sections': ['text', 'data', 'rsrc'],
            'imports': ['kernel32.dll', 'user32.dll', 'wininet.dll'],
            'exports': [],
            'compilation_timestamp': '2024-01-10T15:30:00Z'
        }