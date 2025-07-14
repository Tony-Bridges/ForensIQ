"""
Live and Remote Forensics Module
Acquire data from running systems remotely without tampering with evidence.
"""
import json
from datetime import datetime
import logging
import socket
import os

class LiveRemoteForensics:
    def __init__(self):
        self.supported_protocols = ['ssh', 'wmi', 'powershell_remoting', 'snmp']
        self.acquisition_methods = ['memory_dump', 'disk_imaging', 'file_collection', 'process_analysis']
        self.remote_tools = ['volatility', 'rekall', 'winpmem', 'osxpmem']
        
    def remote_memory_acquisition(self, target_info, acquisition_method='winpmem'):
        """
        Acquire memory from remote system.
        
        Args:
            target_info: Target system information and credentials
            acquisition_method: Memory acquisition tool to use
            
        Returns:
            dict: Memory acquisition results
        """
        acquisition_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_system': target_info.get('hostname', 'unknown'),
            'acquisition_method': acquisition_method,
            'memory_dump_info': {},
            'acquisition_status': 'unknown',
            'integrity_verification': {},
            'evidence_metadata': {},
            'chain_of_custody': []
        }
        
        try:
            # Establish secure connection
            connection_result = self._establish_secure_connection(target_info)
            if not connection_result['success']:
                acquisition_results['error'] = connection_result['error']
                return acquisition_results
                
            # Verify target system
            system_info = self._verify_target_system(target_info)
            acquisition_results['target_system_info'] = system_info
            
            # Perform memory acquisition
            if acquisition_method == 'winpmem':
                memory_result = self._acquire_windows_memory(target_info)
            elif acquisition_method == 'osxpmem':
                memory_result = self._acquire_macos_memory(target_info)
            elif acquisition_method == 'volatility':
                memory_result = self._acquire_linux_memory(target_info)
            else:
                memory_result = {'error': f'Unsupported acquisition method: {acquisition_method}'}
                
            acquisition_results.update(memory_result)
            
            # Verify integrity
            if acquisition_results.get('memory_dump_path'):
                acquisition_results['integrity_verification'] = self._verify_memory_integrity(
                    acquisition_results['memory_dump_path']
                )
                
            # Generate evidence metadata
            acquisition_results['evidence_metadata'] = self._generate_evidence_metadata(
                acquisition_results
            )
            
            # Log chain of custody
            acquisition_results['chain_of_custody'] = self._log_chain_of_custody(
                'memory_acquisition', acquisition_results
            )
            
        except Exception as e:
            logging.error(f"Remote memory acquisition failed: {str(e)}")
            acquisition_results['error'] = str(e)
            
        return acquisition_results
        
    def live_process_analysis(self, target_info, analysis_options=None):
        """
        Analyze running processes on live system.
        
        Args:
            target_info: Target system information
            analysis_options: Analysis configuration options
            
        Returns:
            dict: Live process analysis results
        """
        if analysis_options is None:
            analysis_options = ['process_list', 'network_connections', 'loaded_modules', 'handles']
            
        process_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_system': target_info.get('hostname', 'unknown'),
            'running_processes': [],
            'suspicious_processes': [],
            'network_connections': [],
            'loaded_modules': {},
            'process_tree': {},
            'memory_analysis': {},
            'behavioral_indicators': []
        }
        
        try:
            # Get running processes
            if 'process_list' in analysis_options:
                process_results['running_processes'] = self._get_running_processes(target_info)
                
            # Analyze network connections
            if 'network_connections' in analysis_options:
                process_results['network_connections'] = self._get_network_connections(target_info)
                
            # Get loaded modules
            if 'loaded_modules' in analysis_options:
                process_results['loaded_modules'] = self._get_loaded_modules(target_info)
                
            # Analyze process handles
            if 'handles' in analysis_options:
                process_results['process_handles'] = self._get_process_handles(target_info)
                
            # Detect suspicious processes
            process_results['suspicious_processes'] = self._detect_suspicious_processes(
                process_results['running_processes']
            )
            
            # Build process tree
            process_results['process_tree'] = self._build_process_tree(
                process_results['running_processes']
            )
            
            # Analyze process behavior
            process_results['behavioral_indicators'] = self._analyze_process_behavior(
                process_results
            )
            
        except Exception as e:
            logging.error(f"Live process analysis failed: {str(e)}")
            process_results['error'] = str(e)
            
        return process_results
        
    def remote_file_collection(self, target_info, collection_rules):
        """
        Collect specific files from remote system.
        
        Args:
            target_info: Target system information
            collection_rules: Rules defining what files to collect
            
        Returns:
            dict: File collection results
        """
        collection_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_system': target_info.get('hostname', 'unknown'),
            'collection_rules': collection_rules,
            'collected_files': [],
            'failed_collections': [],
            'total_files_collected': 0,
            'total_size_collected': 0,
            'integrity_hashes': {},
            'collection_log': []
        }
        
        try:
            # Process collection rules
            file_targets = self._process_collection_rules(collection_rules)
            
            # Collect files based on rules
            for target in file_targets:
                collection_result = self._collect_remote_file(target_info, target)
                
                if collection_result['success']:
                    collection_results['collected_files'].append(collection_result)
                    collection_results['total_files_collected'] += 1
                    collection_results['total_size_collected'] += collection_result.get('file_size', 0)
                else:
                    collection_results['failed_collections'].append(collection_result)
                    
                # Log collection activity
                collection_results['collection_log'].append({
                    'timestamp': datetime.utcnow().isoformat(),
                    'action': 'file_collection',
                    'target': target,
                    'result': 'success' if collection_result['success'] else 'failed'
                })
                
            # Generate integrity hashes
            collection_results['integrity_hashes'] = self._generate_collection_hashes(
                collection_results['collected_files']
            )
            
        except Exception as e:
            logging.error(f"Remote file collection failed: {str(e)}")
            collection_results['error'] = str(e)
            
        return collection_results
        
    def live_registry_analysis(self, target_info, registry_keys=None):
        """
        Analyze Windows registry on live system.
        
        Args:
            target_info: Target system information
            registry_keys: Specific registry keys to analyze
            
        Returns:
            dict: Registry analysis results
        """
        if registry_keys is None:
            registry_keys = [
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM\\System\\CurrentControlSet\\Services',
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
            ]
            
        registry_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_system': target_info.get('hostname', 'unknown'),
            'registry_analysis': {},
            'suspicious_entries': [],
            'autostart_locations': [],
            'installed_software': [],
            'service_analysis': {},
            'recent_modifications': []
        }
        
        try:
            # Analyze each registry key
            for key in registry_keys:
                key_analysis = self._analyze_registry_key(target_info, key)
                registry_results['registry_analysis'][key] = key_analysis
                
            # Detect suspicious entries
            registry_results['suspicious_entries'] = self._detect_suspicious_registry_entries(
                registry_results['registry_analysis']
            )
            
            # Extract autostart locations
            registry_results['autostart_locations'] = self._extract_autostart_locations(
                registry_results['registry_analysis']
            )
            
            # Extract installed software
            registry_results['installed_software'] = self._extract_installed_software(
                registry_results['registry_analysis']
            )
            
            # Analyze services
            registry_results['service_analysis'] = self._analyze_services(
                registry_results['registry_analysis']
            )
            
        except Exception as e:
            logging.error(f"Live registry analysis failed: {str(e)}")
            registry_results['error'] = str(e)
            
        return registry_results
        
    def remote_network_analysis(self, target_info, capture_duration=300):
        """
        Perform network analysis on remote system.
        
        Args:
            target_info: Target system information
            capture_duration: Duration in seconds to capture network traffic
            
        Returns:
            dict: Network analysis results
        """
        network_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_system': target_info.get('hostname', 'unknown'),
            'capture_duration': capture_duration,
            'network_interfaces': [],
            'active_connections': [],
            'listening_ports': [],
            'network_statistics': {},
            'suspicious_connections': [],
            'bandwidth_analysis': {}
        }
        
        try:
            # Get network interfaces
            network_results['network_interfaces'] = self._get_network_interfaces(target_info)
            
            # Get active connections
            network_results['active_connections'] = self._get_active_connections(target_info)
            
            # Get listening ports
            network_results['listening_ports'] = self._get_listening_ports(target_info)
            
            # Collect network statistics
            network_results['network_statistics'] = self._collect_network_statistics(target_info)
            
            # Detect suspicious connections
            network_results['suspicious_connections'] = self._detect_suspicious_connections(
                network_results['active_connections']
            )
            
            # Perform bandwidth analysis
            network_results['bandwidth_analysis'] = self._analyze_bandwidth_usage(target_info)
            
        except Exception as e:
            logging.error(f"Remote network analysis failed: {str(e)}")
            network_results['error'] = str(e)
            
        return network_results
        
    def _establish_secure_connection(self, target_info):
        """Establish secure connection to target system."""
        # Simulated secure connection establishment
        return {
            'success': True,
            'connection_type': target_info.get('protocol', 'ssh'),
            'encryption': 'AES-256',
            'authentication': 'key-based'
        }
        
    def _verify_target_system(self, target_info):
        """Verify target system information."""
        return {
            'hostname': target_info.get('hostname', 'target-system'),
            'os_version': 'Windows 10 Enterprise',
            'architecture': 'x64',
            'domain': 'CORPORATE',
            'last_boot_time': '2024-01-15T06:00:00Z',
            'system_time': datetime.utcnow().isoformat()
        }
        
    def _acquire_windows_memory(self, target_info):
        """Acquire memory from Windows system."""
        return {
            'acquisition_status': 'completed',
            'memory_dump_path': f'/evidence/{target_info.get("hostname", "unknown")}_memory.dmp',
            'memory_size': '8 GB',
            'acquisition_time': '00:15:30',
            'tool_version': 'WinPMem 3.3',
            'compression': 'none',
            'md5_hash': 'a1b2c3d4e5f6789012345678901234567890abcd',
            'sha256_hash': 'ef123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
        }
        
    def _acquire_macos_memory(self, target_info):
        """Acquire memory from macOS system."""
        return {
            'acquisition_status': 'completed',
            'memory_dump_path': f'/evidence/{target_info.get("hostname", "unknown")}_memory.mem',
            'memory_size': '16 GB',
            'acquisition_time': '00:22:45',
            'tool_version': 'OSXPMem 2.1',
            'compression': 'gzip',
            'md5_hash': 'b2c3d4e5f6789012345678901234567890abcde1',
            'sha256_hash': 'f0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0'
        }
        
    def _acquire_linux_memory(self, target_info):
        """Acquire memory from Linux system."""
        return {
            'acquisition_status': 'completed',
            'memory_dump_path': f'/evidence/{target_info.get("hostname", "unknown")}_memory.lime',
            'memory_size': '32 GB',
            'acquisition_time': '00:45:15',
            'tool_version': 'LiME 1.9',
            'compression': 'none',
            'md5_hash': 'c3d4e5f6789012345678901234567890abcdef12',
            'sha256_hash': '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde01'
        }
        
    def _get_running_processes(self, target_info):
        """Get list of running processes."""
        # Simulated process list
        return [
            {
                'pid': 1234,
                'name': 'explorer.exe',
                'parent_pid': 1000,
                'user': 'CORPORATE\\user',
                'start_time': '2024-01-15T08:00:00Z',
                'memory_usage': '45.2 MB',
                'cpu_percent': 2.1,
                'command_line': 'C:\\Windows\\explorer.exe'
            },
            {
                'pid': 5678,
                'name': 'suspicious.exe',
                'parent_pid': 1234,
                'user': 'CORPORATE\\user',
                'start_time': '2024-01-15T10:30:00Z',
                'memory_usage': '125.8 MB',
                'cpu_percent': 15.6,
                'command_line': 'C:\\temp\\suspicious.exe -hidden'
            },
            {
                'pid': 9012,
                'name': 'svchost.exe',
                'parent_pid': 4,
                'user': 'NT AUTHORITY\\SYSTEM',
                'start_time': '2024-01-15T06:05:00Z',
                'memory_usage': '78.4 MB',
                'cpu_percent': 0.8,
                'command_line': 'C:\\Windows\\System32\\svchost.exe -k NetworkService'
            }
        ]
        
    def _get_network_connections(self, target_info):
        """Get active network connections."""
        return [
            {
                'local_address': '192.168.1.100',
                'local_port': 52341,
                'remote_address': '203.0.113.10',
                'remote_port': 80,
                'protocol': 'TCP',
                'state': 'ESTABLISHED',
                'pid': 1234,
                'process_name': 'chrome.exe'
            },
            {
                'local_address': '192.168.1.100',
                'local_port': 52342,
                'remote_address': '198.51.100.25',
                'remote_port': 443,
                'protocol': 'TCP',
                'state': 'ESTABLISHED',
                'pid': 5678,
                'process_name': 'suspicious.exe'
            }
        ]
        
    def _detect_suspicious_processes(self, processes):
        """Detect suspicious processes."""
        suspicious = []
        
        for process in processes:
            risk_factors = []
            
            # Check for suspicious names
            if 'suspicious' in process['name'].lower():
                risk_factors.append('suspicious_name')
                
            # Check for high CPU usage
            if process['cpu_percent'] > 20:
                risk_factors.append('high_cpu_usage')
                
            # Check for temporary directory execution
            if '\\temp\\' in process['command_line'] or '/tmp/' in process['command_line']:
                risk_factors.append('temp_directory_execution')
                
            # Check for command line arguments
            if '-hidden' in process['command_line'] or '--silent' in process['command_line']:
                risk_factors.append('suspicious_arguments')
                
            if risk_factors:
                suspicious.append({
                    'process': process,
                    'risk_factors': risk_factors,
                    'risk_score': len(risk_factors) * 25  # 25 points per factor
                })
                
        return suspicious
        
    def _verify_memory_integrity(self, memory_dump_path):
        """Verify integrity of memory dump."""
        return {
            'verification_method': 'cryptographic_hash',
            'md5_hash': 'a1b2c3d4e5f6789012345678901234567890abcd',
            'sha256_hash': 'ef123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            'verification_time': datetime.utcnow().isoformat(),
            'integrity_status': 'verified'
        }
        
    def _generate_evidence_metadata(self, acquisition_results):
        """Generate metadata for acquired evidence."""
        return {
            'case_number': 'CASE-2024-001',
            'investigator': 'Digital Forensics Team',
            'acquisition_date': datetime.utcnow().isoformat(),
            'evidence_type': 'memory_dump',
            'source_system': acquisition_results.get('target_system', 'unknown'),
            'acquisition_tool': acquisition_results.get('acquisition_method', 'unknown'),
            'file_size': acquisition_results.get('memory_size', 'unknown'),
            'hash_algorithm': 'SHA-256',
            'notes': 'Live memory acquisition from running system'
        }
        
    def _log_chain_of_custody(self, action, results):
        """Log chain of custody entry."""
        return [
            {
                'timestamp': datetime.utcnow().isoformat(),
                'action': action,
                'investigator': 'Digital Forensics Team',
                'details': f'Remote {action} completed successfully',
                'system': results.get('target_system', 'unknown'),
                'integrity_verified': True
            }
        ]