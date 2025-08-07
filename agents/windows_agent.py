import os
import subprocess
import winreg
import platform
from agents.base_agent import BaseAgent
import logging

logger = logging.getLogger(__name__)

class WindowsAgent(BaseAgent):
    """Windows-specific forensic agent"""
    
    def __init__(self, agent_id=None, server_url="ws://127.0.0.1:5000"):
        super().__init__(agent_id, server_url)
        self.platform = "windows"
    
    def _get_capabilities(self):
        """Get Windows-specific capabilities"""
        return {
            'memory_capture': True,
            'file_hashing': True,
            'registry_analysis': True,
            'event_log_collection': True,
            'wmi_queries': True,
            'process_analysis': True,
            'network_monitoring': True,
            'prefetch_analysis': True,
            'ntfs_timeline': True
        }
    
    def collect_memory_dump(self, output_path):
        """Collect Windows memory dump using winpmem or similar tool"""
        try:
            # In production, would use winpmem or DumpIt
            # For simulation, create a placeholder file
            
            logger.info(f"Collecting Windows memory dump to {output_path}")
            
            # Simulate memory dump collection
            with open(output_path, 'wb') as f:
                # Write some dummy data to simulate memory dump
                f.write(b'WINDOWS_MEMORY_DUMP_SIMULATION')
                f.write(b'\x00' * (1024 * 1024))  # 1MB of zeros
            
            logger.info(f"Memory dump collected: {output_path}")
            return {'success': True, 'output_path': output_path}
            
        except Exception as e:
            logger.error(f"Memory dump collection failed: {e}")
            raise
    
    def hash_files(self, paths):
        """Hash files using Windows utilities"""
        hash_results = {}
        
        for path in paths:
            try:
                if os.path.isfile(path):
                    # Hash single file
                    file_hash = self._hash_single_file(path)
                    hash_results[path] = file_hash
                elif os.path.isdir(path):
                    # Hash directory recursively
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                file_hash = self._hash_single_file(file_path)
                                hash_results[file_path] = file_hash
                            except Exception as e:
                                logger.warning(f"Failed to hash {file_path}: {e}")
                
            except Exception as e:
                logger.error(f"Error processing path {path}: {e}")
        
        return hash_results
    
    def _hash_single_file(self, file_path):
        """Hash a single file using certutil or PowerShell"""
        try:
            # In production, would use certutil or PowerShell Get-FileHash
            # For simulation, return a mock hash
            import hashlib
            
            # Use file path and size to generate consistent mock hash
            with open(file_path, 'rb') as f:
                # Read first 1KB for hash simulation
                data = f.read(1024)
                return hashlib.sha256(data + file_path.encode()).hexdigest()
                
        except Exception as e:
            # Return a deterministic mock hash based on file path
            import hashlib
            return hashlib.sha256(file_path.encode()).hexdigest()
    
    def collect_system_info(self):
        """Collect Windows system information"""
        try:
            system_info = {
                'platform': 'Windows',
                'version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'hostname': platform.node(),
                'domain': self._get_domain_info(),
                'installed_software': self._get_installed_software(),
                'services': self._get_services(),
                'network_config': self._get_network_config(),
                'event_logs': self._get_event_log_info(),
                'startup_programs': self._get_startup_programs()
            }
            
            return system_info
            
        except Exception as e:
            logger.error(f"System info collection failed: {e}")
            return {'error': str(e)}
    
    def _get_domain_info(self):
        """Get Windows domain information"""
        try:
            # Simulate domain info
            return {
                'domain': 'WORKGROUP',  # Default for non-domain machines
                'computer_name': platform.node(),
                'is_domain_joined': False
            }
        except Exception as e:
            logger.error(f"Domain info collection failed: {e}")
            return {}
    
    def _get_installed_software(self):
        """Get list of installed software from registry"""
        try:
            software_list = []
            
            # Registry paths for installed software
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for reg_path in registry_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                        # Get first few subkeys for simulation
                        for i in range(min(10, winreg.QueryInfoKey(key)[0])):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    software_list.append({
                                        'name': display_name,
                                        'registry_key': subkey_name
                                    })
                            except (OSError, FileNotFoundError):
                                continue
                except (OSError, FileNotFoundError):
                    continue
            
            return software_list[:20]  # Limit to first 20 for demo
            
        except Exception as e:
            logger.error(f"Software enumeration failed: {e}")
            return []
    
    def _get_services(self):
        """Get Windows services information"""
        try:
            # Simulate services using psutil
            import psutil
            
            services = []
            for service in list(psutil.win_service_iter())[:10]:  # First 10 for demo
                try:
                    service_info = service.as_dict()
                    services.append({
                        'name': service_info.get('name'),
                        'display_name': service_info.get('display_name'),
                        'status': service_info.get('status'),
                        'start_type': service_info.get('start_type')
                    })
                except Exception:
                    continue
            
            return services
            
        except Exception as e:
            logger.error(f"Services enumeration failed: {e}")
            return []
    
    def _get_network_config(self):
        """Get network configuration"""
        try:
            import psutil
            
            network_info = {
                'interfaces': [],
                'connections': []
            }
            
            # Network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                if_info = {'name': interface, 'addresses': []}
                for addr in addrs:
                    if_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                network_info['interfaces'].append(if_info)
            
            # Active connections (first 10)
            for conn in psutil.net_connections()[:10]:
                network_info['connections'].append({
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
            
            return network_info
            
        except Exception as e:
            logger.error(f"Network config collection failed: {e}")
            return {}
    
    def _get_event_log_info(self):
        """Get Windows Event Log information"""
        try:
            # Simulate event log analysis
            return {
                'security_events': 1234,
                'system_events': 5678,
                'application_events': 9012,
                'recent_logons': [
                    {'user': 'Administrator', 'time': '2024-08-06 10:30:00', 'type': 'Interactive'},
                    {'user': 'user1', 'time': '2024-08-06 09:15:00', 'type': 'Network'}
                ]
            }
            
        except Exception as e:
            logger.error(f"Event log analysis failed: {e}")
            return {}
    
    def _get_startup_programs(self):
        """Get startup programs"""
        try:
            startup_programs = []
            
            # Registry locations for startup programs
            startup_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            ]
            
            for key_path in startup_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                        for i in range(winreg.QueryInfoKey(key)[1]):  # Number of values
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                startup_programs.append({
                                    'name': name,
                                    'command': value,
                                    'location': f"HKLM\\{key_path}"
                                })
                            except OSError:
                                continue
                except OSError:
                    continue
            
            return startup_programs
            
        except Exception as e:
            logger.error(f"Startup programs enumeration failed: {e}")
            return []
    
    def collect_prefetch_analysis(self):
        """Analyze Windows Prefetch files"""
        try:
            prefetch_path = r"C:\Windows\Prefetch"
            prefetch_files = []
            
            if os.path.exists(prefetch_path):
                for file in os.listdir(prefetch_path)[:10]:  # First 10 for demo
                    if file.endswith('.pf'):
                        file_path = os.path.join(prefetch_path, file)
                        prefetch_files.append({
                            'filename': file,
                            'path': file_path,
                            'size': os.path.getsize(file_path),
                            'modified': os.path.getmtime(file_path)
                        })
            
            return prefetch_files
            
        except Exception as e:
            logger.error(f"Prefetch analysis failed: {e}")
            return []
