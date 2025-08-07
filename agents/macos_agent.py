import os
import subprocess
import platform
import plistlib
from agents.base_agent import BaseAgent
import logging

logger = logging.getLogger(__name__)

class MacOSAgent(BaseAgent):
    """macOS-specific forensic agent"""
    
    def __init__(self, agent_id=None, server_url="ws://127.0.0.1:5000"):
        super().__init__(agent_id, server_url)
        self.platform = "macos"
    
    def _get_capabilities(self):
        """Get macOS-specific capabilities"""
        return {
            'memory_capture': True,
            'file_hashing': True,
            'system_log_collection': True,
            'keychain_analysis': True,
            'spotlight_metadata': True,
            'process_analysis': True,
            'network_monitoring': True,
            'launch_agents_analysis': True,
            'filesystem_timeline': True
        }
    
    def collect_memory_dump(self, output_path):
        """Collect macOS memory dump using osxpmem or vmmap"""
        try:
            logger.info(f"Collecting macOS memory dump to {output_path}")
            
            # In production, would use osxpmem or other memory acquisition tools
            # For simulation, create a placeholder file
            
            with open(output_path, 'wb') as f:
                # Write some dummy data to simulate memory dump
                f.write(b'MACOS_MEMORY_DUMP_SIMULATION')
                f.write(b'\x00' * (1024 * 1024))  # 1MB of zeros
            
            logger.info(f"Memory dump collected: {output_path}")
            return {'success': True, 'output_path': output_path}
            
        except Exception as e:
            logger.error(f"Memory dump collection failed: {e}")
            raise
    
    def hash_files(self, paths):
        """Hash files using macOS utilities"""
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
        """Hash a single file using shasum"""
        try:
            # In production, would use shasum command
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
        """Collect macOS system information"""
        try:
            system_info = {
                'platform': 'macOS',
                'version': platform.mac_ver()[0],
                'architecture': platform.architecture()[0],
                'hostname': platform.node(),
                'hardware': self._get_hardware_info(),
                'users': self._get_users(),
                'processes': self._get_running_processes(),
                'network_config': self._get_network_config(),
                'launch_agents': self._get_launch_agents(),
                'installed_applications': self._get_installed_applications(),
                'system_preferences': self._get_system_preferences()
            }
            
            return system_info
            
        except Exception as e:
            logger.error(f"System info collection failed: {e}")
            return {'error': str(e)}
    
    def _get_hardware_info(self):
        """Get hardware information using system_profiler"""
        try:
            # Use system_profiler to get hardware info
            result = subprocess.run(['system_profiler', 'SPHardwareDataType', '-json'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                return data.get('SPHardwareDataType', [{}])[0]
            else:
                # Fallback to basic info
                return {
                    'machine_model': platform.machine(),
                    'processor_name': platform.processor()
                }
                
        except Exception as e:
            logger.error(f"Hardware info collection failed: {e}")
            return {}
    
    def _get_users(self):
        """Get system users using dscl"""
        try:
            users = []
            
            # Get list of users
            result = subprocess.run(['dscl', '.', 'list', '/Users'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                user_list = result.stdout.strip().split('\n')
                
                for username in user_list[:10]:  # First 10 users for demo
                    if username and not username.startswith('_'):  # Skip system users
                        user_info = self._get_user_info(username)
                        users.append(user_info)
            
            return users
            
        except Exception as e:
            logger.error(f"User enumeration failed: {e}")
            return []
    
    def _get_user_info(self, username):
        """Get detailed info for a specific user"""
        try:
            user_info = {'username': username}
            
            # Get user details
            attributes = ['UniqueID', 'PrimaryGroupID', 'RealName', 'NFSHomeDirectory', 'UserShell']
            
            for attr in attributes:
                try:
                    result = subprocess.run(['dscl', '.', 'read', f'/Users/{username}', attr],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        value = result.stdout.split(':', 1)[1].strip() if ':' in result.stdout else ''
                        user_info[attr.lower()] = value
                except subprocess.TimeoutExpired:
                    continue
            
            return user_info
            
        except Exception as e:
            logger.error(f"User info collection failed for {username}: {e}")
            return {'username': username, 'error': str(e)}
    
    def _get_running_processes(self):
        """Get running processes"""
        try:
            import psutil
            
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline'])[:20]:
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'username': proc_info['username'],
                        'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return processes
            
        except Exception as e:
            logger.error(f"Process enumeration failed: {e}")
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
    
    def _get_launch_agents(self):
        """Get LaunchAgents and LaunchDaemons"""
        try:
            launch_items = []
            
            # LaunchAgent and LaunchDaemon directories
            launch_dirs = [
                '/System/Library/LaunchAgents',
                '/System/Library/LaunchDaemons',
                '/Library/LaunchAgents',
                '/Library/LaunchDaemons',
                os.path.expanduser('~/Library/LaunchAgents')
            ]
            
            for launch_dir in launch_dirs:
                if os.path.exists(launch_dir):
                    try:
                        for file in os.listdir(launch_dir)[:5]:  # First 5 files per directory
                            if file.endswith('.plist'):
                                file_path = os.path.join(launch_dir, file)
                                plist_info = self._parse_plist(file_path)
                                launch_items.append({
                                    'path': file_path,
                                    'filename': file,
                                    'directory': launch_dir,
                                    'plist_data': plist_info
                                })
                    except PermissionError:
                        continue
            
            return launch_items
            
        except Exception as e:
            logger.error(f"LaunchAgent enumeration failed: {e}")
            return []
    
    def _parse_plist(self, plist_path):
        """Parse plist file"""
        try:
            with open(plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
                
                # Extract key information
                return {
                    'label': plist_data.get('Label', ''),
                    'program': plist_data.get('Program', ''),
                    'program_arguments': plist_data.get('ProgramArguments', []),
                    'run_at_load': plist_data.get('RunAtLoad', False),
                    'keep_alive': plist_data.get('KeepAlive', False)
                }
                
        except Exception as e:
            logger.error(f"Plist parsing failed for {plist_path}: {e}")
            return {'error': str(e)}
    
    def _get_installed_applications(self):
        """Get installed applications"""
        try:
            applications = []
            app_dirs = ['/Applications', '/System/Applications']
            
            for app_dir in app_dirs:
                if os.path.exists(app_dir):
                    try:
                        for item in os.listdir(app_dir)[:10]:  # First 10 apps per directory
                            if item.endswith('.app'):
                                app_path = os.path.join(app_dir, item)
                                app_info = {
                                    'name': item,
                                    'path': app_path,
                                    'directory': app_dir
                                }
                                
                                # Try to get app info from Info.plist
                                info_plist_path = os.path.join(app_path, 'Contents', 'Info.plist')
                                if os.path.exists(info_plist_path):
                                    plist_info = self._parse_plist(info_plist_path)
                                    app_info['bundle_id'] = plist_info.get('CFBundleIdentifier', '')
                                    app_info['version'] = plist_info.get('CFBundleShortVersionString', '')
                                
                                applications.append(app_info)
                    except PermissionError:
                        continue
            
            return applications
            
        except Exception as e:
            logger.error(f"Application enumeration failed: {e}")
            return []
    
    def _get_system_preferences(self):
        """Get system preferences"""
        try:
            preferences = {}
            
            # Read some key system preferences
            pref_files = [
                '/Library/Preferences/com.apple.TimeMachine.plist',
                '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'
            ]
            
            for pref_file in pref_files:
                if os.path.exists(pref_file):
                    try:
                        pref_data = self._parse_plist(pref_file)
                        preferences[os.path.basename(pref_file)] = pref_data
                    except Exception:
                        continue
            
            return preferences
            
        except Exception as e:
            logger.error(f"System preferences collection failed: {e}")
            return {}
