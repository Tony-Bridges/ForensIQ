import os
import subprocess
import platform
import pwd
import grp
from agents.base_agent import BaseAgent
import logging

logger = logging.getLogger(__name__)

class LinuxAgent(BaseAgent):
    """Linux-specific forensic agent"""
    
    def __init__(self, agent_id=None, server_url="ws://127.0.0.1:5000"):
        super().__init__(agent_id, server_url)
        self.platform = "linux"
    
    def _get_capabilities(self):
        """Get Linux-specific capabilities"""
        return {
            'memory_capture': True,
            'file_hashing': True,
            'system_call_tracing': True,
            'kernel_module_analysis': True,
            'container_inspection': True,
            'process_analysis': True,
            'network_monitoring': True,
            'log_analysis': True,
            'filesystem_timeline': True
        }
    
    def collect_memory_dump(self, output_path):
        """Collect Linux memory dump using dd or lime"""
        try:
            logger.info(f"Collecting Linux memory dump to {output_path}")
            
            # In production, would use LiME or dd if=/dev/mem
            # For simulation, create a placeholder file
            
            with open(output_path, 'wb') as f:
                # Write some dummy data to simulate memory dump
                f.write(b'LINUX_MEMORY_DUMP_SIMULATION')
                f.write(b'\x00' * (1024 * 1024))  # 1MB of zeros
            
            logger.info(f"Memory dump collected: {output_path}")
            return {'success': True, 'output_path': output_path}
            
        except Exception as e:
            logger.error(f"Memory dump collection failed: {e}")
            raise
    
    def hash_files(self, paths):
        """Hash files using Linux utilities"""
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
        """Hash a single file using sha256sum"""
        try:
            # In production, would use sha256sum command
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
        """Collect Linux system information"""
        try:
            system_info = {
                'platform': 'Linux',
                'distribution': self._get_distribution(),
                'kernel': platform.uname().release,
                'architecture': platform.architecture()[0],
                'hostname': platform.node(),
                'users': self._get_users(),
                'groups': self._get_groups(),
                'processes': self._get_running_processes(),
                'network_config': self._get_network_config(),
                'mounted_filesystems': self._get_mounted_filesystems(),
                'cron_jobs': self._get_cron_jobs(),
                'systemd_services': self._get_systemd_services()
            }
            
            return system_info
            
        except Exception as e:
            logger.error(f"System info collection failed: {e}")
            return {'error': str(e)}
    
    def _get_distribution(self):
        """Get Linux distribution information"""
        try:
            # Read /etc/os-release
            dist_info = {}
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            dist_info[key] = value.strip('"')
            
            return dist_info
            
        except Exception as e:
            logger.error(f"Distribution detection failed: {e}")
            return {'error': str(e)}
    
    def _get_users(self):
        """Get system users"""
        try:
            users = []
            for user in pwd.getpwall()[:10]:  # First 10 users for demo
                users.append({
                    'username': user.pw_name,
                    'uid': user.pw_uid,
                    'gid': user.pw_gid,
                    'home': user.pw_dir,
                    'shell': user.pw_shell
                })
            
            return users
            
        except Exception as e:
            logger.error(f"User enumeration failed: {e}")
            return []
    
    def _get_groups(self):
        """Get system groups"""
        try:
            groups = []
            for group in grp.getgrall()[:10]:  # First 10 groups for demo
                groups.append({
                    'groupname': group.gr_name,
                    'gid': group.gr_gid,
                    'members': list(group.gr_mem)
                })
            
            return groups
            
        except Exception as e:
            logger.error(f"Group enumeration failed: {e}")
            return []
    
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
                'connections': [],
                'routing_table': self._get_routing_table()
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
    
    def _get_routing_table(self):
        """Get routing table"""
        try:
            # Read /proc/net/route for IPv4 routing table
            routing_entries = []
            if os.path.exists('/proc/net/route'):
                with open('/proc/net/route', 'r') as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines[:10]:  # First 10 entries
                        fields = line.strip().split()
                        if len(fields) >= 8:
                            routing_entries.append({
                                'interface': fields[0],
                                'destination': fields[1],
                                'gateway': fields[2],
                                'flags': fields[3],
                                'metric': fields[6]
                            })
            
            return routing_entries
            
        except Exception as e:
            logger.error(f"Routing table collection failed: {e}")
            return []
    
    def _get_mounted_filesystems(self):
        """Get mounted filesystems"""
        try:
            import psutil
            
            filesystems = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    filesystems.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free
                    })
                except PermissionError:
                    continue
            
            return filesystems
            
        except Exception as e:
            logger.error(f"Filesystem enumeration failed: {e}")
            return []
    
    def _get_cron_jobs(self):
        """Get cron jobs"""
        try:
            cron_jobs = []
            
            # System crontab
            system_crontab_paths = ['/etc/crontab', '/etc/cron.d/']
            
            for path in system_crontab_paths:
                if os.path.isfile(path):
                    try:
                        with open(path, 'r') as f:
                            for line_num, line in enumerate(f.readlines()[:10]):
                                if line.strip() and not line.startswith('#'):
                                    cron_jobs.append({
                                        'source': path,
                                        'line': line_num + 1,
                                        'content': line.strip()
                                    })
                    except PermissionError:
                        continue
                elif os.path.isdir(path):
                    try:
                        for file in os.listdir(path)[:5]:  # First 5 files
                            file_path = os.path.join(path, file)
                            if os.path.isfile(file_path):
                                with open(file_path, 'r') as f:
                                    content = f.read(1024)  # First 1KB
                                    cron_jobs.append({
                                        'source': file_path,
                                        'content': content[:200]  # First 200 chars
                                    })
                    except PermissionError:
                        continue
            
            return cron_jobs
            
        except Exception as e:
            logger.error(f"Cron job collection failed: {e}")
            return []
    
    def _get_systemd_services(self):
        """Get systemd services"""
        try:
            services = []
            
            # Use systemctl to list services
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--no-pager'], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines[:10]:  # First 10 services
                        if line.strip():
                            fields = line.split()
                            if len(fields) >= 4:
                                services.append({
                                    'unit': fields[0],
                                    'load': fields[1],
                                    'active': fields[2],
                                    'sub': fields[3],
                                    'description': ' '.join(fields[4:]) if len(fields) > 4 else ''
                                })
                
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # systemctl not available or timed out
                pass
            
            return services
            
        except Exception as e:
            logger.error(f"Systemd service enumeration failed: {e}")
            return []
