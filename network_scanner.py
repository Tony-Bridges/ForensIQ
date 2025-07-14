
import socket
import logging
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def scan_network(self, target_range='192.168.1'):
        """Scan network for active devices using basic socket connections."""
        try:
            self.logger.info(f"Starting network scan on range: {target_range}")
            devices = []
            
            # Scan common IP ranges first
            priority_ranges = [1, 100, 254] + list(range(1, 20))
            for i in priority_ranges:
                ip = f"{target_range}.{i}"
                try:
                    # Get hostname
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = 'Unknown'
                
                # Check if host is up
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    
                    # Try common ports
                    common_ports = [80, 443, 22, 21]
                    open_ports = []
                    services = {}
                    
                    for port in common_ports:
                        try:
                            result = sock.connect_ex((ip, port))
                            if result == 0:
                                open_ports.append(port)
                                services[port] = {
                                    'name': self._get_service_name(port),
                                    'state': 'open'
                                }
                        except:
                            continue
                    
                    if open_ports:  # Only add devices with open ports
                        device_info = {
                            'ip': ip,
                            'hostname': hostname,
                            'status': 'up',
                            'timestamp': datetime.utcnow().isoformat(),
                            'open_ports': open_ports,
                            'services': services
                        }
                        devices.append(device_info)
                        
                except socket.error:
                    continue
                finally:
                    sock.close()
            
            return devices
            
        except Exception as e:
            self.logger.error(f"Error during network scan: {str(e)}")
            return []
    
    def _get_service_name(self, port):
        """Return common service names for well-known ports."""
        services = {
            21: 'FTP',
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS'
        }
        return services.get(port, 'Unknown')
