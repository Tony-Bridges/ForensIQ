import socket
import logging
from datetime import datetime
import subprocess
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def scan_network(self, target_range="192.168.1.0/24"):
        """
        Scan network for active devices.

        Args:
            target_range: Network range to scan (CIDR notation)

        Returns:
            list: List of discovered devices
        """
        devices = []

        try:
            # Parse network range
            network = ipaddress.IPv4Network(target_range, strict=False)

            def ping_host(ip_str):
                """Ping a single host to check if it's alive."""
                try:
                    # Use ping command
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', ip_str], 
                                          capture_output=True, text=True, timeout=3)
                    return ip_str if result.returncode == 0 else None
                except:
                    return None

            def scan_host(ip_str):
                """Scan a single host for open ports and gather info."""
                device_info = {
                    'ip': ip_str,
                    'hostname': None,
                    'mac': None,
                    'ports': [],
                    'os': 'Unknown',
                    'device_type': 'Unknown',
                    'response_time': None
                }

                # Get hostname
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                    device_info['hostname'] = hostname
                except:
                    pass

                # Common ports to scan
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 135, 139, 445, 3389, 5900]

                open_ports = []
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((ip_str, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    except:
                        pass

                device_info['ports'] = open_ports

                # Try to determine OS and device type based on open ports
                if 135 in open_ports or 445 in open_ports or 3389 in open_ports:
                    device_info['os'] = 'Windows'
                    device_info['device_type'] = 'Windows Computer'
                elif 22 in open_ports and 80 not in open_ports:
                    device_info['os'] = 'Linux'
                    device_info['device_type'] = 'Linux Server'
                elif 22 in open_ports and 80 in open_ports:
                    device_info['device_type'] = 'Web Server'
                elif 80 in open_ports or 443 in open_ports:
                    device_info['device_type'] = 'Web Server/Router'

                # Try to get MAC address (only works for local network)
                try:
                    arp_result = subprocess.run(['arp', '-n', ip_str], 
                                              capture_output=True, text=True, timeout=2)
                    if arp_result.returncode == 0:
                        lines = arp_result.stdout.split('\n')
                        for line in lines:
                            if ip_str in line and ':' in line:
                                parts = line.split()
                                for part in parts:
                                    if ':' in part and len(part.replace(':', '')) == 12:
                                        device_info['mac'] = part
                                        break
                except:
                    pass

                return device_info

            # First, ping sweep to find live hosts
            live_hosts = []
            with ThreadPoolExecutor(max_workers=50) as executor:
                ping_futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in network.hosts()}

                for future in as_completed(ping_futures):
                    result = future.result()
                    if result:
                        live_hosts.append(result)

            # Then scan live hosts for ports and services
            if live_hosts:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    scan_futures = {executor.submit(scan_host, ip): ip for ip in live_hosts}

                    for future in as_completed(scan_futures):
                        device_info = future.result()
                        if device_info['ports'] or device_info['hostname']:  # Only add if we found something
                            devices.append(device_info)

            # Sort by IP address
            devices.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))

        except Exception as e:
            self.logger.error(f"Network scan failed: {str(e)}")
            devices.append({
                'ip': 'scan_failed',
                'error': str(e),
                'message': 'Network scan failed. Check permissions and network connectivity.'
            })

        return devices