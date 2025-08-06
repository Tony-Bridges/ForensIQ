import logging
from datetime import datetime
from adb_shell.adb_device import AdbDeviceUsb, AdbDeviceTcp
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from usb.core import find as usb_find
import os
import json

class DeviceAcquisition:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def detect_devices(self):
        """Detect connected mobile devices and systems."""
        from network_scanner import NetworkScanner
        
        scanner = NetworkScanner()
        network_devices = scanner.scan_network()
        
        devices = {
            'ios': self._detect_ios_devices(),
            'android': self._detect_android_devices(),
            'huawei': self._detect_huawei_devices(),
            'windows': self._detect_windows_systems(),
            'linux': self._detect_linux_systems(),
            'macos': self._detect_macos_systems(),
            'network': network_devices
        }
        return devices
    
    def _detect_ios_devices(self):
        """Detect connected iOS devices."""
        try:
            # Using libimobiledevice to detect iOS devices
            # This is a placeholder for actual implementation
            return []
        except Exception as e:
            self.logger.error(f"Error detecting iOS devices: {str(e)}")
            return []
    
    def _detect_android_devices(self):
        """Detect connected Android devices."""
        devices = []
        try:
            import subprocess
            
            # Use ADB to list devices
            try:
                result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip() and '\t' in line:
                            device_id, status = line.strip().split('\t')
                            devices.append({
                                'id': device_id,
                                'type': 'android',
                                'status': status,
                                'connection': 'adb'
                            })
                            
                            # Get additional device info
                            try:
                                model_result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.product.model'], 
                                                            capture_output=True, text=True, timeout=5)
                                if model_result.returncode == 0:
                                    devices[-1]['model'] = model_result.stdout.strip()
                                    
                                version_result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.build.version.release'], 
                                                              capture_output=True, text=True, timeout=5)
                                if version_result.returncode == 0:
                                    devices[-1]['android_version'] = version_result.stdout.strip()
                            except:
                                pass
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # ADB not available or timeout
                pass
            
            # Fallback to USB detection
            if not devices:
                try:
                    import usb.core
                    # Look for Android devices by vendor ID
                    android_vendors = [0x18d1, 0x04e8, 0x22b8, 0x0bb4, 0x12d1]  # Google, Samsung, Motorola, HTC, Huawei
                    
                    for vendor_id in android_vendors:
                        usb_devices = usb.core.find(find_all=True, idVendor=vendor_id)
                        for device in usb_devices:
                            devices.append({
                                'id': f'USB_{vendor_id:04x}_{device.idProduct:04x}',
                                'type': 'android',
                                'status': 'detected_usb',
                                'vendor_id': vendor_id,
                                'product_id': device.idProduct,
                                'connection': 'usb'
                            })
                except ImportError:
                    pass
                    
            if not devices:
                devices.append({
                    'id': 'No Android devices found',
                    'type': 'android',
                    'status': 'not_found',
                    'message': 'No Android devices detected. Enable USB debugging and connect device.'
                })
                
        except Exception as e:
            self.logger.error(f"Error detecting Android devices: {str(e)}")
            devices.append({
                'id': 'Detection failed',
                'type': 'android',
                'status': 'error',
                'error': str(e)
            })
            
        return devices
    
    def acquire_device_data(self, device_id, device_type, acquisition_type='logical'):
        """
        Acquire data from a mobile device.
        
        Args:
            device_id: Device identifier
            device_type: 'ios' or 'android'
            acquisition_type: 'logical' or 'physical'
            
        Returns:
            dict: Acquisition metadata and status
        """
        try:
            if device_type == 'ios':
                return self._acquire_ios_data(device_id, acquisition_type)
            elif device_type == 'android':
                return self._acquire_android_data(device_id, acquisition_type)
            elif device_type == 'linux':
                return self._acquire_linux_data(device_id, acquisition_type)
            else:
                raise ValueError(f"Unsupported device type: {device_type}")
        except Exception as e:
            self.logger.error(f"Error acquiring device data: {str(e)}")
            return {'error': str(e)}
    
    def _acquire_ios_data(self, device_id, acquisition_type):
        """Acquire data from iOS device."""
        # Placeholder for iOS acquisition implementation
        acquisition_data = {
            'device_id': device_id,
            'type': 'ios',
            'timestamp': datetime.utcnow().isoformat(),
            'acquisition_type': acquisition_type,
            'status': 'not_implemented'
        }
        return acquisition_data
    
    def _acquire_android_data(self, device_id, acquisition_type):
        """Acquire data from Android device."""
        try:
            device = AdbDeviceUsb()
            device.connect()
            
            # Get device info
            device_info = device.shell('getprop')
            
            # Get basic device data
            acquisition_data = {
                'device_id': device_id,
                'type': 'android',
                'timestamp': datetime.utcnow().isoformat(),
                'acquisition_type': acquisition_type,
                'device_info': device_info,
                'status': 'completed'
            }
            
            return acquisition_data
        except Exception as e:
            self.logger.error(f"Error acquiring Android data: {str(e)}")
            return {'error': str(e)}


    def _detect_huawei_devices(self):
        """Detect connected Huawei devices."""
        try:
            # Using Huawei Mobile Services (HMS) Core interface
            return []  # Placeholder for HMS implementation
        except Exception as e:
            self.logger.error(f"Error detecting Huawei devices: {str(e)}")
            return []

    def _detect_windows_systems(self):
        """Detect Windows systems."""
        try:
            # Using Windows Management Instrumentation (WMI)
            import wmi
            c = wmi.WMI()
            systems = [{'id': os.system_info.Name, 'type': 'windows'} 
                      for os in c.Win32_OperatingSystem()]
            return systems
        except Exception as e:
            self.logger.error(f"Error detecting Windows systems: {str(e)}")
            return []

    def _detect_linux_systems(self):
        """Detect Linux systems."""
        try:
            # Using system commands to get Linux info
            import platform
            if platform.system() == 'Linux':
                return [{'id': platform.node(), 'type': 'linux'}]
            return []
        except Exception as e:
            self.logger.error(f"Error detecting Linux systems: {str(e)}")
            return []

    def _detect_macos_systems(self):
        """Detect MacOS systems."""
        try:
            # Using system commands to get MacOS info
            import platform
            if platform.system() == 'Darwin':
                return [{'id': platform.node(), 'type': 'macos'}]
            return []
        except Exception as e:
            self.logger.error(f"Error detecting MacOS systems: {str(e)}")
            return []

    def _acquire_linux_data(self, device_id, acquisition_type):
        """Acquire data from Linux system."""
        try:
            import platform
            import subprocess
            import json
            
            # Basic system information
            system_info = {
                'hostname': platform.node(),
                'platform': platform.platform(),
                'distribution': platform.freedesktop_os_release() if hasattr(platform, 'freedesktop_os_release') else 'Unknown',
                'processor': platform.processor()
            }
            
            # System logs if logical acquisition
            if acquisition_type == 'logical':
                try:
                    logs = subprocess.check_output(['journalctl', '-n', '100']).decode()
                except:
                    logs = "Log acquisition failed or requires elevated privileges"
                system_info['system_logs'] = logs
            
            acquisition_data = {
                'device_id': device_id,
                'type': 'linux',
                'timestamp': datetime.utcnow().isoformat(),
                'acquisition_type': acquisition_type,
                'system_info': system_info,
                'status': 'completed'
            }
            
            return acquisition_data
        except Exception as e:
            self.logger.error(f"Error acquiring Linux data: {str(e)}")
            return {'error': str(e)}
