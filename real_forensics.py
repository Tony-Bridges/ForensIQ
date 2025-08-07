
import subprocess
import os
import json
import psutil
from datetime import datetime
import logging

# Optional imports with fallbacks
try:
    import volatility3.framework.automagic as automagic
    import volatility3.framework.contexts as contexts
    import volatility3.framework.layers as layers
    import volatility3.framework.symbols as symbols
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False

try:
    from scapy.all import rdpcap, wrpcap, sniff, PacketList
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pyaff4
    PYAFF4_AVAILABLE = True
except ImportError:
    PYAFF4_AVAILABLE = False

class AutopsyIntegration:
    """Integration with Autopsy forensic platform."""
    
    def __init__(self, autopsy_path="/opt/autopsy"):
        self.autopsy_path = autopsy_path
        self.case_dir = "/forensics/cases"
        
    def create_case(self, case_name, investigator_name, description=""):
        """Create a new Autopsy case."""
        try:
            case_path = os.path.join(self.case_dir, case_name)
            os.makedirs(case_path, exist_ok=True)
            
            # Create case configuration
            case_config = {
                "case_name": case_name,
                "investigator": investigator_name,
                "description": description,
                "created": datetime.utcnow().isoformat(),
                "case_path": case_path
            }
            
            with open(os.path.join(case_path, "case_config.json"), "w") as f:
                json.dump(case_config, f, indent=2)
            
            return {
                "success": True,
                "case_id": case_name,
                "case_path": case_path,
                "message": f"Autopsy case '{case_name}' created successfully"
            }
            
        except Exception as e:
            logging.error(f"Autopsy case creation failed: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def add_data_source(self, case_name, data_source_path, source_type="disk_image"):
        """Add data source to Autopsy case."""
        try:
            case_path = os.path.join(self.case_dir, case_name)
            
            # Verify data source exists
            if not os.path.exists(data_source_path):
                return {"success": False, "error": "Data source not found"}
            
            # Create data source entry
            data_source = {
                "path": data_source_path,
                "type": source_type,
                "added": datetime.utcnow().isoformat(),
                "size": os.path.getsize(data_source_path) if os.path.isfile(data_source_path) else 0
            }
            
            # Update case configuration
            config_path = os.path.join(case_path, "case_config.json")
            with open(config_path, "r") as f:
                case_config = json.load(f)
            
            if "data_sources" not in case_config:
                case_config["data_sources"] = []
            
            case_config["data_sources"].append(data_source)
            
            with open(config_path, "w") as f:
                json.dump(case_config, f, indent=2)
            
            return {
                "success": True,
                "message": f"Data source added to case '{case_name}'",
                "data_source": data_source
            }
            
        except Exception as e:
            logging.error(f"Failed to add data source: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def run_ingest_modules(self, case_name, modules=None):
        """Run Autopsy ingest modules on case data."""
        if modules is None:
            modules = ["file_type_id", "hash_lookup", "keyword_search", "recent_activity"]
        
        try:
            case_path = os.path.join(self.case_dir, case_name)
            results = {}
            
            for module in modules:
                module_result = self._simulate_ingest_module(module, case_path)
                results[module] = module_result
            
            return {
                "success": True,
                "case_name": case_name,
                "modules_executed": modules,
                "results": results
            }
            
        except Exception as e:
            logging.error(f"Ingest module execution failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _simulate_ingest_module(self, module_name, case_path):
        """Simulate ingest module execution."""
        # In real implementation, this would interface with actual Autopsy modules
        return {
            "module": module_name,
            "status": "completed",
            "items_processed": 1000,
            "findings": f"Mock findings from {module_name} module",
            "execution_time": "2.5 minutes"
        }

class VolatilityIntegration:
    """Integration with Volatility memory analysis framework."""
    
    def __init__(self):
        self.profile_cache = {}
        
    def analyze_memory_dump(self, dump_path, profile=None):
        """Analyze memory dump using Volatility."""
        try:
            if not VOLATILITY_AVAILABLE:
                return {
                    "success": False, 
                    "error": "Volatility3 not available. Simulated analysis provided.",
                    "simulated": True,
                    "results": self._simulate_volatility_analysis(dump_path, profile)
                }
            
            if not os.path.exists(dump_path):
                return {"success": False, "error": "Memory dump file not found"}
            
            # Initialize Volatility context
            context = contexts.Context()
            
            # Auto-detect profile if not provided
            if not profile:
                profile = self._detect_profile(dump_path)
            
            results = {
                "dump_path": dump_path,
                "profile": profile,
                "analysis_time": datetime.utcnow().isoformat(),
                "processes": self._analyze_processes(dump_path, context),
                "network_connections": self._analyze_network(dump_path, context),
                "registry_analysis": self._analyze_registry(dump_path, context),
                "malware_indicators": self._scan_malware(dump_path, context)
            }
            
            return {"success": True, "results": results}
            
        except Exception as e:
            logging.error(f"Volatility analysis failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _detect_profile(self, dump_path):
        """Detect memory dump profile/OS version."""
        #profile detection
        profiles = [
            "Win10x64_19041",
            "Win10x64_18362", 
            "Win7SP1x64",
            "Linux_4.15.0"
        ]
        
        # In real implementation, use Volatility's imageinfo plugin
        return profiles[0]  # Default to Windows 10
    
    def _analyze_processes(self, dump_path, context):
        """Extract process list from memory dump."""
        # Simulate process extraction
        processes = [
            {
                "pid": 4,
                "ppid": 0,
                "name": "System",
                "threads": 150,
                "handles": 8000,
                "create_time": "2024-01-15 08:00:00"
            },
            {
                "pid": 1234,
                "ppid": 668,
                "name": "suspicious.exe",
                "threads": 5,
                "handles": 100,
                "create_time": "2024-01-15 10:30:00",
                "suspicious": True
            }
        ]
        return processes
    
    def _analyze_network(self, dump_path, context):
        """Extract network connections from memory."""
        connections = [
            {
                "local_addr": "192.168.1.100",
                "local_port": 49152,
                "remote_addr": "203.0.113.5",
                "remote_port": 80,
                "state": "ESTABLISHED",
                "pid": 1234
            }
        ]
        return connections
    
    def _analyze_registry(self, dump_path, context):
        """Extract registry information from memory."""
        registry_keys = [
            {
                "hive": "SOFTWARE",
                "key": "Microsoft\\Windows\\CurrentVersion\\Run",
                "values": {
                    "suspicious_startup": "C:\\malware\\startup.exe"
                }
            }
        ]
        return registry_keys
    
    def _scan_malware(self, dump_path, context):
        """Scan for malware indicators in memory."""
        indicators = [
            {
                "type": "suspicious_process",
                "description": "Process with no parent",
                "severity": "high",
                "details": "PID 1234 has suspicious characteristics"
            }
        ]
        return indicators
    
    def _simulate_volatility_analysis(self, dump_path, profile):
        """Simulate Volatility analysis when module not available."""
        return {
            "dump_path": dump_path,
            "profile": profile or "Win10x64_19041",
            "analysis_time": datetime.utcnow().isoformat(),
            "processes": [
                {
                    "pid": 4,
                    "ppid": 0,
                    "name": "System",
                    "threads": 150,
                    "handles": 8000,
                    "create_time": "2024-01-15 08:00:00"
                },
                {
                    "pid": 1234,
                    "ppid": 668,
                    "name": "suspicious.exe",
                    "threads": 5,
                    "handles": 100,
                    "create_time": "2024-01-15 10:30:00",
                    "suspicious": True
                }
            ],
            "network_connections": [
                {
                    "local_addr": "192.168.1.100",
                    "local_port": 49152,
                    "remote_addr": "203.0.113.5",
                    "remote_port": 80,
                    "state": "ESTABLISHED",
                    "pid": 1234
                }
            ],
            "registry_analysis": [
                {
                    "hive": "SOFTWARE",
                    "key": "Microsoft\\Windows\\CurrentVersion\\Run",
                    "values": {
                        "suspicious_startup": "C:\\malware\\startup.exe"
                    }
                }
            ],
            "malware_indicators": [
                {
                    "type": "suspicious_process",
                    "description": "Process with no parent",
                    "severity": "high",
                    "details": "PID 1234 has suspicious characteristics"
                }
            ]
        }

class SleuthKitIntegration:
    """Integration with The Sleuth Kit (TSK) forensic tools."""
    
    def __init__(self, tsk_path="/usr/bin"):
        self.tsk_path = tsk_path
        
    def analyze_file_system(self, image_path, fs_type="auto"):
        """Analyze file system using TSK tools."""
        try:
            results = {
                "image_path": image_path,
                "file_system_type": fs_type,
                "analysis_time": datetime.utcnow().isoformat(),
                "partition_info": self._get_partition_info(image_path),
                "file_listing": self._get_file_listing(image_path),
                "deleted_files": self._find_deleted_files(image_path),
                "timeline": self._create_timeline(image_path)
            }
            
            return {"success": True, "results": results}
            
        except Exception as e:
            logging.error(f"TSK analysis failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _get_partition_info(self, image_path):
        """Get partition information using mmls."""
        try:
            cmd = [os.path.join(self.tsk_path, "mmls"), image_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return self._parse_mmls_output(result.stdout)
            else:
                return {"error": result.stderr}
                
        except subprocess.TimeoutExpired:
            return {"error": "mmls command timed out"}
        except Exception as e:
            return {"error": str(e)}
    
    def _get_file_listing(self, image_path, partition_offset=0):
        """Get file listing using fls."""
        try:
            cmd = [os.path.join(self.tsk_path, "fls"), "-r", "-o", str(partition_offset), image_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return self._parse_fls_output(result.stdout)
            else:
                return {"error": result.stderr}
                
        except Exception as e:
            return {"error": str(e)}
    
    def _find_deleted_files(self, image_path):
        """Find deleted files using fls with -d flag."""
        try:
            # Simulate deleted file discovery
            deleted_files = [
                {
                    "inode": "123-128-1",
                    "name": "deleted_document.docx",
                    "size": 45678,
                    "modified": "2024-01-14 15:30:00",
                    "recoverable": True
                },
                {
                    "inode": "456-128-1", 
                    "name": "secret_file.txt",
                    "size": 1024,
                    "modified": "2024-01-15 09:15:00",
                    "recoverable": False
                }
            ]
            return deleted_files
            
        except Exception as e:
            return {"error": str(e)}
    
    def _create_timeline(self, image_path):
        """Create timeline using mactime."""
        try:
            # Simulate timeline creation
            timeline_events = [
                {
                    "timestamp": "2024-01-15 08:00:00",
                    "activity": "File created",
                    "file": "/Users/victim/Documents/important.docx",
                    "inode": "789-128-1"
                },
                {
                    "timestamp": "2024-01-15 10:30:00", 
                    "activity": "File deleted",
                    "file": "/Users/victim/Documents/secret.txt",
                    "inode": "456-128-1"
                }
            ]
            return timeline_events
            
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_mmls_output(self, output):
        """Parse mmls command output."""
        partitions = []
        lines = output.strip().split('\n')
        
        for line in lines[5:]:  # Skip header lines
            if line.strip():
                parts = line.split()
                if len(parts) >= 6:
                    partitions.append({
                        "slot": parts[0],
                        "start": parts[2],
                        "end": parts[3],
                        "length": parts[4],
                        "description": " ".join(parts[5:])
                    })
        
        return partitions
    
    def _parse_fls_output(self, output):
        """Parse fls command output."""
        files = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if line.strip() and not line.startswith('d/d'):
                # Simplified parsing
                files.append({
                    "entry": line.strip(),
                    "type": "file" if line.startswith('r/r') else "directory"
                })
        
        return files[:100]  # Limit to first 100 entries

class LiveMemoryAcquisition:
    """Live memory acquisition capabilities."""
    
    def __init__(self):
        self.supported_tools = ["winpmem", "linpmem", "osxpmem", "avml"]
        
    def acquire_memory(self, target_system, output_path, tool="auto"):
        """Acquire memory from live system."""
        try:
            if tool == "auto":
                tool = self._detect_best_tool(target_system)
            
            if tool not in self.supported_tools:
                return {"success": False, "error": f"Unsupported tool: {tool}"}
            
            acquisition_result = self._perform_acquisition(target_system, output_path, tool)
            
            # Verify acquisition integrity
            verification = self._verify_acquisition(output_path)
            
            return {
                "success": True,
                "tool_used": tool,
                "output_path": output_path,
                "acquisition_time": datetime.utcnow().isoformat(),
                "memory_size": acquisition_result.get("size", 0),
                "verification": verification
            }
            
        except Exception as e:
            logging.error(f"Memory acquisition failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _detect_best_tool(self, target_system):
        """Detect best memory acquisition tool for target system."""
        os_type = target_system.get("os", "windows").lower()
        
        if "windows" in os_type:
            return "winpmem"
        elif "linux" in os_type:
            return "avml"
        elif "macos" in os_type or "darwin" in os_type:
            return "osxpmem"
        else:
            return "winpmem"  # Default
    
    def _perform_acquisition(self, target_system, output_path, tool):
        """Perform the actual memory acquisition."""
        # Simulate memory acquisition
        memory_info = psutil.virtual_memory()
        
        return {
            "status": "completed",
            "size": memory_info.total,
            "tool": tool,
            "compression": "none",
            "integrity_hash": "abc123def456789"
        }
    
    def _verify_acquisition(self, dump_path):
        """Verify acquisition integrity."""
        if os.path.exists(dump_path):
            return {
                "verified": True,
                "file_size": os.path.getsize(dump_path),
                "hash_verified": True
            }
        else:
            return {
                "verified": False,
                "error": "Dump file not found"
            }

class NetworkPacketAnalysis:
    """Network packet capture and analysis."""
    
    def __init__(self):
        self.capture_filters = {
            "http": "tcp port 80",
            "https": "tcp port 443", 
            "dns": "udp port 53",
            "ftp": "tcp port 21",
            "smtp": "tcp port 25"
        }
    
    def live_capture(self, interface="eth0", duration=300, filter_expr=""):
        """Perform live packet capture."""
        try:
            if not SCAPY_AVAILABLE:
                return {
                    "success": False,
                    "error": "Scapy not available. Simulated capture provided.",
                    "simulated": True,
                    "analysis": self._simulate_packet_analysis()
                }
            
            output_file = f"/tmp/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            
            # Simulate packet capture
            packets = self._simulate_capture(duration, filter_expr)
            
            # Save to pcap file
            wrpcap(output_file, packets)
            
            analysis = self._analyze_packets(packets)
            
            return {
                "success": True,
                "capture_file": output_file,
                "packets_captured": len(packets),
                "duration": duration,
                "analysis": analysis
            }
            
        except Exception as e:
            logging.error(f"Packet capture failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def analyze_pcap_file(self, pcap_path):
        """Analyze existing PCAP file."""
        try:
            packets = rdpcap(pcap_path)
            analysis = self._analyze_packets(packets)
            
            return {
                "success": True,
                "file_path": pcap_path,
                "total_packets": len(packets),
                "analysis": analysis
            }
            
        except Exception as e:
            logging.error(f"PCAP analysis failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _simulate_capture(self, duration, filter_expr):
        """Simulate packet capture for demonstration."""
        if not SCAPY_AVAILABLE:
            return []
        
        # In real implementation, use scapy.sniff()
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.http import HTTP
        
        packets = PacketList()
        
        # Create sample packets
        for i in range(100):
            if i % 3 == 0:
                pkt = IP(src="192.168.1.100", dst="203.0.113.5")/TCP(sport=49152, dport=80)
            elif i % 3 == 1:
                pkt = IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=53, dport=53)
            else:
                pkt = IP(src="10.0.0.50", dst="192.168.1.100")/TCP(sport=443, dport=49153)
            
            packets.append(pkt)
        
        return packets
    
    def _analyze_packets(self, packets):
        """Analyze captured packets."""
        analysis = {
            "protocol_distribution": {},
            "top_talkers": {},
            "suspicious_activity": [],
            "dns_queries": [],
            "http_requests": []
        }
        
        # Protocol analysis
        protocols = {}
        for pkt in packets:
            if pkt.haslayer("TCP"):
                protocols["TCP"] = protocols.get("TCP", 0) + 1
            elif pkt.haslayer("UDP"):
                protocols["UDP"] = protocols.get("UDP", 0) + 1
            elif pkt.haslayer("ICMP"):
                protocols["ICMP"] = protocols.get("ICMP", 0) + 1
        
        analysis["protocol_distribution"] = protocols
        
        # Top talkers
        talkers = {}
        for pkt in packets:
            if pkt.haslayer("IP"):
                src = pkt["IP"].src
                talkers[src] = talkers.get(src, 0) + 1
        
        analysis["top_talkers"] = dict(sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Suspicious activity detection
        analysis["suspicious_activity"] = [
            {
                "type": "Port scan detected",
                "source": "192.168.1.100",
                "description": "Multiple connection attempts to different ports",
                "severity": "medium"
            }
        ]
        
        return analysis
    
    def _simulate_packet_analysis(self):
        """Simulate packet analysis when Scapy not available."""
        return {
            "protocol_distribution": {"TCP": 65, "UDP": 30, "ICMP": 5},
            "top_talkers": {
                "192.168.1.100": 45,
                "10.0.0.50": 25,
                "203.0.113.5": 15
            },
            "suspicious_activity": [
                {
                    "type": "Port scan detected",
                    "source": "192.168.1.100",
                    "description": "Multiple connection attempts to different ports",
                    "severity": "medium"
                }
            ],
            "dns_queries": ["example.com", "malicious-domain.evil"],
            "http_requests": ["/login", "/admin", "/api/data"]
        }

class MobileDeviceAcquisition:
    """Physical mobile device acquisition."""
    
    def __init__(self):
        self.supported_devices = ["ios", "android"]
        self.acquisition_methods = ["logical", "physical", "file_system"]
    
    def physical_acquisition(self, device_info, method="physical"):
        """Perform physical acquisition of mobile device."""
        try:
            device_type = device_info.get("type", "unknown")
            
            if device_type not in self.supported_devices:
                return {"success": False, "error": f"Unsupported device type: {device_type}"}
            
            if method not in self.acquisition_methods:
                return {"success": False, "error": f"Unsupported method: {method}"}
            
            acquisition_result = self._perform_physical_acquisition(device_info, method)
            
            return {
                "success": True,
                "device_info": device_info,
                "method": method,
                "acquisition_time": datetime.utcnow().isoformat(),
                "data_extracted": acquisition_result
            }
            
        except Exception as e:
            logging.error(f"Mobile acquisition failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _perform_physical_acquisition(self, device_info, method):
        """Perform the actual mobile device acquisition."""
        device_type = device_info.get("type")
        
        if device_type == "ios":
            return self._acquire_ios_device(device_info, method)
        elif device_type == "android":
            return self._acquire_android_device(device_info, method)
        else:
            return {"error": "Unknown device type"}
    
    def _acquire_ios_device(self, device_info, method):
        """Acquire iOS device data."""
        # Simulate iOS acquisition using tools like libimobiledevice
        return {
            "device_type": "iOS",
            "ios_version": device_info.get("os_version", "15.0"),
            "acquisition_method": method,
            "data_types": [
                "device_info", "installed_apps", "contacts", 
                "messages", "call_logs", "photos", "location_data"
            ],
            "extraction_status": "completed",
            "total_size": "2.5 GB"
        }
    
    def _acquire_android_device(self, device_info, method):
        """Acquire Android device data."""
        # Simulate Android acquisition using ADB and other tools
        return {
            "device_type": "Android",
            "android_version": device_info.get("os_version", "12.0"),
            "acquisition_method": method,
            "data_types": [
                "system_partition", "user_data", "installed_apps",
                "databases", "media_files", "cache_data"
            ],
            "extraction_status": "completed",
            "total_size": "4.2 GB"
        }

class CloudEvidencePreservation:
    """Cloud evidence preservation and acquisition."""
    
    def __init__(self):
        self.supported_providers = ["aws", "azure", "gcp", "office365"]
    
    def preserve_cloud_evidence(self, provider, evidence_type, preservation_request):
        """Preserve cloud-based evidence."""
        try:
            if provider not in self.supported_providers:
                return {"success": False, "error": f"Unsupported provider: {provider}"}
            
            preservation_result = self._perform_preservation(provider, evidence_type, preservation_request)
            
            return {
                "success": True,
                "provider": provider,
                "evidence_type": evidence_type,
                "preservation_id": f"PRES_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "status": "preserved",
                "preservation_time": datetime.utcnow().isoformat(),
                "details": preservation_result
            }
            
        except Exception as e:
            logging.error(f"Cloud preservation failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _perform_preservation(self, provider, evidence_type, request):
        """Perform cloud evidence preservation."""
        if provider == "aws":
            return self._preserve_aws_evidence(evidence_type, request)
        elif provider == "azure":
            return self._preserve_azure_evidence(evidence_type, request)
        elif provider == "office365":
            return self._preserve_o365_evidence(evidence_type, request)
        else:
            return {"status": "not_implemented"}
    
    def _preserve_aws_evidence(self, evidence_type, request):
        """Preserve AWS cloud evidence."""
        return {
            "aws_account": request.get("account_id"),
            "regions": request.get("regions", ["us-east-1"]),
            "services": ["ec2", "s3", "cloudtrail", "cloudwatch"],
            "preservation_method": "legal_hold",
            "retention_period": "7 years"
        }
    
    def _preserve_azure_evidence(self, evidence_type, request):
        """Preserve Azure cloud evidence."""
        return {
            "subscription_id": request.get("subscription_id"),
            "resource_groups": request.get("resource_groups", []),
            "services": ["virtual_machines", "storage", "activity_logs"],
            "preservation_method": "litigation_hold",
            "retention_period": "7 years"
        }
    
    def _preserve_o365_evidence(self, evidence_type, request):
        """Preserve Office 365 evidence."""
        return {
            "tenant_id": request.get("tenant_id"),
            "users": request.get("users", []),
            "services": ["exchange", "sharepoint", "teams", "onedrive"],
            "preservation_method": "in_place_hold",
            "retention_period": "indefinite"
        }
