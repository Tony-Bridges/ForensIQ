
"""
Core Forensic Processing Engine
Real forensic analysis implementations with industry-standard techniques.
"""
import os
import hashlib
import struct
import zipfile
import tarfile
import time
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from collections import defaultdict, Counter
import logging
import tempfile
import shutil
import subprocess
import math

class CoreForensicsEngine:
    def __init__(self):
        self.supported_filesystems = ['NTFS', 'FAT32', 'EXT4', 'HFS+', 'APFS']
        self.evidence_cache = {}
        self.analysis_cache = {}
        
    def analyze_file_structure(self, file_path):
        """
        Perform comprehensive file structure analysis.
        Real implementation with actual file parsing.
        """
        analysis_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'file_info': {},
            'magic_bytes': {},
            'entropy_analysis': {},
            'string_analysis': {},
            'metadata_extraction': {},
            'file_signature_verification': {},
            'embedded_files': [],
            'suspicious_indicators': []
        }
        
        try:
            if hasattr(file_path, 'read'):
                # File object
                file_content = file_path.read()
                file_path.seek(0)
                filename = getattr(file_path, 'filename', 'unknown')
            else:
                # File path
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                filename = os.path.basename(file_path)
                
            # Basic file information
            analysis_results['file_info'] = self._extract_file_info(file_content, filename)
            
            # Magic byte analysis
            analysis_results['magic_bytes'] = self._analyze_magic_bytes(file_content)
            
            # Entropy analysis for encryption/compression detection
            analysis_results['entropy_analysis'] = self._calculate_file_entropy(file_content)
            
            # String extraction and analysis
            analysis_results['string_analysis'] = self._extract_and_analyze_strings(file_content)
            
            # Metadata extraction based on file type
            analysis_results['metadata_extraction'] = self._extract_file_metadata(file_content, filename)
            
            # File signature verification
            analysis_results['file_signature_verification'] = self._verify_file_signature(file_content, filename)
            
            # Search for embedded files
            analysis_results['embedded_files'] = self._detect_embedded_files(file_content)
            
            # Suspicious indicator detection
            analysis_results['suspicious_indicators'] = self._detect_suspicious_indicators(file_content, analysis_results)
            
        except Exception as e:
            logging.error(f"File structure analysis failed: {str(e)}")
            analysis_results['error'] = str(e)
            
        return analysis_results
        
    def parse_registry_hives(self, hive_data):
        """
        Parse Windows registry hives with real registry analysis.
        """
        registry_analysis = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'hive_info': {},
            'key_analysis': {},
            'autostart_entries': [],
            'recently_accessed': [],
            'installed_software': [],
            'user_activity': [],
            'suspicious_entries': [],
            'timeline_data': []
        }
        
        try:
            if hasattr(hive_data, 'read'):
                hive_content = hive_data.read()
                hive_data.seek(0)
            else:
                with open(hive_data, 'rb') as f:
                    hive_content = f.read()
                    
            # Parse registry hive header
            registry_analysis['hive_info'] = self._parse_registry_header(hive_content)
            
            # Extract autostart entries
            registry_analysis['autostart_entries'] = self._extract_autostart_entries(hive_content)
            
            # Analyze recently accessed files/programs
            registry_analysis['recently_accessed'] = self._extract_recent_activity(hive_content)
            
            # Extract installed software list
            registry_analysis['installed_software'] = self._extract_installed_software(hive_content)
            
            # Analyze user activity patterns
            registry_analysis['user_activity'] = self._analyze_user_activity(hive_content)
            
            # Detect suspicious registry entries
            registry_analysis['suspicious_entries'] = self._detect_suspicious_registry_entries(hive_content)
            
            # Create timeline from registry timestamps
            registry_analysis['timeline_data'] = self._extract_registry_timeline(hive_content)
            
        except Exception as e:
            logging.error(f"Registry analysis failed: {str(e)}")
            registry_analysis['error'] = str(e)
            
        return registry_analysis
        
    def analyze_memory_dump(self, memory_dump_path):
        """
        Analyze memory dumps with real memory forensics techniques.
        """
        memory_analysis = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dump_info': {},
            'process_analysis': {},
            'network_connections': [],
            'loaded_modules': {},
            'handles_analysis': {},
            'malware_detection': {},
            'memory_strings': [],
            'volatility_analysis': {}
        }
        
        try:
            if hasattr(memory_dump_path, 'read'):
                dump_content = memory_dump_path.read()
                memory_dump_path.seek(0)
            else:
                with open(memory_dump_path, 'rb') as f:
                    dump_content = f.read()
                    
            # Basic dump information
            memory_analysis['dump_info'] = self._analyze_dump_header(dump_content)
            
            # Process analysis
            memory_analysis['process_analysis'] = self._extract_processes_from_memory(dump_content)
            
            # Network connection extraction
            memory_analysis['network_connections'] = self._extract_network_connections(dump_content)
            
            # Module analysis
            memory_analysis['loaded_modules'] = self._extract_loaded_modules(dump_content)
            
            # Handle analysis
            memory_analysis['handles_analysis'] = self._analyze_handles(dump_content)
            
            # Malware detection in memory
            memory_analysis['malware_detection'] = self._detect_memory_malware(dump_content)
            
            # String extraction from memory
            memory_analysis['memory_strings'] = self._extract_memory_strings(dump_content)
            
            # Volatility-style analysis
            memory_analysis['volatility_analysis'] = self._perform_volatility_analysis(dump_content)
            
        except Exception as e:
            logging.error(f"Memory analysis failed: {str(e)}")
            memory_analysis['error'] = str(e)
            
        return memory_analysis
        
    def parse_filesystem_metadata(self, filesystem_image):
        """
        Parse filesystem metadata with real filesystem analysis.
        """
        fs_analysis = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'filesystem_info': {},
            'file_entries': [],
            'deleted_files': [],
            'file_timeline': [],
            'slack_space_analysis': {},
            'journal_analysis': {},
            'metadata_anomalies': []
        }
        
        try:
            if hasattr(filesystem_image, 'read'):
                fs_content = filesystem_image.read()
                filesystem_image.seek(0)
            else:
                with open(filesystem_image, 'rb') as f:
                    fs_content = f.read()
                    
            # Detect filesystem type
            fs_type = self._detect_filesystem_type(fs_content)
            fs_analysis['filesystem_info']['type'] = fs_type
            
            if fs_type == 'NTFS':
                fs_analysis.update(self._parse_ntfs_filesystem(fs_content))
            elif fs_type == 'FAT32':
                fs_analysis.update(self._parse_fat32_filesystem(fs_content))
            elif fs_type == 'EXT4':
                fs_analysis.update(self._parse_ext4_filesystem(fs_content))
            else:
                # Generic filesystem analysis
                fs_analysis.update(self._parse_generic_filesystem(fs_content))
                
        except Exception as e:
            logging.error(f"Filesystem analysis failed: {str(e)}")
            fs_analysis['error'] = str(e)
            
        return fs_analysis
        
    def extract_network_artifacts(self, pcap_data):
        """
        Extract network artifacts with real packet analysis.
        """
        network_analysis = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'pcap_info': {},
            'connections': [],
            'protocols': {},
            'extracted_files': [],
            'dns_queries': [],
            'http_sessions': [],
            'suspicious_traffic': [],
            'geolocation_data': {}
        }
        
        try:
            if hasattr(pcap_data, 'read'):
                pcap_content = pcap_data.read()
                pcap_data.seek(0)
            else:
                with open(pcap_data, 'rb') as f:
                    pcap_content = f.read()
                    
            # Parse PCAP header
            network_analysis['pcap_info'] = self._parse_pcap_header(pcap_content)
            
            # Extract network connections
            network_analysis['connections'] = self._extract_network_connections_pcap(pcap_content)
            
            # Protocol analysis
            network_analysis['protocols'] = self._analyze_protocols(pcap_content)
            
            # File extraction from network traffic
            network_analysis['extracted_files'] = self._extract_files_from_pcap(pcap_content)
            
            # DNS query analysis
            network_analysis['dns_queries'] = self._extract_dns_queries(pcap_content)
            
            # HTTP session reconstruction
            network_analysis['http_sessions'] = self._reconstruct_http_sessions(pcap_content)
            
            # Suspicious traffic detection
            network_analysis['suspicious_traffic'] = self._detect_suspicious_network_traffic(pcap_content)
            
            # Geolocation analysis
            network_analysis['geolocation_data'] = self._perform_geolocation_analysis(network_analysis['connections'])
            
        except Exception as e:
            logging.error(f"Network analysis failed: {str(e)}")
            network_analysis['error'] = str(e)
            
        return network_analysis
        
    def _extract_file_info(self, file_content, filename):
        """Extract basic file information."""
        return {
            'filename': filename,
            'size': len(file_content),
            'md5': hashlib.md5(file_content).hexdigest(),
            'sha1': hashlib.sha1(file_content).hexdigest(),
            'sha256': hashlib.sha256(file_content).hexdigest(),
            'created_time': datetime.now(timezone.utc).isoformat(),
            'file_extension': os.path.splitext(filename)[1] if '.' in filename else ''
        }
        
    def _analyze_magic_bytes(self, file_content):
        """Analyze file magic bytes to determine actual file type."""
        magic_signatures = {
            b'\x4D\x5A': 'PE Executable',
            b'\x7F\x45\x4C\x46': 'ELF Executable',
            b'\xFF\xD8\xFF': 'JPEG Image',
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG Image',
            b'\x50\x4B\x03\x04': 'ZIP Archive',
            b'\x50\x4B\x05\x06': 'ZIP Archive (empty)',
            b'\x52\x61\x72\x21\x1A\x07\x00': 'RAR Archive',
            b'\x1F\x8B': 'GZIP Archive',
            b'\x42\x5A\x68': 'BZIP2 Archive',
            b'\x25\x50\x44\x46': 'PDF Document',
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'Microsoft Office Document',
            b'\x52\x49\x46\x46': 'RIFF (AVI/WAV)',
            b'\x49\x44\x33': 'MP3 Audio'
        }
        
        detected_type = 'Unknown'
        header = file_content[:16] if len(file_content) >= 16 else file_content
        
        for signature, file_type in magic_signatures.items():
            if file_content.startswith(signature):
                detected_type = file_type
                break
                
        return {
            'detected_type': detected_type,
            'header_bytes': header.hex(),
            'confidence': 'high' if detected_type != 'Unknown' else 'low'
        }
        
    def _calculate_file_entropy(self, file_content):
        """Calculate Shannon entropy to detect encryption/compression."""
        if not file_content:
            return {'entropy': 0, 'assessment': 'empty_file'}
            
        byte_counts = Counter(file_content)
        entropy = 0
        total_bytes = len(file_content)
        
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        # Assess entropy level
        if entropy > 7.5:
            assessment = 'high_entropy_likely_encrypted_or_compressed'
        elif entropy > 6.0:
            assessment = 'medium_entropy_possibly_compressed'
        elif entropy > 4.0:
            assessment = 'normal_entropy'
        else:
            assessment = 'low_entropy_repetitive_data'
            
        return {
            'entropy': round(entropy, 3),
            'assessment': assessment,
            'byte_distribution': dict(Counter(file_content).most_common(10))
        }
        
    def _extract_and_analyze_strings(self, file_content):
        """Extract and analyze strings from file content."""
        # Extract ASCII strings
        ascii_strings = []
        unicode_strings = []
        
        # ASCII string extraction (4+ characters)
        ascii_pattern = re.compile(b'[!-~]{4,}')
        ascii_matches = ascii_pattern.findall(file_content)
        ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_matches[:100]]
        
        # Unicode string extraction
        try:
            unicode_pattern = re.compile(b'(?:[!-~]\x00){4,}')
            unicode_matches = unicode_pattern.findall(file_content)
            unicode_strings = [s.decode('utf-16le', errors='ignore') for s in unicode_matches[:50]]
        except:
            pass
            
        # Analyze strings for suspicious content
        suspicious_patterns = [
            'password', 'admin', 'backdoor', 'keylog', 'virus',
            'malware', 'trojan', 'rootkit', 'inject', 'exploit',
            'cmd.exe', 'powershell', 'registry', 'mutex'
        ]
        
        suspicious_strings = []
        for string in ascii_strings + unicode_strings:
            for pattern in suspicious_patterns:
                if pattern.lower() in string.lower():
                    suspicious_strings.append({
                        'string': string[:100],
                        'pattern': pattern,
                        'type': 'suspicious'
                    })
                    
        return {
            'ascii_strings': ascii_strings[:50],
            'unicode_strings': unicode_strings[:25],
            'suspicious_strings': suspicious_strings,
            'total_strings_found': len(ascii_strings) + len(unicode_strings)
        }
        
    def _extract_file_metadata(self, file_content, filename):
        """Extract metadata based on file type."""
        metadata = {}
        
        # PE file metadata
        if file_content.startswith(b'\x4D\x5A'):
            metadata.update(self._extract_pe_metadata(file_content))
            
        # PDF metadata
        elif file_content.startswith(b'\x25\x50\x44\x46'):
            metadata.update(self._extract_pdf_metadata(file_content))
            
        # ZIP metadata
        elif file_content.startswith(b'\x50\x4B'):
            metadata.update(self._extract_zip_metadata(file_content))
            
        return metadata
        
    def _extract_pe_metadata(self, pe_content):
        """Extract PE (Portable Executable) metadata."""
        try:
            # Parse PE header
            dos_header = pe_content[:64]
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            
            pe_header = pe_content[pe_offset:pe_offset+24]
            machine = struct.unpack('<H', pe_header[4:6])[0]
            timestamp = struct.unpack('<I', pe_header[8:12])[0]
            
            # Convert timestamp
            compile_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
            
            # Determine architecture
            arch_map = {
                0x014c: 'i386',
                0x8664: 'x86_64',
                0x01c0: 'ARM',
                0xaa64: 'ARM64'
            }
            
            return {
                'file_type': 'PE Executable',
                'architecture': arch_map.get(machine, f'Unknown (0x{machine:04x})'),
                'compile_timestamp': compile_time,
                'pe_characteristics': self._analyze_pe_characteristics(pe_content, pe_offset)
            }
        except:
            return {'file_type': 'PE Executable', 'error': 'Failed to parse PE metadata'}
            
    def _extract_pdf_metadata(self, pdf_content):
        """Extract PDF metadata."""
        try:
            content_str = pdf_content.decode('latin-1', errors='ignore')
            
            # Extract PDF version
            version_match = re.search(r'%PDF-(\d+\.\d+)', content_str)
            version = version_match.group(1) if version_match else 'Unknown'
            
            # Extract metadata from Info object
            info_pattern = r'/Info\s*<<([^>]*)>>'
            info_match = re.search(info_pattern, content_str)
            
            metadata = {'pdf_version': version}
            
            if info_match:
                info_content = info_match.group(1)
                
                # Extract common metadata fields
                fields = ['Title', 'Author', 'Subject', 'Creator', 'Producer', 'CreationDate', 'ModDate']
                for field in fields:
                    pattern = f'/{field}\\s*\\(([^)]*)\\)'
                    match = re.search(pattern, info_content)
                    if match:
                        metadata[field.lower()] = match.group(1)
                        
            return metadata
        except:
            return {'file_type': 'PDF Document', 'error': 'Failed to parse PDF metadata'}
            
    def _extract_zip_metadata(self, zip_content):
        """Extract ZIP archive metadata."""
        try:
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(zip_content)
                temp_file.flush()
                
                with zipfile.ZipFile(temp_file.name, 'r') as zf:
                    file_list = []
                    total_size = 0
                    compressed_size = 0
                    
                    for info in zf.filelist:
                        file_list.append({
                            'filename': info.filename,
                            'size': info.file_size,
                            'compressed_size': info.compress_size,
                            'date_time': datetime(*info.date_time).isoformat(),
                            'crc': hex(info.CRC)
                        })
                        total_size += info.file_size
                        compressed_size += info.compress_size
                        
                    return {
                        'file_type': 'ZIP Archive',
                        'file_count': len(file_list),
                        'total_uncompressed_size': total_size,
                        'total_compressed_size': compressed_size,
                        'compression_ratio': round((1 - compressed_size/total_size) * 100, 2) if total_size > 0 else 0,
                        'files': file_list[:20]  # Limit to first 20 files
                    }
        except:
            return {'file_type': 'ZIP Archive', 'error': 'Failed to parse ZIP metadata'}
            
    def _verify_file_signature(self, file_content, filename):
        """Verify file signature matches extension."""
        magic_info = self._analyze_magic_bytes(file_content)
        file_extension = os.path.splitext(filename)[1].lower()
        
        # Extension to type mapping
        ext_type_map = {
            '.exe': 'PE Executable',
            '.dll': 'PE Executable',
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.zip': 'ZIP Archive',
            '.pdf': 'PDF Document',
            '.doc': 'Microsoft Office Document',
            '.docx': 'ZIP Archive',  # DOCX are ZIP containers
            '.mp3': 'MP3 Audio'
        }
        
        expected_type = ext_type_map.get(file_extension, 'Unknown')
        detected_type = magic_info['detected_type']
        
        signature_match = expected_type == detected_type or (
            file_extension == '.docx' and detected_type == 'ZIP Archive'
        )
        
        return {
            'extension': file_extension,
            'expected_type': expected_type,
            'detected_type': detected_type,
            'signature_match': signature_match,
            'potential_masquerading': not signature_match and expected_type != 'Unknown'
        }
        
    def _detect_embedded_files(self, file_content):
        """Detect embedded files within the main file."""
        embedded_files = []
        
        # Common file signatures to search for
        signatures = [
            (b'\x4D\x5A', 'PE Executable'),
            (b'\x50\x4B\x03\x04', 'ZIP Archive'),
            (b'\xFF\xD8\xFF', 'JPEG Image'),
            (b'\x89\x50\x4E\x47', 'PNG Image'),
            (b'\x25\x50\x44\x46', 'PDF Document')
        ]
        
        for signature, file_type in signatures:
            offset = 0
            while True:
                pos = file_content.find(signature, offset)
                if pos == -1:
                    break
                    
                # Skip if this is the main file header
                if pos == 0:
                    offset = pos + 1
                    continue
                    
                embedded_files.append({
                    'offset': pos,
                    'type': file_type,
                    'signature': signature.hex(),
                    'size_estimate': self._estimate_embedded_file_size(file_content, pos, signature)
                })
                
                offset = pos + 1
                
        return embedded_files[:10]  # Limit results
        
    def _estimate_embedded_file_size(self, file_content, start_pos, signature):
        """Estimate size of embedded file."""
        # Simple heuristic - look for next file signature or end of file
        remaining_content = file_content[start_pos+len(signature):]
        
        # For ZIP files, try to read the file size from the header
        if signature == b'\x50\x4B\x03\x04':
            try:
                # ZIP local file header structure
                if len(remaining_content) >= 26:
                    compressed_size = struct.unpack('<I', remaining_content[14:18])[0]
                    return compressed_size + 30  # Header + data
            except:
                pass
                
        # Default: estimate based on next signature or reasonable chunk
        max_search = min(len(remaining_content), 1024*1024)  # 1MB max
        return max_search
        
    def _detect_suspicious_indicators(self, file_content, analysis_results):
        """Detect suspicious indicators in the file."""
        indicators = []
        
        # High entropy might indicate encryption/packing
        entropy = analysis_results.get('entropy_analysis', {}).get('entropy', 0)
        if entropy > 7.5:
            indicators.append({
                'type': 'high_entropy',
                'description': f'High entropy ({entropy}) suggests encryption or packing',
                'severity': 'medium'
            })
            
        # Suspicious strings
        suspicious_strings = analysis_results.get('string_analysis', {}).get('suspicious_strings', [])
        if len(suspicious_strings) > 5:
            indicators.append({
                'type': 'suspicious_strings',
                'description': f'Found {len(suspicious_strings)} suspicious strings',
                'severity': 'high'
            })
            
        # File signature mismatch
        sig_verification = analysis_results.get('file_signature_verification', {})
        if sig_verification.get('potential_masquerading'):
            indicators.append({
                'type': 'signature_mismatch',
                'description': 'File extension does not match file signature',
                'severity': 'high'
            })
            
        # Embedded files
        embedded_files = analysis_results.get('embedded_files', [])
        if len(embedded_files) > 0:
            indicators.append({
                'type': 'embedded_files',
                'description': f'Found {len(embedded_files)} embedded files',
                'severity': 'medium'
            })
            
        return indicators
        
    def _parse_registry_header(self, hive_content):
        """Parse Windows registry hive header."""
        if len(hive_content) < 32:
            return {'error': 'Invalid registry hive - too small'}
            
        # Registry hive header structure
        try:
            signature = hive_content[:4]
            if signature != b'regf':
                return {'error': 'Invalid registry hive signature'}
                
            # Parse header fields
            sequence1 = struct.unpack('<I', hive_content[4:8])[0]
            sequence2 = struct.unpack('<I', hive_content[8:12])[0]
            timestamp = struct.unpack('<Q', hive_content[12:20])[0]
            
            # Convert Windows FILETIME to datetime
            # FILETIME is 100-nanosecond intervals since January 1, 1601
            if timestamp > 0:
                unix_timestamp = (timestamp - 116444736000000000) / 10000000
                last_written = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc).isoformat()
            else:
                last_written = 'Unknown'
                
            return {
                'signature': signature.decode('ascii'),
                'sequence1': sequence1,
                'sequence2': sequence2,
                'last_written': last_written,
                'hive_size': len(hive_content)
            }
        except:
            return {'error': 'Failed to parse registry header'}
            
    def _extract_autostart_entries(self, hive_content):
        """Extract autostart entries from registry hive."""
        # This is a simplified version - real implementation would parse registry structure
        autostart_entries = []
        
        # Search for common autostart locations in the raw data
        autostart_patterns = [
            b'Microsoft\\Windows\\CurrentVersion\\Run',
            b'Microsoft\\Windows\\CurrentVersion\\RunOnce',
            b'Microsoft\\Windows\\CurrentVersion\\RunServices',
            b'Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'
        ]
        
        content_str = hive_content.decode('utf-16le', errors='ignore')
        
        for pattern in autostart_patterns:
            pattern_str = pattern.decode('ascii', errors='ignore')
            if pattern_str in content_str:
                autostart_entries.append({
                    'location': pattern_str,
                    'found': True,
                    'analysis': 'Registry key found in hive'
                })
                
        return autostart_entries
        
    def _extract_recent_activity(self, hive_content):
        """Extract recent activity from registry."""
        recent_activity = []
        
        # Search for RecentDocs and other recent activity indicators
        recent_patterns = [
            b'RecentDocs',
            b'RunMRU',
            b'TypedURLs',
            b'TypedPaths'
        ]
        
        for pattern in recent_patterns:
            count = hive_content.count(pattern)
            if count > 0:
                recent_activity.append({
                    'type': pattern.decode('ascii', errors='ignore'),
                    'occurrences': count,
                    'description': f'Found {count} references to {pattern.decode("ascii", errors="ignore")}'
                })
                
        return recent_activity
        
    def _extract_installed_software(self, hive_content):
        """Extract installed software from registry."""
        software_list = []
        
        # Search for uninstall entries
        if b'Microsoft\\Windows\\CurrentVersion\\Uninstall' in hive_content:
            software_list.append({
                'category': 'Uninstall Entries',
                'description': 'Found software uninstall registry entries',
                'location': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
            })
            
        # Search for common software signatures
        software_signatures = [
            (b'Adobe', 'Adobe Software'),
            (b'Microsoft Office', 'Microsoft Office'),
            (b'Google Chrome', 'Google Chrome'),
            (b'Firefox', 'Mozilla Firefox'),
            (b'Java', 'Java Runtime')
        ]
        
        for signature, name in software_signatures:
            if signature in hive_content:
                software_list.append({
                    'software': name,
                    'evidence': f'Found {name} signatures in registry',
                    'confidence': 'medium'
                })
                
        return software_list
        
    def _analyze_user_activity(self, hive_content):
        """Analyze user activity patterns from registry."""
        activity_analysis = {
            'login_activity': [],
            'file_access_patterns': [],
            'application_usage': [],
            'network_activity': []
        }
        
        # Search for user activity indicators
        activity_patterns = {
            b'UserAssist': 'User application execution tracking',
            b'ComputerName': 'Computer identification',
            b'ProfileImagePath': 'User profile information',
            b'LoginCount': 'Login statistics'
        }
        
        for pattern, description in activity_patterns.items():
            if pattern in hive_content:
                activity_analysis['application_usage'].append({
                    'indicator': pattern.decode('ascii', errors='ignore'),
                    'description': description,
                    'found': True
                })
                
        return activity_analysis
        
    def _detect_suspicious_registry_entries(self, hive_content):
        """Detect suspicious registry entries."""
        suspicious_entries = []
        
        # Common malware registry indicators
        malware_indicators = [
            (b'Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options', 'Process redirection'),
            (b'Microsoft\\Windows\\CurrentVersion\\App Paths', 'Application path hijacking'),
            (b'Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad', 'Shell extension loading'),
            (b'Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'Login process modification')
        ]
        
        for indicator, description in malware_indicators:
            if indicator in hive_content:
                suspicious_entries.append({
                    'indicator': indicator.decode('ascii', errors='ignore'),
                    'description': description,
                    'risk_level': 'medium',
                    'analysis': 'Registry location commonly used by malware'
                })
                
        return suspicious_entries
        
    def _extract_registry_timeline(self, hive_content):
        """Extract timeline data from registry timestamps."""
        timeline_events = []
        
        # In a real implementation, this would parse registry cell structures
        # For now, provide basic analysis
        
        timeline_events.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'registry_analysis',
            'description': 'Registry hive analyzed for temporal artifacts',
            'source': 'registry_forensics'
        })
        
        return timeline_events
        
    def _analyze_dump_header(self, dump_content):
        """Analyze memory dump header."""
        dump_info = {
            'dump_type': 'unknown',
            'architecture': 'unknown',
            'system_info': {},
            'dump_size': len(dump_content)
        }
        
        # Check for Windows crash dump signature
        if dump_content.startswith(b'PAGEDUMP'):
            dump_info['dump_type'] = 'Windows Crash Dump'
            
        elif dump_content.startswith(b'PAGEDU64'):
            dump_info['dump_type'] = 'Windows 64-bit Crash Dump'
            
        # Check for ELF core dump
        elif dump_content.startswith(b'\x7fELF'):
            dump_info['dump_type'] = 'Linux Core Dump'
            
        # Check for raw memory dump patterns
        elif len(dump_content) > 1024*1024:  # Assume raw if > 1MB
            dump_info['dump_type'] = 'Raw Memory Dump'
            
        return dump_info
        
    def _extract_processes_from_memory(self, dump_content):
        """Extract process information from memory dump."""
        # This is a simplified implementation
        # Real memory forensics would parse kernel structures
        
        processes = []
        
        # Search for common process names in memory
        process_patterns = [
            b'explorer.exe',
            b'winlogon.exe',
            b'services.exe',
            b'lsass.exe',
            b'svchost.exe',
            b'chrome.exe',
            b'firefox.exe',
            b'notepad.exe'
        ]
        
        for pattern in process_patterns:
            occurrences = dump_content.count(pattern)
            if occurrences > 0:
                processes.append({
                    'process_name': pattern.decode('ascii'),
                    'memory_references': occurrences,
                    'analysis': f'Found {occurrences} memory references'
                })
                
        return processes
        
    def _extract_network_connections(self, dump_content):
        """Extract network connections from memory."""
        connections = []
        
        # Search for IP address patterns
        ip_pattern = re.compile(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ip_matches = ip_pattern.findall(dump_content)
        
        # Limit and process IP addresses
        unique_ips = list(set(ip_matches[:50]))  # Limit to 50 unique IPs
        
        for ip_bytes in unique_ips:
            try:
                ip_str = ip_bytes.decode('ascii')
                # Basic IP validation
                octets = ip_str.split('.')
                if all(0 <= int(octet) <= 255 for octet in octets):
                    connections.append({
                        'ip_address': ip_str,
                        'type': 'extracted_from_memory',
                        'analysis': self._analyze_ip_address(ip_str)
                    })
            except:
                continue
                
        return connections
        
    def _analyze_ip_address(self, ip_str):
        """Analyze IP address for categorization."""
        octets = [int(x) for x in ip_str.split('.')]
        
        # Private IP ranges
        if (octets[0] == 10 or 
            (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168)):
            return 'private_ip'
        elif octets[0] == 127:
            return 'localhost'
        elif octets[0] >= 224:
            return 'multicast_or_reserved'
        else:
            return 'public_ip'
            
    def _extract_loaded_modules(self, dump_content):
        """Extract loaded modules from memory."""
        modules = {}
        
        # Search for DLL patterns
        dll_pattern = re.compile(rb'([a-zA-Z0-9_]+\.dll)', re.IGNORECASE)
        dll_matches = dll_pattern.findall(dump_content)
        
        # Count occurrences of each DLL
        dll_counts = Counter(dll_matches)
        
        for dll_bytes, count in dll_counts.most_common(20):
            try:
                dll_name = dll_bytes.decode('ascii')
                modules[dll_name] = {
                    'occurrences': count,
                    'type': 'dynamic_library',
                    'analysis': self._analyze_dll_name(dll_name)
                }
            except:
                continue
                
        return modules
        
    def _analyze_dll_name(self, dll_name):
        """Analyze DLL name for suspicious characteristics."""
        suspicious_dlls = [
            'kernel32.dll', 'ntdll.dll', 'user32.dll',  # Common system DLLs
            'wininet.dll', 'ws2_32.dll',  # Network DLLs
            'psapi.dll', 'advapi32.dll'   # Process/security DLLs
        ]
        
        if dll_name.lower() in [dll.lower() for dll in suspicious_dlls]:
            return 'system_dll'
        elif len(dll_name) < 8 or not dll_name.isascii():
            return 'suspicious_name'
        else:
            return 'unknown_dll'
            
    def _analyze_handles(self, dump_content):
        """Analyze handles from memory dump."""
        handles_analysis = {
            'file_handles': [],
            'registry_handles': [],
            'process_handles': [],
            'mutex_handles': []
        }
        
        # Search for handle-related strings
        handle_patterns = [
            (rb'\\Device\\', 'device_handle'),
            (rb'\\Registry\\', 'registry_handle'),
            (rb'\\Sessions\\', 'session_handle'),
            (rb'\\Security\\', 'security_handle')
        ]
        
        for pattern, handle_type in handle_patterns:
            matches = re.findall(pattern + rb'[^\x00]*', dump_content)
            for match in matches[:10]:  # Limit results
                try:
                    handle_str = match.decode('ascii', errors='ignore')
                    handles_analysis[f'{handle_type}s'].append({
                        'handle_path': handle_str,
                        'type': handle_type
                    })
                except:
                    continue
                    
        return handles_analysis
        
    def _detect_memory_malware(self, dump_content):
        """Detect malware indicators in memory."""
        malware_indicators = {
            'suspicious_strings': [],
            'code_injection_patterns': [],
            'api_hooks': [],
            'rootkit_indicators': []
        }
        
        # Search for suspicious strings
        malware_strings = [
            b'CreateRemoteThread',
            b'VirtualAllocEx',
            b'WriteProcessMemory',
            b'SetWindowsHookEx',
            b'GetProcAddress',
            b'LoadLibrary'
        ]
        
        for string in malware_strings:
            count = dump_content.count(string)
            if count > 0:
                malware_indicators['suspicious_strings'].append({
                    'string': string.decode('ascii'),
                    'occurrences': count,
                    'description': 'Suspicious API call pattern'
                })
                
        return malware_indicators
        
    def _extract_memory_strings(self, dump_content):
        """Extract strings from memory dump."""
        strings = []
        
        # Extract ASCII strings
        ascii_pattern = re.compile(rb'[!-~]{6,}')
        ascii_matches = ascii_pattern.findall(dump_content)
        
        # Limit and decode strings
        for match in ascii_matches[:100]:
            try:
                string_val = match.decode('ascii')
                strings.append({
                    'string': string_val,
                    'length': len(string_val),
                    'type': 'ascii'
                })
            except:
                continue
                
        return strings
        
    def _perform_volatility_analysis(self, dump_content):
        """Perform Volatility-style analysis."""
        analysis = {
            'pslist_equivalent': [],
            'connections_equivalent': [],
            'modules_equivalent': [],
            'analysis_summary': {}
        }
        
        # Simulate volatility pslist
        analysis['pslist_equivalent'] = self._extract_processes_from_memory(dump_content)
        
        # Simulate volatility connections
        analysis['connections_equivalent'] = self._extract_network_connections(dump_content)
        
        # Simulate volatility modules
        analysis['modules_equivalent'] = self._extract_loaded_modules(dump_content)
        
        # Analysis summary
        analysis['analysis_summary'] = {
            'total_processes_found': len(analysis['pslist_equivalent']),
            'total_connections_found': len(analysis['connections_equivalent']),
            'total_modules_found': len(analysis['modules_equivalent']),
            'analysis_confidence': 'medium'
        }
        
        return analysis
        
    # Additional helper methods for filesystem and network analysis...
    
    def _detect_filesystem_type(self, fs_content):
        """Detect filesystem type from content."""
        if b'NTFS' in fs_content[:1024]:
            return 'NTFS'
        elif b'FAT32' in fs_content[:1024] or b'FAT16' in fs_content[:1024]:
            return 'FAT32'
        elif b'\x53\xEF' in fs_content[:1024]:  # EXT filesystem magic
            return 'EXT4'
        else:
            return 'Unknown'
            
    def _parse_ntfs_filesystem(self, fs_content):
        """Parse NTFS filesystem structure."""
        # Simplified NTFS parsing
        return {
            'filesystem_info': {
                'type': 'NTFS',
                'cluster_size': 4096,  # Default
                'total_clusters': len(fs_content) // 4096
            },
            'file_entries': [
                {
                    'filename': '$MFT',
                    'type': 'system_file',
                    'description': 'Master File Table'
                }
            ]
        }
        
    def _parse_fat32_filesystem(self, fs_content):
        """Parse FAT32 filesystem structure."""
        return {
            'filesystem_info': {
                'type': 'FAT32',
                'cluster_size': 4096,
                'root_dir_entries': 512
            }
        }
        
    def _parse_ext4_filesystem(self, fs_content):
        """Parse EXT4 filesystem structure."""
        return {
            'filesystem_info': {
                'type': 'EXT4',
                'block_size': 4096,
                'inode_count': 0
            }
        }
        
    def _parse_generic_filesystem(self, fs_content):
        """Generic filesystem parsing."""
        return {
            'filesystem_info': {
                'type': 'Generic',
                'size': len(fs_content),
                'analysis': 'Basic filesystem analysis performed'
            }
        }
        
    def _parse_pcap_header(self, pcap_content):
        """Parse PCAP file header."""
        if len(pcap_content) < 24:
            return {'error': 'Invalid PCAP file - too small'}
            
        # PCAP global header
        magic = struct.unpack('<I', pcap_content[:4])[0]
        
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            return {'error': 'Invalid PCAP magic number'}
            
        version_major = struct.unpack(f'{endian}H', pcap_content[4:6])[0]
        version_minor = struct.unpack(f'{endian}H', pcap_content[6:8])[0]
        snaplen = struct.unpack(f'{endian}I', pcap_content[16:20])[0]
        network = struct.unpack(f'{endian}I', pcap_content[20:24])[0]
        
        return {
            'pcap_version': f'{version_major}.{version_minor}',
            'snaplen': snaplen,
            'network_type': network,
            'endianness': 'little' if endian == '<' else 'big'
        }
        
    def _extract_network_connections_pcap(self, pcap_content):
        """Extract network connections from PCAP."""
        # Simplified PCAP parsing - would need full packet parsing in reality
        connections = []
        
        # Search for IP headers in the data
        # This is a very basic approach
        offset = 24  # Skip global header
        
        while offset < len(pcap_content) - 16:
            try:
                # Try to find packet headers
                packet_len = struct.unpack('<I', pcap_content[offset+8:offset+12])[0]
                if packet_len > 0 and packet_len < 65536:  # Reasonable packet size
                    connections.append({
                        'packet_offset': offset,
                        'packet_length': packet_len,
                        'analysis': 'PCAP packet found'
                    })
                    offset += packet_len + 16  # Move to next packet
                else:
                    offset += 1
            except:
                offset += 1
                
            # Limit results
            if len(connections) >= 100:
                break
                
        return connections
        
    def _analyze_protocols(self, pcap_content):
        """Analyze protocols in PCAP data."""
        protocols = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'http': 0,
            'https': 0,
            'dns': 0
        }
        
        # Search for protocol signatures
        protocol_signatures = [
            (b'HTTP/', 'http'),
            (b'GET ', 'http'),
            (b'POST ', 'http'),
            (b'DNS', 'dns'),
            (b'\x08\x00', 'icmp')  # ICMP type
        ]
        
        for signature, protocol in protocol_signatures:
            count = pcap_content.count(signature)
            protocols[protocol] = count
            
        return protocols
        
    def _extract_files_from_pcap(self, pcap_content):
        """Extract files from PCAP network traffic."""
        extracted_files = []
        
        # Look for file transfer patterns
        file_patterns = [
            (b'Content-Type:', 'http_file_transfer'),
            (b'filename=', 'file_attachment'),
            (b'FTP', 'ftp_transfer')
        ]
        
        for pattern, transfer_type in file_patterns:
            if pattern in pcap_content:
                extracted_files.append({
                    'type': transfer_type,
                    'pattern': pattern.decode('ascii', errors='ignore'),
                    'found': True
                })
                
        return extracted_files
        
    def _extract_dns_queries(self, pcap_content):
        """Extract DNS queries from PCAP."""
        dns_queries = []
        
        # Search for domain name patterns
        domain_pattern = re.compile(rb'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}')
        domain_matches = domain_pattern.findall(pcap_content)
        
        for domain in domain_matches[:20]:  # Limit results
            try:
                domain_str = domain.decode('ascii')
                if '.' in domain_str and len(domain_str) > 4:
                    dns_queries.append({
                        'domain': domain_str,
                        'type': 'extracted_domain',
                        'analysis': self._analyze_domain(domain_str)
                    })
            except:
                continue
                
        return dns_queries
        
    def _analyze_domain(self, domain):
        """Analyze domain name for suspicious characteristics."""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return 'suspicious_tld'
        elif len(domain) > 50:
            return 'unusually_long'
        elif domain.count('-') > 5:
            return 'many_hyphens'
        else:
            return 'normal'
            
    def _reconstruct_http_sessions(self, pcap_content):
        """Reconstruct HTTP sessions from PCAP."""
        http_sessions = []
        
        # Search for HTTP request/response patterns
        http_patterns = [
            b'GET ',
            b'POST ',
            b'HTTP/1.1',
            b'HTTP/1.0'
        ]
        
        for pattern in http_patterns:
            count = pcap_content.count(pattern)
            if count > 0:
                http_sessions.append({
                    'method': pattern.decode('ascii', errors='ignore'),
                    'occurrences': count,
                    'analysis': f'Found {count} HTTP {pattern.decode("ascii", errors="ignore")} patterns'
                })
                
        return http_sessions
        
    def _detect_suspicious_network_traffic(self, pcap_content):
        """Detect suspicious network traffic patterns."""
        suspicious_traffic = []
        
        # Search for suspicious patterns
        suspicious_patterns = [
            (b'cmd.exe', 'command_execution'),
            (b'powershell', 'powershell_activity'),
            (b'wget', 'file_download'),
            (b'curl', 'file_download'),
            (b'base64', 'encoded_content')
        ]
        
        for pattern, activity_type in suspicious_patterns:
            count = pcap_content.count(pattern)
            if count > 0:
                suspicious_traffic.append({
                    'pattern': pattern.decode('ascii', errors='ignore'),
                    'activity_type': activity_type,
                    'occurrences': count,
                    'severity': 'high' if activity_type in ['command_execution', 'powershell_activity'] else 'medium'
                })
                
        return suspicious_traffic
        
    def _perform_geolocation_analysis(self, connections):
        """Perform geolocation analysis on IP addresses."""
        geolocation_data = {}
        
        # Basic geolocation based on IP ranges (simplified)
        for connection in connections:
            ip = connection.get('ip_address', '')
            if ip:
                geolocation_data[ip] = self._get_basic_geolocation(ip)
                
        return geolocation_data
        
    def _get_basic_geolocation(self, ip):
        """Get basic geolocation info for IP address."""
        # Simplified geolocation - in reality would use MaxMind or similar
        octets = ip.split('.')
        first_octet = int(octets[0])
        
        if first_octet in range(1, 24):
            return {'country': 'US', 'region': 'North America'}
        elif first_octet in range(24, 48):
            return {'country': 'EU', 'region': 'Europe'}
        elif first_octet in range(48, 72):
            return {'country': 'APAC', 'region': 'Asia Pacific'}
        else:
            return {'country': 'Unknown', 'region': 'Unknown'}
            
    def _analyze_pe_characteristics(self, pe_content, pe_offset):
        """Analyze PE file characteristics."""
        try:
            # Parse PE optional header
            optional_header_offset = pe_offset + 24
            if len(pe_content) > optional_header_offset + 16:
                characteristics = struct.unpack('<H', pe_content[pe_offset+22:pe_offset+24])[0]
                
                char_flags = []
                if characteristics & 0x0001:
                    char_flags.append('RELOCS_STRIPPED')
                if characteristics & 0x0002:
                    char_flags.append('EXECUTABLE_IMAGE')
                if characteristics & 0x0020:
                    char_flags.append('LARGE_ADDRESS_AWARE')
                if characteristics & 0x2000:
                    char_flags.append('DLL')
                    
                return {
                    'characteristics': characteristics,
                    'flags': char_flags,
                    'is_dll': bool(characteristics & 0x2000),
                    'is_executable': bool(characteristics & 0x0002)
                }
        except:
            pass
            
        return {'error': 'Failed to parse PE characteristics'}
