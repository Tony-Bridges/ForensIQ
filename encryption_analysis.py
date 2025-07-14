"""
Encryption, Steganography, and Evasion Analysis Module
Detects encrypted volumes, steganography, rootkits, and fileless malware.
"""
import hashlib
import struct
import re
import os
import math
from datetime import datetime
import logging
from collections import Counter
import base64

class EncryptionAnalysis:
    def __init__(self):
        self.encryption_signatures = {
            'veracrypt': [b'VERA', b'TRUE'],
            'bitlocker': [b'BOOT\x00\x00\x00', b'-FVE-FS-'],
            'luks': [b'LUKS\xba\xbe'],
            'pgp': [b'\x99\x00', b'\x99\x01', b'\x99\x02'],
            'zip_encrypted': [b'PK\x03\x04', b'PK\x05\x06'],
            'rar_encrypted': [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01']
        }
        
        self.steganography_formats = ['jpg', 'png', 'bmp', 'gif', 'wav', 'mp3', 'avi', 'mp4']
        
        self.rootkit_indicators = [
            'SSDT hooks', 'IDT modifications', 'hidden processes',
            'hidden files', 'network hiding', 'registry hiding'
        ]
        
    def detect_encrypted_volumes(self, file_path_or_data, analysis_type='file'):
        """
        Detect encrypted volumes and files.
        
        Args:
            file_path_or_data: File path or binary data to analyze
            analysis_type: 'file', 'volume', or 'memory'
            
        Returns:
            dict: Encryption detection results
        """
        detection_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'analysis_type': analysis_type,
            'encryption_detected': False,
            'encryption_type': 'unknown',
            'encryption_strength': 'unknown',
            'container_format': 'unknown',
            'metadata': {},
            'cracking_recommendations': []
        }
        
        try:
            if analysis_type == 'file':
                detection_results.update(self._analyze_encrypted_file(file_path_or_data))
            elif analysis_type == 'volume':
                detection_results.update(self._analyze_encrypted_volume(file_path_or_data))
            elif analysis_type == 'memory':
                detection_results.update(self._analyze_encrypted_memory(file_path_or_data))
                
        except Exception as e:
            logging.error(f"Encryption detection failed: {str(e)}")
            detection_results['error'] = str(e)
            
        return detection_results
        
    def detect_steganography(self, media_file, media_type='auto'):
        """
        Detect hidden data in media files using steganography.
        
        Args:
            media_file: Media file to analyze
            media_type: 'image', 'audio', 'video', or 'auto'
            
        Returns:
            dict: Steganography detection results
        """
        stego_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'media_type': media_type,
            'steganography_detected': False,
            'stego_methods': [],
            'hidden_data_size': 0,
            'extracted_data': None,
            'statistical_analysis': {},
            'visual_analysis': {},
            'confidence_score': 0.0
        }
        
        try:
            # Auto-detect media type if not specified
            if media_type == 'auto':
                media_type = self._detect_media_type(media_file)
                stego_results['media_type'] = media_type
                
            if media_type == 'image':
                stego_results.update(self._analyze_image_steganography(media_file))
            elif media_type == 'audio':
                stego_results.update(self._analyze_audio_steganography(media_file))
            elif media_type == 'video':
                stego_results.update(self._analyze_video_steganography(media_file))
                
        except Exception as e:
            logging.error(f"Steganography detection failed: {str(e)}")
            stego_results['error'] = str(e)
            
        return stego_results
        
    def detect_rootkits(self, system_data, analysis_scope='full'):
        """
        Detect rootkits and kernel-level malware.
        
        Args:
            system_data: System data including memory dumps, registry, etc.
            analysis_scope: 'full', 'memory', 'registry', or 'filesystem'
            
        Returns:
            dict: Rootkit detection results
        """
        rootkit_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'analysis_scope': analysis_scope,
            'rootkit_detected': False,
            'rootkit_type': 'unknown',
            'indicators': [],
            'hidden_processes': [],
            'hidden_files': [],
            'registry_modifications': [],
            'ssdt_hooks': [],
            'network_hiding': [],
            'confidence_score': 0.0
        }
        
        try:
            if analysis_scope in ['full', 'memory']:
                rootkit_results.update(self._analyze_memory_rootkits(system_data))
                
            if analysis_scope in ['full', 'registry']:
                rootkit_results.update(self._analyze_registry_rootkits(system_data))
                
            if analysis_scope in ['full', 'filesystem']:
                rootkit_results.update(self._analyze_filesystem_rootkits(system_data))
                
            # Calculate overall confidence score
            rootkit_results['confidence_score'] = self._calculate_rootkit_confidence(rootkit_results)
            
        except Exception as e:
            logging.error(f"Rootkit detection failed: {str(e)}")
            rootkit_results['error'] = str(e)
            
        return rootkit_results
        
    def detect_fileless_malware(self, memory_dump, process_list=None):
        """
        Detect fileless malware and memory-resident threats.
        
        Args:
            memory_dump: Memory dump data
            process_list: List of running processes
            
        Returns:
            dict: Fileless malware detection results
        """
        fileless_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'fileless_detected': False,
            'techniques_used': [],
            'injected_processes': [],
            'memory_artifacts': [],
            'powershell_indicators': [],
            'dll_injection': [],
            'process_hollowing': [],
            'reflective_loading': [],
            'confidence_score': 0.0
        }
        
        try:
            # Analyze memory for injection techniques
            fileless_results.update(self._analyze_memory_injection(memory_dump, process_list))
            
            # Detect PowerShell-based attacks
            fileless_results['powershell_indicators'] = self._detect_powershell_attacks(memory_dump)
            
            # Detect DLL injection
            fileless_results['dll_injection'] = self._detect_dll_injection(memory_dump, process_list)
            
            # Detect process hollowing
            fileless_results['process_hollowing'] = self._detect_process_hollowing(memory_dump, process_list)
            
            # Detect reflective DLL loading
            fileless_results['reflective_loading'] = self._detect_reflective_loading(memory_dump)
            
            # Calculate confidence score
            fileless_results['confidence_score'] = self._calculate_fileless_confidence(fileless_results)
            
        except Exception as e:
            logging.error(f"Fileless malware detection failed: {str(e)}")
            fileless_results['error'] = str(e)
            
        return fileless_results
        
    def analyze_encryption_strength(self, encrypted_data, encryption_type=None):
        """
        Analyze encryption strength and provide cracking recommendations.
        
        Args:
            encrypted_data: Encrypted data to analyze
            encryption_type: Known encryption type (optional)
            
        Returns:
            dict: Encryption strength analysis
        """
        strength_analysis = {
            'timestamp': datetime.utcnow().isoformat(),
            'encryption_type': encryption_type or 'unknown',
            'key_length': 'unknown',
            'algorithm_strength': 'unknown',
            'entropy_analysis': {},
            'vulnerability_assessment': [],
            'cracking_difficulty': 'unknown',
            'estimated_time_to_crack': 'unknown',
            'recommended_tools': []
        }
        
        try:
            # Perform entropy analysis
            strength_analysis['entropy_analysis'] = self._calculate_entropy_analysis(encrypted_data)
            
            # Analyze algorithm strength if known
            if encryption_type:
                strength_analysis.update(self._analyze_algorithm_strength(encryption_type))
                
            # Assess vulnerabilities
            strength_analysis['vulnerability_assessment'] = self._assess_encryption_vulnerabilities(
                encrypted_data, encryption_type
            )
            
            # Provide cracking recommendations
            strength_analysis['recommended_tools'] = self._recommend_cracking_tools(
                encryption_type, strength_analysis['vulnerability_assessment']
            )
            
        except Exception as e:
            logging.error(f"Encryption strength analysis failed: {str(e)}")
            strength_analysis['error'] = str(e)
            
        return strength_analysis
        
    def _analyze_encrypted_file(self, file_path):
        """Analyze file for encryption signatures."""
        results = {
            'encryption_detected': False,
            'encryption_type': 'unknown',
            'container_format': 'unknown'
        }
        
        try:
            if hasattr(file_path, 'read'):
                # File-like object
                header = file_path.read(1024)
                file_path.seek(0)
            else:
                # File path
                with open(file_path, 'rb') as f:
                    header = f.read(1024)
                    
            # Check for encryption signatures
            for enc_type, signatures in self.encryption_signatures.items():
                for signature in signatures:
                    if signature in header:
                        results['encryption_detected'] = True
                        results['encryption_type'] = enc_type
                        results['container_format'] = enc_type
                        break
                        
        except Exception as e:
            logging.error(f"File analysis error: {str(e)}")
            
        return results
        
    def _analyze_encrypted_volume(self, volume_path):
        """Analyze volume for encryption."""
        results = {
            'encryption_detected': False,
            'encryption_type': 'unknown',
            'volume_type': 'unknown'
        }
        
        # Simulated volume analysis
        # In production, this would analyze disk sectors and boot records
        results.update({
            'encryption_detected': True,
            'encryption_type': 'bitlocker',
            'volume_type': 'NTFS',
            'metadata': {
                'volume_size': '500GB',
                'encrypted_sectors': 1048576,
                'encryption_method': 'AES-256-XTS'
            }
        })
        
        return results
        
    def _analyze_encrypted_memory(self, memory_dump):
        """Analyze memory dump for encryption artifacts."""
        results = {
            'encryption_detected': False,
            'memory_encryption': [],
            'encrypted_regions': []
        }
        
        # Simulated memory encryption analysis
        results.update({
            'encryption_detected': True,
            'memory_encryption': ['process_encryption', 'heap_encryption'],
            'encrypted_regions': [
                {'start': '0x7ff000000000', 'end': '0x7ff000100000', 'type': 'code_section'},
                {'start': '0x7ff001000000', 'end': '0x7ff001050000', 'type': 'data_section'}
            ]
        })
        
        return results
        
    def _analyze_image_steganography(self, image_file):
        """Analyze image for steganographic content."""
        results = {
            'steganography_detected': False,
            'stego_methods': [],
            'statistical_analysis': {}
        }
        
        try:
            # Read image data
            if hasattr(image_file, 'read'):
                image_data = image_file.read()
            else:
                with open(image_file, 'rb') as f:
                    image_data = f.read()
                    
            # Perform statistical analysis
            results['statistical_analysis'] = self._perform_statistical_analysis(image_data)
            
            # Check for LSB steganography
            if self._detect_lsb_steganography(image_data):
                results['steganography_detected'] = True
                results['stego_methods'].append('LSB')
                
            # Check for DCT steganography (JPEG)
            if b'\xff\xd8\xff' in image_data[:10]:  # JPEG signature
                if self._detect_dct_steganography(image_data):
                    results['steganography_detected'] = True
                    results['stego_methods'].append('DCT')
                    
        except Exception as e:
            logging.error(f"Image steganography analysis error: {str(e)}")
            
        return results
        
    def _analyze_audio_steganography(self, audio_file):
        """Analyze audio for steganographic content."""
        results = {
            'steganography_detected': False,
            'stego_methods': [],
            'audio_analysis': {}
        }
        
        # Simulated audio steganography detection
        results.update({
            'steganography_detected': True,
            'stego_methods': ['LSB_audio', 'echo_hiding'],
            'audio_analysis': {
                'sample_rate': 44100,
                'bit_depth': 16,
                'channels': 2,
                'suspicious_frequencies': [1000, 2000, 4000]
            }
        })
        
        return results
        
    def _analyze_video_steganography(self, video_file):
        """Analyze video for steganographic content."""
        results = {
            'steganography_detected': False,
            'stego_methods': [],
            'video_analysis': {}
        }
        
        # Simulated video steganography detection
        results.update({
            'steganography_detected': False,
            'stego_methods': [],
            'video_analysis': {
                'codec': 'H.264',
                'resolution': '1920x1080',
                'frame_rate': 30,
                'suspicious_frames': []
            }
        })
        
        return results
        
    def _detect_media_type(self, media_file):
        """Detect media file type."""
        if hasattr(media_file, 'read'):
            header = media_file.read(16)
            media_file.seek(0)
        else:
            with open(media_file, 'rb') as f:
                header = f.read(16)
                
        # Check file signatures
        if header.startswith(b'\xff\xd8\xff'):
            return 'image'  # JPEG
        elif header.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image'  # PNG
        elif header.startswith(b'RIFF') and b'WAVE' in header:
            return 'audio'  # WAV
        elif header.startswith(b'ID3') or header.startswith(b'\xff\xfb'):
            return 'audio'  # MP3
        elif header.startswith(b'\x00\x00\x00\x18ftypmp4') or header.startswith(b'\x00\x00\x00\x20ftypisom'):
            return 'video'  # MP4
        else:
            return 'unknown'
            
    def _analyze_memory_rootkits(self, system_data):
        """Analyze memory for rootkit indicators."""
        results = {
            'ssdt_hooks': [],
            'hidden_processes': [],
            'memory_modifications': []
        }
        
        # Simulated memory rootkit analysis
        results.update({
            'ssdt_hooks': [
                {'function': 'NtCreateFile', 'hooked': True, 'hook_address': '0x80504020'},
                {'function': 'NtOpenProcess', 'hooked': True, 'hook_address': '0x80504040'}
            ],
            'hidden_processes': [
                {'pid': 1234, 'name': 'suspicious.exe', 'hiding_method': 'DKOM'}
            ],
            'memory_modifications': [
                {'address': '0x80500000', 'type': 'code_modification', 'size': 1024}
            ]
        })
        
        return results
        
    def _analyze_registry_rootkits(self, system_data):
        """Analyze registry for rootkit modifications."""
        results = {
            'registry_modifications': [],
            'hidden_keys': [],
            'suspicious_values': []
        }
        
        # Simulated registry rootkit analysis
        results.update({
            'registry_modifications': [
                {
                    'key': 'HKLM\\System\\CurrentControlSet\\Services\\malware_service',
                    'modification_type': 'hidden_service',
                    'detection_method': 'direct_access'
                }
            ],
            'hidden_keys': [
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware'
            ],
            'suspicious_values': [
                {
                    'key': 'HKLM\\System\\CurrentControlSet\\Control\\Session Manager',
                    'value': 'PendingFileRenameOperations',
                    'suspicious_content': 'malware.exe'
                }
            ]
        })
        
        return results
        
    def _analyze_filesystem_rootkits(self, system_data):
        """Analyze filesystem for rootkit hiding techniques."""
        results = {
            'hidden_files': [],
            'alternate_data_streams': [],
            'file_system_hooks': []
        }
        
        # Simulated filesystem rootkit analysis
        results.update({
            'hidden_files': [
                {'path': 'C:\\Windows\\System32\\malware.sys', 'hiding_method': 'rootkit_driver'},
                {'path': 'C:\\temp\\backdoor.exe', 'hiding_method': 'alternate_data_stream'}
            ],
            'alternate_data_streams': [
                {'file': 'C:\\innocent.txt:hidden.exe', 'size': 102400, 'type': 'executable'}
            ],
            'file_system_hooks': [
                {'function': 'ZwCreateFile', 'hooked': True, 'filter_driver': 'malware.sys'}
            ]
        })
        
        return results
        
    def _analyze_memory_injection(self, memory_dump, process_list):
        """Analyze memory for injection techniques."""
        results = {
            'injected_processes': [],
            'memory_artifacts': [],
            'techniques_used': []
        }
        
        # Simulated memory injection analysis
        results.update({
            'injected_processes': [
                {
                    'pid': 1234,
                    'process_name': 'explorer.exe',
                    'injection_type': 'dll_injection',
                    'injected_module': 'malware.dll'
                }
            ],
            'memory_artifacts': [
                {
                    'address': '0x7ff000000000',
                    'size': 65536,
                    'type': 'injected_code',
                    'characteristics': 'executable'
                }
            ],
            'techniques_used': ['dll_injection', 'process_hollowing']
        })
        
        return results
        
    def _detect_powershell_attacks(self, memory_dump):
        """Detect PowerShell-based attacks in memory."""
        powershell_indicators = []
        
        # Simulated PowerShell attack detection
        powershell_indicators = [
            {
                'technique': 'encoded_command',
                'indicator': 'powershell.exe -EncodedCommand',
                'decoded_content': 'Invoke-Expression (New-Object Net.WebClient).DownloadString',
                'threat_level': 'high'
            },
            {
                'technique': 'bypass_execution_policy',
                'indicator': 'powershell.exe -ExecutionPolicy Bypass',
                'threat_level': 'medium'
            }
        ]
        
        return powershell_indicators
        
    def _detect_dll_injection(self, memory_dump, process_list):
        """Detect DLL injection techniques."""
        dll_injections = []
        
        # Simulated DLL injection detection
        dll_injections = [
            {
                'target_process': 'notepad.exe',
                'target_pid': 5678,
                'injected_dll': 'malicious.dll',
                'injection_method': 'SetWindowsHookEx',
                'detection_confidence': 0.85
            }
        ]
        
        return dll_injections
        
    def _detect_process_hollowing(self, memory_dump, process_list):
        """Detect process hollowing techniques."""
        hollowing_detections = []
        
        # Simulated process hollowing detection
        hollowing_detections = [
            {
                'process_name': 'svchost.exe',
                'pid': 9012,
                'original_image': 'C:\\Windows\\System32\\svchost.exe',
                'replacement_detected': True,
                'suspicious_sections': ['0x400000-0x450000'],
                'confidence': 0.9
            }
        ]
        
        return hollowing_detections
        
    def _detect_reflective_loading(self, memory_dump):
        """Detect reflective DLL loading."""
        reflective_detections = []
        
        # Simulated reflective loading detection
        reflective_detections = [
            {
                'memory_address': '0x7ff800000000',
                'size': 131072,
                'pe_characteristics': 'manually_loaded',
                'reflective_loader_detected': True,
                'confidence': 0.8
            }
        ]
        
        return reflective_detections
        
    def _perform_statistical_analysis(self, data):
        """Perform statistical analysis on data for steganography detection."""
        if len(data) < 100:
            return {'error': 'Insufficient data for analysis'}
            
        # Calculate entropy
        entropy = self._calculate_entropy(data)
        
        # Calculate chi-square test
        chi_square = self._calculate_chi_square(data)
        
        # Calculate byte frequency analysis
        byte_frequencies = Counter(data)
        
        return {
            'entropy': entropy,
            'chi_square': chi_square,
            'byte_distribution': dict(byte_frequencies.most_common(10)),
            'data_size': len(data),
            'anomaly_score': entropy + (chi_square / 1000)  # Simplified scoring
        }
        
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0
            
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
        
    def _calculate_chi_square(self, data):
        """Calculate chi-square test statistic."""
        if len(data) < 256:
            return 0
            
        observed = [0] * 256
        for byte in data:
            observed[byte] += 1
            
        expected = len(data) / 256
        chi_square = 0
        
        for obs in observed:
            chi_square += ((obs - expected) ** 2) / expected
            
        return chi_square
        
    def _detect_lsb_steganography(self, image_data):
        """Detect LSB steganography in image data."""
        # Simplified LSB detection
        # In production, would analyze pixel values and LSB patterns
        if len(image_data) > 1000:
            # Check for regular patterns in LSBs
            lsb_pattern = sum(byte & 1 for byte in image_data[-1000:])
            # If LSBs are too regular or irregular, might indicate steganography
            return 400 < lsb_pattern < 600  # Expect ~500 for random data
        return False
        
    def _detect_dct_steganography(self, jpeg_data):
        """Detect DCT coefficient steganography in JPEG."""
        # Simplified DCT steganography detection
        # In production, would analyze DCT coefficients for modifications
        return False  # Placeholder
        
    def _calculate_entropy_analysis(self, data):
        """Calculate comprehensive entropy analysis."""
        entropy = self._calculate_entropy(data)
        
        return {
            'shannon_entropy': entropy,
            'min_entropy': 0,
            'max_entropy': 8,
            'entropy_ratio': entropy / 8,
            'randomness_assessment': 'high' if entropy > 7.5 else 'medium' if entropy > 6 else 'low'
        }
        
    def _analyze_algorithm_strength(self, encryption_type):
        """Analyze the strength of encryption algorithm."""
        algorithm_info = {
            'veracrypt': {'strength': 'very_high', 'key_length': '256-bit', 'algorithm': 'AES'},
            'bitlocker': {'strength': 'high', 'key_length': '128/256-bit', 'algorithm': 'AES'},
            'pgp': {'strength': 'high', 'key_length': 'variable', 'algorithm': 'RSA/AES'},
            'zip_encrypted': {'strength': 'low', 'key_length': '96-bit', 'algorithm': 'proprietary'},
            'rar_encrypted': {'strength': 'medium', 'key_length': '128-bit', 'algorithm': 'AES'}
        }
        
        return algorithm_info.get(encryption_type, {'strength': 'unknown', 'key_length': 'unknown', 'algorithm': 'unknown'})
        
    def _assess_encryption_vulnerabilities(self, data, encryption_type):
        """Assess vulnerabilities in encrypted data."""
        vulnerabilities = []
        
        if encryption_type == 'zip_encrypted':
            vulnerabilities.append({
                'type': 'weak_encryption',
                'description': 'ZIP encryption uses weak proprietary algorithm',
                'severity': 'high'
            })
            
        if encryption_type == 'rar_encrypted':
            vulnerabilities.append({
                'type': 'known_attacks',
                'description': 'RAR encryption vulnerable to known plaintext attacks',
                'severity': 'medium'
            })
            
        return vulnerabilities
        
    def _recommend_cracking_tools(self, encryption_type, vulnerabilities):
        """Recommend tools for cracking encryption."""
        tools = []
        
        if encryption_type in ['zip_encrypted', 'rar_encrypted']:
            tools.extend(['john', 'hashcat', 'fcrackzip', 'rarcrack'])
            
        if encryption_type == 'bitlocker':
            tools.extend(['hashcat', 'bitcracker', 'dislocker'])
            
        if encryption_type == 'veracrypt':
            tools.extend(['hashcat', 'veracrypt_bruteforce'])
            
        if any(vuln['severity'] == 'high' for vuln in vulnerabilities):
            tools.append('custom_attack_tools')
            
        return tools
        
    def _calculate_rootkit_confidence(self, rootkit_results):
        """Calculate confidence score for rootkit detection."""
        confidence = 0.0
        
        if rootkit_results.get('ssdt_hooks'):
            confidence += 0.4
            
        if rootkit_results.get('hidden_processes'):
            confidence += 0.3
            
        if rootkit_results.get('hidden_files'):
            confidence += 0.2
            
        if rootkit_results.get('registry_modifications'):
            confidence += 0.1
            
        return min(confidence, 1.0)
        
    def _calculate_fileless_confidence(self, fileless_results):
        """Calculate confidence score for fileless malware detection."""
        confidence = 0.0
        
        if fileless_results.get('injected_processes'):
            confidence += 0.3
            
        if fileless_results.get('powershell_indicators'):
            confidence += 0.3
            
        if fileless_results.get('dll_injection'):
            confidence += 0.2
            
        if fileless_results.get('process_hollowing'):
            confidence += 0.2
            
        return min(confidence, 1.0)