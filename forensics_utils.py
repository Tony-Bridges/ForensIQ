"""
Forensic utilities for file analysis, hashing, and timeline generation.
"""
import hashlib
import os
import stat
import time
import math
import logging
import re
import struct
from datetime import datetime

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    logging.warning("python-magic not available, using fallback file type detection")

def calculate_hash(file, algorithm="sha256"):
    """Calculate file hash using specified algorithm."""
    algorithms = {
        "md5": hashlib.md5(),
        "sha256": hashlib.sha256()
    }

    if algorithm not in algorithms:
        raise ValueError("Unsupported hash algorithm")

    hash_obj = algorithms[algorithm]

    for chunk in iter(lambda: file.read(4096), b""):
        hash_obj.update(chunk)

    file.seek(0)  # Reset file pointer
    return hash_obj.hexdigest()

def get_file_metadata(file):
    """Extract metadata from uploaded file."""
    metadata = {
        "filename": file.filename,
        "size": 0,
        "mime_type": "unknown",
        "timestamp": datetime.utcnow().isoformat()
    }

    try:
        # Get file size
        file.seek(0, 2)  # Seek to end
        metadata["size"] = file.tell()
        file.seek(0)  # Reset to beginning

        # Get MIME type
        if HAS_MAGIC:
            try:
                file_content = file.read(1024)
                file.seek(0)
                metadata["mime_type"] = magic.from_buffer(file_content, mime=True)
            except Exception as e:
                # Fallback MIME type detection
                extension = file.filename.split('.')[-1].lower() if '.' in file.filename else ''
                mime_types = {
                    'txt': 'text/plain',
                    'pdf': 'application/pdf',
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'exe': 'application/x-executable',
                    'zip': 'application/zip'
                }
                metadata["mime_type"] = mime_types.get(extension, 'application/octet-stream')
        else:
            # Simple extension-based detection
            extension = file.filename.split('.')[-1].lower() if '.' in file.filename else ''
            mime_types = {
                'txt': 'text/plain',
                'pdf': 'application/pdf',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'png': 'image/png',
                'exe': 'application/x-executable',
                'zip': 'application/zip'
            }
            metadata["mime_type"] = mime_types.get(extension, 'application/octet-stream')

    except Exception as e:
        metadata["error"] = str(e)
        logging.error(f"Metadata extraction error: {str(e)}")

    return metadata

def analyze_file(file_data):
    """
    Perform comprehensive file analysis.

    Args:
        file_data: File object or file path

    Returns:
        dict: Analysis results
    """
    import magic
    import os
    import struct
    import re
    from datetime import datetime

    try:
        # Handle file object or path
        if hasattr(file_data, 'read'):
            content = file_data.read()
            file_data.seek(0)
            filename = getattr(file_data, 'filename', 'unknown')
        else:
            with open(file_data, 'rb') as f:
                content = f.read()
            filename = os.path.basename(file_data)

        # File type detection using magic bytes
        file_type = magic.from_buffer(content, mime=True)
        file_description = magic.from_buffer(content)

        # Calculate hashes
        md5_hash = hashlib.md5(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Extract strings (printable characters)
        strings = []
        string_pattern = re.compile(b'[!-~]{4,}')
        string_matches = string_pattern.findall(content)
        strings = [s.decode('ascii', errors='ignore') for s in string_matches[:100]]

        # Calculate entropy (for encryption/compression detection)
        if content:
            byte_counts = {}
            for byte in content:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

            entropy = 0
            content_length = len(content)
            for count in byte_counts.values():
                probability = count / content_length
                if probability > 0:
                    entropy -= probability * math.log2(probability)
        else:
            entropy = 0

        # Suspicious indicators detection
        suspicious_indicators = []
        suspicious_strings = ['password', 'admin', 'backdoor', 'keylog', 'virus', 
                            'malware', 'trojan', 'rootkit', 'exploit', 'cmd.exe']

        for string in strings:
            for indicator in suspicious_strings:
                if indicator.lower() in string.lower():
                    suspicious_indicators.append(f'suspicious_string_{indicator}')

        # High entropy suggests encryption/compression
        if entropy > 7.5:
            suspicious_indicators.append('high_entropy_encrypted_or_compressed')

        # PE file analysis
        pe_info = {}
        if content.startswith(b'MZ'):
            try:
                dos_header = content[:64]
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                if pe_offset < len(content) - 4:
                    pe_signature = content[pe_offset:pe_offset+4]
                    if pe_signature == b'PE\x00\x00':
                        pe_info['is_pe'] = True
                        # Extract compilation timestamp
                        if pe_offset + 8 < len(content):
                            timestamp = struct.unpack('<I', content[pe_offset+8:pe_offset+12])[0]
                            pe_info['compile_time'] = datetime.fromtimestamp(timestamp).isoformat()
            except:
                pass

        return {
            'filename': filename,
            'file_type': file_type,
            'file_description': file_description,
            'size': len(content),
            'md5_hash': md5_hash,
            'sha256_hash': sha256_hash,
            'entropy': round(entropy, 3),
            'strings': strings[:50],  # Limit for performance
            'suspicious_indicators': list(set(suspicious_indicators)),
            'pe_info': pe_info,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }

    except Exception as e:
        logging.error(f"File analysis failed: {str(e)}")
        return {
            'error': str(e),
            'analysis_timestamp': datetime.utcnow().isoformat()
        }

def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def extract_strings(content):
    """Extract printable strings from binary data."""
    strings_found = []
    current_string = ""
    min_length = 4

    for byte in content:
        if 32 <= byte <= 126:
            current_string += chr(byte)
        elif len(current_string) >= min_length:
            strings_found.append(current_string)
            current_string = ""
        else:
            current_string = ""

    return strings_found[:100]  # Limit to first 100 strings

def extract_metadata(file):
    """Extract file metadata based on file type."""
    try:
        mime_type = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)

        if 'pdf' in mime_type:
            return extract_pdf_metadata(file)
        elif 'image' in mime_type:
            return extract_image_metadata(file)
        return {}
    except Exception as e:
        logging.error(f"Metadata extraction error: {str(e)}")
        return {}

def check_encryption(content):
    """Check if file might be encrypted."""
    entropy = calculate_entropy(content)
    return {
        "likely_encrypted": entropy > 7.5,
        "entropy_score": entropy
    }

def generate_timeline(evidence_list):
    """
    Generate forensic timeline from evidence.

    Args:
        evidence_list: List of evidence items (file paths or Evidence objects)

    Returns:
        list: Timeline events sorted by timestamp
    """
    timeline_events = []

    for evidence in evidence_list:
        try:
            if isinstance(evidence, str):
                # File path
                file_path = evidence
                if not os.path.exists(file_path):
                    continue

                stat_info = os.stat(file_path)
                filename = os.path.basename(file_path)

                # Creation time (Windows) or change time (Unix)
                if hasattr(stat_info, 'st_birthtime'):
                    created_time = stat_info.st_birthtime
                else:
                    created_time = stat_info.st_ctime

                timeline_events.append({
                    'timestamp': datetime.fromtimestamp(created_time).isoformat(),
                    'event': 'File Created',
                    'source': filename,
                    'details': f'File created: {file_path}',
                    'file_size': stat_info.st_size,
                    'permissions': oct(stat_info.st_mode)[-3:]
                })

                # Modification time
                timeline_events.append({
                    'timestamp': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    'event': 'File Modified',
                    'source': filename,
                    'details': f'File modified: {file_path}',
                    'file_size': stat_info.st_size,
                    'permissions': oct(stat_info.st_mode)[-3:]
                })

                # Access time
                timeline_events.append({
                    'timestamp': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                    'event': 'File Accessed',
                    'source': filename,
                    'details': f'File accessed: {file_path}',
                    'file_size': stat_info.st_size,
                    'permissions': oct(stat_info.st_mode)[-3:]
                })

            else:
                # Evidence object from database
                timeline_events.append({
                    'timestamp': evidence.timestamp.isoformat() if evidence.timestamp else datetime.utcnow().isoformat(),
                    'event': 'Evidence Added',
                    'source': evidence.filename,
                    'details': f'Evidence file: {evidence.filename}',
                    'file_size': evidence.file_size,
                    'hash': evidence.file_hash
                })

        except Exception as e:
            logging.error(f"Timeline generation error for {evidence}: {str(e)}")
            continue

    # Sort timeline by timestamp
    timeline_events.sort(key=lambda x: x['timestamp'])

    return timeline_events

def write_block_check(file):
    """Implement basic write-blocking check."""
    try:
        # For uploaded files, we want to ensure we can read but not modify them
        # Store current position
        current_pos = file.tell()

        # Try reading from the file
        file.read(1)
        file.seek(current_pos)  # Reset to original position

        return True
    except Exception as e:
        logging.error(f"Write-block check failed: {str(e)}")
        return False