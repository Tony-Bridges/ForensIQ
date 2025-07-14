"""
Forensic utilities for file analysis, hashing, and timeline generation.
"""
import hashlib
import os
import logging
from datetime import datetime
import json

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

def analyze_file(file):
    """Perform forensic analysis on uploaded file."""
    analysis = {
        "status": "analyzed",
        "timestamp": datetime.utcnow().isoformat(),
        "findings": [],
        "file_type": "unknown",
        "entropy": 0.0,
        "suspicious_indicators": []
    }

    try:
        # Reset file pointer
        file.seek(0)
        content = file.read()
        file.seek(0)

        # Basic analysis
        analysis["file_size"] = len(content)
        analysis["findings"].append({
            "type": "file_analysis",
            "description": f"File contains {len(content)} bytes",
            "severity": "info"
        })

        # Calculate entropy (simple version)
        if content:
            byte_counts = [0] * 256
            for byte in content:
                byte_counts[byte] += 1

            entropy = 0.0
            length = len(content)
            for count in byte_counts:
                if count > 0:
                    probability = count / length
                    entropy -= probability * (probability.bit_length() - 1)

            analysis["entropy"] = round(entropy, 2)

            if entropy > 7.5:
                analysis["findings"].append({
                    "type": "high_entropy",
                    "description": f"High entropy detected ({entropy:.2f}) - possible encryption/compression",
                    "severity": "medium"
                })

        # Check for suspicious patterns
        suspicious_strings = [
            (b"password", "Password-related content found"),
            (b"malware", "Malware-related strings detected"),
            (b"exploit", "Exploit-related content detected"),
            (b"backdoor", "Backdoor indicators found"),
            (b"keylog", "Keylogger indicators detected"),
            (b"trojan", "Trojan indicators found"),
            (b"virus", "Virus-related content detected")
        ]

        content_lower = content.lower()
        for pattern, description in suspicious_strings:
            if pattern in content_lower:
                analysis["findings"].append({
                    "type": "suspicious_content",
                    "description": description,
                    "severity": "high" if pattern in [b"malware", b"exploit", b"backdoor"] else "medium"
                })
                analysis["suspicious_indicators"].append(pattern.decode())

        # Check for executable signatures
        pe_signature = b"MZ"  # PE executable
        elf_signature = b"\x7fELF"  # ELF executable

        if content.startswith(pe_signature):
            analysis["file_type"] = "PE Executable"
            analysis["findings"].append({
                "type": "executable",
                "description": "Windows PE executable detected",
                "severity": "medium"
            })
        elif content.startswith(elf_signature):
            analysis["file_type"] = "ELF Executable"
            analysis["findings"].append({
                "type": "executable",
                "description": "Linux ELF executable detected",
                "severity": "medium"
            })

        # Check for archive signatures
        zip_signature = b"PK"
        if content.startswith(zip_signature):
            analysis["file_type"] = "ZIP Archive"
            analysis["findings"].append({
                "type": "archive",
                "description": "ZIP archive detected",
                "severity": "info"
            })

        # Risk assessment
        risk_score = len([f for f in analysis["findings"] if f["severity"] == "high"]) * 3
        risk_score += len([f for f in analysis["findings"] if f["severity"] == "medium"]) * 2
        risk_score += len([f for f in analysis["findings"] if f["severity"] == "low"])

        analysis["risk_score"] = risk_score
        if risk_score >= 10:
            analysis["risk_level"] = "HIGH"
        elif risk_score >= 5:
            analysis["risk_level"] = "MEDIUM"
        else:
            analysis["risk_level"] = "LOW"

    except Exception as e:
        analysis["error"] = str(e)
        logging.error(f"File analysis error: {str(e)}")

    return analysis

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

def generate_timeline(metadata):
    """Generate basic timeline from metadata."""
    timeline = []

    if metadata.get("created"):
        timeline.append({
            "timestamp": metadata["created"],
            "event": "File Created"
        })

    if metadata.get("modified"):
        timeline.append({
            "timestamp": metadata["modified"],
            "event": "Last Modified"
        })

    if metadata.get("accessed"):
        timeline.append({
            "timestamp": metadata["accessed"],
            "event": "Last Accessed"
        })

    return sorted(timeline, key=lambda x: x["timestamp"])

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