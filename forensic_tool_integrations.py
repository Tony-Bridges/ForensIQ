
"""
Real-World Forensic Tool Integrations
Integration with industry-standard forensic tools and utilities.
"""
import subprocess
import os
import tempfile
import json
import logging
from datetime import datetime, timezone
import shutil
import sqlite3
import hashlib

class ForensicToolIntegrations:
    def __init__(self):
        self.available_tools = {}
        self.tool_paths = {}
        self._detect_available_tools()
        
    def _detect_available_tools(self):
        """Detect available forensic tools on the system."""
        tools_to_check = {
            'strings': ['strings', 'Extract strings from binary files'],
            'file': ['file', 'Determine file types'],
            'hexdump': ['hexdump', 'Hexadecimal dump utility'],
            'xxd': ['xxd', 'Hexdump utility'],
            'grep': ['grep', 'Search text patterns'],
            'awk': ['awk', 'Text processing tool'],
            'sed': ['sed', 'Stream editor'],
            'dd': ['dd', 'Data duplicator'],
            'md5sum': ['md5sum', 'MD5 hash calculator'],
            'sha256sum': ['sha256sum', 'SHA256 hash calculator'],
            'sqlite3': ['sqlite3', 'SQLite database tool'],
            'python3': ['python3', 'Python interpreter']
        }
        
        for tool_name, (command, description) in tools_to_check.items():
            if shutil.which(command):
                self.available_tools[tool_name] = {
                    'command': command,
                    'description': description,
                    'available': True
                }
                self.tool_paths[tool_name] = shutil.which(command)
            else:
                self.available_tools[tool_name] = {
                    'command': command,
                    'description': description,
                    'available': False
                }
                
    def analyze_with_strings(self, file_data, min_length=4, encoding='ascii'):
        """
        Use the 'strings' utility to extract strings from binary files.
        """
        strings_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': 'strings',
            'parameters': {
                'min_length': min_length,
                'encoding': encoding
            },
            'strings_found': [],
            'suspicious_strings': [],
            'analysis': {}
        }
        
        if not self.available_tools.get('strings', {}).get('available'):
            strings_results['error'] = 'strings utility not available'
            return strings_results
            
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                if hasattr(file_data, 'read'):
                    temp_file.write(file_data.read())
                    file_data.seek(0)
                else:
                    with open(file_data, 'rb') as f:
                        temp_file.write(f.read())
                temp_file.flush()
                
                # Run strings command
                cmd = [self.tool_paths['strings'], '-n', str(min_length)]
                if encoding == 'unicode':
                    cmd.append('-e')
                    cmd.append('l')  # little-endian 16-bit
                cmd.append(temp_file.name)
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    strings_list = result.stdout.strip().split('\n')
                    strings_results['strings_found'] = strings_list[:500]  # Limit output
                    
                    # Analyze strings for suspicious content
                    strings_results['suspicious_strings'] = self._analyze_suspicious_strings(strings_list)
                    strings_results['analysis'] = self._analyze_strings_output(strings_list)
                else:
                    strings_results['error'] = f"strings command failed: {result.stderr}"
                    
                os.unlink(temp_file.name)
                
        except Exception as e:
            logging.error(f"Strings analysis failed: {str(e)}")
            strings_results['error'] = str(e)
            
        return strings_results
        
    def analyze_with_file_command(self, file_data):
        """
        Use the 'file' command to determine file type and characteristics.
        """
        file_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': 'file',
            'file_type': 'unknown',
            'mime_type': 'unknown',
            'encoding': 'unknown',
            'detailed_info': '',
            'magic_analysis': {}
        }
        
        if not self.available_tools.get('file', {}).get('available'):
            file_results['error'] = 'file utility not available'
            return file_results
            
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                if hasattr(file_data, 'read'):
                    temp_file.write(file_data.read())
                    file_data.seek(0)
                else:
                    with open(file_data, 'rb') as f:
                        temp_file.write(f.read())
                temp_file.flush()
                
                # Get basic file type
                result = subprocess.run([self.tool_paths['file'], temp_file.name], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    file_results['detailed_info'] = result.stdout.strip()
                    file_results['file_type'] = self._parse_file_type(result.stdout)
                    
                # Get MIME type
                result = subprocess.run([self.tool_paths['file'], '-b', '--mime-type', temp_file.name], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    file_results['mime_type'] = result.stdout.strip()
                    
                # Get encoding
                result = subprocess.run([self.tool_paths['file'], '-b', '--mime-encoding', temp_file.name], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    file_results['encoding'] = result.stdout.strip()
                    
                os.unlink(temp_file.name)
                
        except Exception as e:
            logging.error(f"File command analysis failed: {str(e)}")
            file_results['error'] = str(e)
            
        return file_results
        
    def create_hexdump(self, file_data, length=512, format_type='canonical'):
        """
        Create hexdump of file data using hexdump or xxd utility.
        """
        hexdump_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': 'hexdump',
            'format': format_type,
            'length': length,
            'hexdump_output': '',
            'analysis': {}
        }
        
        # Prefer xxd over hexdump if available
        tool_name = 'xxd' if self.available_tools.get('xxd', {}).get('available') else 'hexdump'
        
        if not self.available_tools.get(tool_name, {}).get('available'):
            hexdump_results['error'] = f'{tool_name} utility not available'
            return hexdump_results
            
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                if hasattr(file_data, 'read'):
                    content = file_data.read()
                    file_data.seek(0)
                else:
                    with open(file_data, 'rb') as f:
                        content = f.read()
                        
                # Limit content length
                content = content[:length]
                temp_file.write(content)
                temp_file.flush()
                
                if tool_name == 'xxd':
                    # Use xxd for better formatting
                    cmd = [self.tool_paths['xxd'], '-l', str(length)]
                    if format_type == 'plain':
                        cmd.append('-p')
                    cmd.append(temp_file.name)
                else:
                    # Use hexdump
                    cmd = [self.tool_paths['hexdump'], '-C', '-n', str(length), temp_file.name]
                    
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    hexdump_results['hexdump_output'] = result.stdout
                    hexdump_results['analysis'] = self._analyze_hexdump_output(content)
                else:
                    hexdump_results['error'] = f"{tool_name} command failed: {result.stderr}"
                    
                os.unlink(temp_file.name)
                
        except Exception as e:
            logging.error(f"Hexdump analysis failed: {str(e)}")
            hexdump_results['error'] = str(e)
            
        return hexdump_results
        
    def calculate_hashes(self, file_data, algorithms=['md5', 'sha1', 'sha256']):
        """
        Calculate file hashes using system utilities.
        """
        hash_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'algorithms': algorithms,
            'hashes': {},
            'file_size': 0
        }
        
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                if hasattr(file_data, 'read'):
                    content = file_data.read()
                    file_data.seek(0)
                else:
                    with open(file_data, 'rb') as f:
                        content = f.read()
                        
                temp_file.write(content)
                temp_file.flush()
                hash_results['file_size'] = len(content)
                
                # Calculate hashes using system utilities
                for algorithm in algorithms:
                    hash_cmd = f'{algorithm}sum'
                    if self.available_tools.get(hash_cmd, {}).get('available'):
                        result = subprocess.run([self.tool_paths[hash_cmd], temp_file.name], 
                                              capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            hash_value = result.stdout.split()[0]
                            hash_results['hashes'][algorithm] = hash_value
                    else:
                        # Fallback to Python hashlib
                        hash_results['hashes'][algorithm] = self._calculate_hash_python(content, algorithm)
                        
                os.unlink(temp_file.name)
                
        except Exception as e:
            logging.error(f"Hash calculation failed: {str(e)}")
            hash_results['error'] = str(e)
            
        return hash_results
        
    def search_patterns(self, file_data, patterns, case_sensitive=False):
        """
        Search for patterns in file using grep utility.
        """
        search_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': 'grep',
            'patterns': patterns,
            'case_sensitive': case_sensitive,
            'matches': {},
            'total_matches': 0
        }
        
        if not self.available_tools.get('grep', {}).get('available'):
            search_results['error'] = 'grep utility not available'
            return search_results
            
        try:
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
                if hasattr(file_data, 'read'):
                    content = file_data.read()
                    file_data.seek(0)
                else:
                    with open(file_data, 'rb') as f:
                        content = f.read()
                        
                temp_file.write(content)
                temp_file.flush()
                
                for pattern in patterns:
                    cmd = [self.tool_paths['grep'], '-n']
                    if not case_sensitive:
                        cmd.append('-i')
                    cmd.extend(['-a', pattern, temp_file.name])  # -a treats binary as text
                    
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, 
                                              timeout=20, errors='ignore')
                        if result.returncode == 0:
                            matches = result.stdout.strip().split('\n')
                            search_results['matches'][pattern] = matches
                            search_results['total_matches'] += len(matches)
                        else:
                            search_results['matches'][pattern] = []
                    except subprocess.TimeoutExpired:
                        search_results['matches'][pattern] = ['Search timeout']
                        
                os.unlink(temp_file.name)
                
        except Exception as e:
            logging.error(f"Pattern search failed: {str(e)}")
            search_results['error'] = str(e)
            
        return search_results
        
    def analyze_sqlite_database(self, db_file):
        """
        Analyze SQLite database files.
        """
        db_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': 'sqlite3',
            'database_info': {},
            'tables': [],
            'schema': {},
            'sample_data': {},
            'forensic_artifacts': []
        }
        
        if not self.available_tools.get('sqlite3', {}).get('available'):
            db_results['error'] = 'sqlite3 utility not available'
            return db_results
            
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
                if hasattr(db_file, 'read'):
                    temp_file.write(db_file.read())
                    db_file.seek(0)
                else:
                    with open(db_file, 'rb') as f:
                        temp_file.write(f.read())
                temp_file.flush()
                
                # Connect to database
                conn = sqlite3.connect(temp_file.name)
                cursor = conn.cursor()
                
                # Get database info
                cursor.execute("PRAGMA database_list;")
                db_results['database_info'] = cursor.fetchall()
                
                # Get table list
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                db_results['tables'] = [table[0] for table in tables]
                
                # Get schema for each table
                for table_name in db_results['tables']:
                    cursor.execute(f"PRAGMA table_info({table_name});")
                    schema = cursor.fetchall()
                    db_results['schema'][table_name] = schema
                    
                    # Get sample data (first 5 rows)
                    try:
                        cursor.execute(f"SELECT * FROM {table_name} LIMIT 5;")
                        sample_data = cursor.fetchall()
                        db_results['sample_data'][table_name] = sample_data
                    except sqlite3.Error:
                        db_results['sample_data'][table_name] = 'Error reading table data'
                        
                # Look for forensic artifacts
                db_results['forensic_artifacts'] = self._identify_sqlite_artifacts(cursor, db_results['tables'])
                
                conn.close()
                os.unlink(temp_file.name)
                
        except Exception as e:
            logging.error(f"SQLite analysis failed: {str(e)}")
            db_results['error'] = str(e)
            
        return db_results
        
    def extract_with_dd(self, source_file, offset=0, count=None, block_size=512):
        """
        Extract data using dd utility.
        """
        dd_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool': 'dd',
            'parameters': {
                'offset': offset,
                'count': count,
                'block_size': block_size
            },
            'extracted_size': 0,
            'extracted_data': None
        }
        
        if not self.available_tools.get('dd', {}).get('available'):
            dd_results['error'] = 'dd utility not available'
            return dd_results
            
        try:
            with tempfile.NamedTemporaryFile(delete=False) as input_file:
                with tempfile.NamedTemporaryFile(delete=False) as output_file:
                    if hasattr(source_file, 'read'):
                        input_file.write(source_file.read())
                        source_file.seek(0)
                    else:
                        with open(source_file, 'rb') as f:
                            input_file.write(f.read())
                    input_file.flush()
                    
                    # Build dd command
                    cmd = [self.tool_paths['dd'], f'if={input_file.name}', f'of={output_file.name}']
                    
                    if offset > 0:
                        cmd.append(f'skip={offset // block_size}')
                    if count:
                        cmd.append(f'count={count}')
                    cmd.append(f'bs={block_size}')
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        with open(output_file.name, 'rb') as f:
                            extracted_data = f.read()
                        dd_results['extracted_size'] = len(extracted_data)
                        dd_results['extracted_data'] = extracted_data
                        dd_results['dd_output'] = result.stderr  # dd outputs stats to stderr
                    else:
                        dd_results['error'] = f"dd command failed: {result.stderr}"
                        
                    os.unlink(input_file.name)
                    os.unlink(output_file.name)
                    
        except Exception as e:
            logging.error(f"DD extraction failed: {str(e)}")
            dd_results['error'] = str(e)
            
        return dd_results
        
    def run_custom_forensic_script(self, script_content, file_data, script_type='python'):
        """
        Run custom forensic analysis scripts.
        """
        script_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'script_type': script_type,
            'execution_time': 0,
            'output': '',
            'error': '',
            'return_code': 0
        }
        
        if script_type == 'python' and not self.available_tools.get('python3', {}).get('available'):
            script_results['error'] = 'Python3 not available'
            return script_results
            
        try:
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=f'.{script_type}') as script_file:
                with tempfile.NamedTemporaryFile(delete=False) as data_file:
                    # Write script content
                    script_file.write(script_content)
                    script_file.flush()
                    
                    # Write data file
                    if hasattr(file_data, 'read'):
                        data_file.write(file_data.read())
                        file_data.seek(0)
                    else:
                        with open(file_data, 'rb') as f:
                            data_file.write(f.read())
                    data_file.flush()
                    
                    # Run script
                    start_time = datetime.now()
                    
                    if script_type == 'python':
                        cmd = [self.tool_paths['python3'], script_file.name, data_file.name]
                    else:
                        script_results['error'] = f'Unsupported script type: {script_type}'
                        return script_results
                        
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    
                    end_time = datetime.now()
                    script_results['execution_time'] = (end_time - start_time).total_seconds()
                    script_results['output'] = result.stdout
                    script_results['error'] = result.stderr
                    script_results['return_code'] = result.returncode
                    
                    os.unlink(script_file.name)
                    os.unlink(data_file.name)
                    
        except Exception as e:
            logging.error(f"Script execution failed: {str(e)}")
            script_results['error'] = str(e)
            
        return script_results
        
    def _analyze_suspicious_strings(self, strings_list):
        """Analyze strings for suspicious content."""
        suspicious_patterns = [
            'password', 'admin', 'backdoor', 'keylog', 'virus', 'malware',
            'trojan', 'rootkit', 'inject', 'exploit', 'cmd.exe', 'powershell',
            'registry', 'mutex', 'CreateRemoteThread', 'VirtualAlloc',
            'WriteProcessMemory', 'SetWindowsHook', 'GetProcAddress'
        ]
        
        suspicious_strings = []
        for string in strings_list:
            for pattern in suspicious_patterns:
                if pattern.lower() in string.lower():
                    suspicious_strings.append({
                        'string': string,
                        'pattern': pattern,
                        'severity': 'high' if pattern in ['backdoor', 'keylog', 'virus', 'malware', 'trojan', 'rootkit'] else 'medium'
                    })
                    break
                    
        return suspicious_strings
        
    def _analyze_strings_output(self, strings_list):
        """Analyze strings output for patterns."""
        analysis = {
            'total_strings': len(strings_list),
            'average_length': sum(len(s) for s in strings_list) / len(strings_list) if strings_list else 0,
            'url_patterns': [],
            'file_paths': [],
            'registry_keys': [],
            'suspicious_count': 0
        }
        
        for string in strings_list:
            # URL patterns
            if 'http://' in string or 'https://' in string:
                analysis['url_patterns'].append(string)
                
            # File paths
            if '\\' in string and (':' in string or string.startswith('\\\\')):
                analysis['file_paths'].append(string)
                
            # Registry keys
            if 'HKEY_' in string or 'HKLM\\' in string or 'HKCU\\' in string:
                analysis['registry_keys'].append(string)
                
        return analysis
        
    def _parse_file_type(self, file_output):
        """Parse file command output to extract file type."""
        output = file_output.lower()
        
        if 'pe32' in output or 'executable' in output:
            return 'PE Executable'
        elif 'elf' in output:
            return 'ELF Executable'
        elif 'jpeg' in output or 'jpg' in output:
            return 'JPEG Image'
        elif 'png' in output:
            return 'PNG Image'
        elif 'pdf' in output:
            return 'PDF Document'
        elif 'zip' in output:
            return 'ZIP Archive'
        elif 'ascii' in output or 'text' in output:
            return 'Text File'
        else:
            return 'Unknown'
            
    def _analyze_hexdump_output(self, content):
        """Analyze hexdump output for patterns."""
        analysis = {
            'null_bytes': content.count(b'\x00'),
            'high_entropy_regions': [],
            'repeating_patterns': [],
            'ascii_percentage': 0
        }
        
        # Calculate ASCII percentage
        printable_count = sum(1 for byte in content if 32 <= byte <= 126)
        analysis['ascii_percentage'] = (printable_count / len(content)) * 100 if content else 0
        
        # Look for repeating patterns
        for i in range(0, len(content) - 4, 4):
            chunk = content[i:i+4]
            if len(set(chunk)) == 1:  # All bytes are the same
                analysis['repeating_patterns'].append({
                    'offset': i,
                    'pattern': chunk.hex(),
                    'length': 4
                })
                
        return analysis
        
    def _calculate_hash_python(self, content, algorithm):
        """Calculate hash using Python hashlib as fallback."""
        if algorithm == 'md5':
            return hashlib.md5(content).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(content).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(content).hexdigest()
        else:
            return 'unsupported_algorithm'
            
    def _identify_sqlite_artifacts(self, cursor, tables):
        """Identify forensic artifacts in SQLite database."""
        artifacts = []
        
        # Common forensic tables
        forensic_tables = [
            'downloads', 'history', 'cookies', 'visits', 'urls',
            'bookmarks', 'search_terms', 'logins', 'passwords',
            'cache', 'preferences', 'extensions', 'sessions'
        ]
        
        for table in tables:
            table_lower = table.lower()
            for forensic_table in forensic_tables:
                if forensic_table in table_lower:
                    artifacts.append({
                        'table': table,
                        'type': forensic_table,
                        'description': f'Potential {forensic_table} data',
                        'forensic_value': 'high'
                    })
                    
        # Check for browser artifacts
        if any('url' in table.lower() for table in tables):
            artifacts.append({
                'artifact_type': 'browser_history',
                'description': 'Browser history artifacts detected',
                'tables_involved': [t for t in tables if 'url' in t.lower()]
            })
            
        return artifacts
        
    def get_available_tools(self):
        """Get list of available forensic tools."""
        return self.available_tools
        
    def get_tool_info(self, tool_name):
        """Get information about a specific tool."""
        return self.available_tools.get(tool_name, {'available': False})
