import logging
import json
import time
import threading
import hashlib
import psutil
import platform
import uuid
from datetime import datetime
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """Base class for forensic agents across different platforms"""
    
    def __init__(self, agent_id=None, server_url="ws://127.0.0.1:5000"):
        self.agent_id = agent_id or self._generate_agent_id()
        self.server_url = server_url
        self.platform = platform.system().lower()
        self.hostname = platform.node()
        self.running = False
        
        # Communication
        self.heartbeat_interval = 30  # seconds
        self.heartbeat_thread = None
        
        # Capabilities
        self.capabilities = self._get_capabilities()
        
        # Evidence collection
        self.evidence_queue = []
        self.collection_lock = threading.Lock()
        
    def _generate_agent_id(self):
        """Generate unique agent ID"""
        return f"{self.platform}_{uuid.uuid4().hex[:8]}"
    
    @abstractmethod
    def _get_capabilities(self):
        """Get platform-specific capabilities"""
        pass
    
    @abstractmethod
    def collect_memory_dump(self, output_path):
        """Collect memory dump"""
        pass
    
    @abstractmethod
    def hash_files(self, paths):
        """Hash files at specified paths"""
        pass
    
    @abstractmethod
    def collect_system_info(self):
        """Collect system information"""
        pass
    
    def start(self):
        """Start the agent"""
        self.running = True
        
        # Start heartbeat
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
        
        logger.info(f"Agent {self.agent_id} started on {self.platform}")
    
    def stop(self):
        """Stop the agent"""
        self.running = False
        
        if self.heartbeat_thread:
            self.heartbeat_thread.join()
        
        logger.info(f"Agent {self.agent_id} stopped")
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats to server"""
        while self.running:
            try:
                self._send_heartbeat()
                time.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    def _send_heartbeat(self):
        """Send heartbeat to server"""
        heartbeat_data = {
            'agent_id': self.agent_id,
            'timestamp': datetime.utcnow().isoformat(),
            'platform': self.platform,
            'hostname': self.hostname,
            'status': 'healthy',
            'system_metrics': self._get_system_metrics(),
            'capabilities': self.capabilities
        }
        
        # In production, this would use WebSocket or MQTT
        logger.debug(f"Heartbeat: {heartbeat_data}")
    
    def _get_system_metrics(self):
        """Get current system metrics"""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:').percent,
                'boot_time': psutil.boot_time(),
                'process_count': len(psutil.pids())
            }
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {}
    
    def execute_command(self, command, parameters=None):
        """Execute command from server"""
        parameters = parameters or {}
        
        try:
            if command == 'collect_memory':
                return self._handle_memory_collection(parameters)
            elif command == 'hash_files':
                return self._handle_file_hashing(parameters)
            elif command == 'system_info':
                return self._handle_system_info_collection()
            elif command == 'update_config':
                return self._handle_config_update(parameters)
            else:
                return {'error': f'Unknown command: {command}'}
                
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return {'error': str(e)}
    
    def _handle_memory_collection(self, parameters):
        """Handle memory collection command"""
        output_path = parameters.get('output_path', f'/tmp/memory_dump_{int(time.time())}.bin')
        
        try:
            # Simulate memory collection
            result = self.collect_memory_dump(output_path)
            
            # Create evidence record
            evidence = {
                'type': 'memory_dump',
                'file_path': output_path,
                'collected_at': datetime.utcnow().isoformat(),
                'agent_id': self.agent_id,
                'hash': self._calculate_file_hash(output_path),
                'size_bytes': self._get_file_size(output_path)
            }
            
            with self.collection_lock:
                self.evidence_queue.append(evidence)
            
            return {'success': True, 'evidence': evidence}
            
        except Exception as e:
            return {'error': f'Memory collection failed: {e}'}
    
    def _handle_file_hashing(self, parameters):
        """Handle file hashing command"""
        paths = parameters.get('paths', [])
        recursive = parameters.get('recursive', True)
        
        try:
            hash_results = self.hash_files(paths)
            
            # Create evidence records
            evidence_items = []
            for path, file_hash in hash_results.items():
                evidence = {
                    'type': 'file_hash',
                    'file_path': path,
                    'collected_at': datetime.utcnow().isoformat(),
                    'agent_id': self.agent_id,
                    'hash': file_hash,
                    'size_bytes': len(file_hash)
                }
                evidence_items.append(evidence)
            
            with self.collection_lock:
                self.evidence_queue.extend(evidence_items)
            
            return {'success': True, 'evidence_count': len(evidence_items)}
            
        except Exception as e:
            return {'error': f'File hashing failed: {e}'}
    
    def _handle_system_info_collection(self):
        """Handle system info collection"""
        try:
            system_info = self.collect_system_info()
            
            evidence = {
                'type': 'system_info',
                'collected_at': datetime.utcnow().isoformat(),
                'agent_id': self.agent_id,
                'data': system_info,
                'size_bytes': len(json.dumps(system_info))
            }
            
            with self.collection_lock:
                self.evidence_queue.append(evidence)
            
            return {'success': True, 'evidence': evidence}
            
        except Exception as e:
            return {'error': f'System info collection failed: {e}'}
    
    def _handle_config_update(self, parameters):
        """Handle configuration update"""
        try:
            config = parameters.get('config', {})
            
            if 'heartbeat_interval' in config:
                self.heartbeat_interval = config['heartbeat_interval']
            
            return {'success': True, 'message': 'Configuration updated'}
            
        except Exception as e:
            return {'error': f'Config update failed: {e}'}
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        try:
            # For simulation, return a mock hash
            return f"sha256:{hashlib.sha256(file_path.encode()).hexdigest()}"
        except Exception:
            return f"sha256:{uuid.uuid4().hex}"
    
    def _get_file_size(self, file_path):
        """Get file size"""
        try:
            # For simulation, return a mock size
            return hash(file_path) % 1000000 + 1024
        except Exception:
            return 1024
    
    def get_pending_evidence(self):
        """Get pending evidence for upload"""
        with self.collection_lock:
            evidence = self.evidence_queue.copy()
            self.evidence_queue.clear()
            return evidence
    
    def upload_evidence(self, evidence_items):
        """Upload evidence to server"""
        # In production, this would upload to secure storage
        for evidence in evidence_items:
            logger.info(f"Uploading evidence: {evidence['type']} - {evidence.get('file_path', 'N/A')}")
        
        return {'success': True, 'uploaded': len(evidence_items)}
