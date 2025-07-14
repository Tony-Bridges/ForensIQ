"""
Post-Quantum & Cryptographic Intelligence - Quantum Contingency Core
Quantum readiness scanning, PQC validation, and future-proofing capabilities.
"""
import json
import hashlib
from datetime import datetime
import logging
import re
from collections import defaultdict

class QuantumContingencyCore:
    def __init__(self):
        self.weak_crypto_patterns = self._load_weak_crypto_patterns()
        self.pqc_algorithms = self._load_pqc_algorithms()
        self.quantum_indicators = self._load_quantum_indicators()
        
    def scan_quantum_readiness(self, system_data, scan_depth='standard'):
        """
        Scan system for quantum readiness and weak cryptography.
        
        Args:
            system_data: System data to analyze
            scan_depth: 'quick', 'standard', or 'deep'
            
        Returns:
            dict: Quantum readiness assessment
        """
        readiness_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'scan_depth': scan_depth,
            'quantum_vulnerability_score': 0,
            'weak_cryptography': [],
            'pqc_readiness': {},
            'migration_recommendations': [],
            'timeline_assessment': {},
            'risk_categories': {},
            'compliance_status': {}
        }
        
        try:
            # Scan for weak cryptography
            weak_crypto = self._scan_weak_cryptography(system_data, scan_depth)
            readiness_results['weak_cryptography'] = weak_crypto
            
            # Assess PQC readiness
            pqc_readiness = self._assess_pqc_readiness(system_data)
            readiness_results['pqc_readiness'] = pqc_readiness
            
            # Generate migration recommendations
            recommendations = self._generate_migration_recommendations(weak_crypto, pqc_readiness)
            readiness_results['migration_recommendations'] = recommendations
            
            # Assess migration timeline
            timeline = self._assess_migration_timeline(weak_crypto, system_data)
            readiness_results['timeline_assessment'] = timeline
            
            # Calculate vulnerability score
            vuln_score = self._calculate_quantum_vulnerability_score(weak_crypto, pqc_readiness)
            readiness_results['quantum_vulnerability_score'] = vuln_score
            
            # Categorize risks
            risk_categories = self._categorize_quantum_risks(weak_crypto)
            readiness_results['risk_categories'] = risk_categories
            
            # Check compliance status
            compliance = self._check_quantum_compliance(weak_crypto, pqc_readiness)
            readiness_results['compliance_status'] = compliance
            
        except Exception as e:
            logging.error(f"Quantum readiness scan failed: {str(e)}")
            readiness_results['error'] = str(e)
            
        return readiness_results
        
    def validate_pqc_signatures(self, evidence_data, validation_options=None):
        """
        Validate evidence integrity using post-quantum cryptographic schemes.
        
        Args:
            evidence_data: Evidence data to validate
            validation_options: Validation configuration
            
        Returns:
            dict: PQC validation results
        """
        if validation_options is None:
            validation_options = {
                'algorithms': ['Dilithium', 'Falcon', 'SPHINCS+'],
                'validate_chain': True,
                'verify_timestamps': True
            }
            
        validation_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'evidence_id': evidence_data.get('id', 'unknown'),
            'pqc_signatures': [],
            'validation_status': 'unknown',
            'algorithm_support': {},
            'signature_chains': [],
            'integrity_verification': {},
            'quantum_resistance_level': 'unknown'
        }
        
        try:
            # Extract PQC signatures
            pqc_signatures = self._extract_pqc_signatures(evidence_data)
            validation_results['pqc_signatures'] = pqc_signatures
            
            # Validate each signature
            for signature in pqc_signatures:
                validation = self._validate_pqc_signature(signature, validation_options)
                validation_results['signature_chains'].append(validation)
                
            # Check algorithm support
            algorithm_support = self._check_algorithm_support(pqc_signatures, validation_options['algorithms'])
            validation_results['algorithm_support'] = algorithm_support
            
            # Verify integrity
            integrity = self._verify_evidence_integrity(evidence_data, pqc_signatures)
            validation_results['integrity_verification'] = integrity
            
            # Assess quantum resistance
            resistance_level = self._assess_quantum_resistance(pqc_signatures)
            validation_results['quantum_resistance_level'] = resistance_level
            
            # Determine overall validation status
            validation_results['validation_status'] = self._determine_validation_status(validation_results)
            
        except Exception as e:
            logging.error(f"PQC signature validation failed: {str(e)}")
            validation_results['error'] = str(e)
            
        return validation_results
        
    def detect_quantum_artifacts(self, computational_data, detection_sensitivity='medium'):
        """
        Detect early quantum computing artifacts and patterns.
        
        Args:
            computational_data: Computational activity data
            detection_sensitivity: 'low', 'medium', or 'high'
            
        Returns:
            dict: Quantum artifact detection results
        """
        detection_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'detection_sensitivity': detection_sensitivity,
            'quantum_indicators': [],
            'timing_anomalies': [],
            'computational_patterns': {},
            'noise_analysis': {},
            'quantum_probability': 0.0,
            'artifact_categories': {}
        }
        
        try:
            # Analyze timing patterns
            timing_anomalies = self._analyze_quantum_timing(computational_data, detection_sensitivity)
            detection_results['timing_anomalies'] = timing_anomalies
            
            # Detect computational patterns
            comp_patterns = self._detect_quantum_computational_patterns(computational_data)
            detection_results['computational_patterns'] = comp_patterns
            
            # Analyze quantum noise
            noise_analysis = self._analyze_quantum_noise(computational_data)
            detection_results['noise_analysis'] = noise_analysis
            
            # Identify quantum indicators
            indicators = self._identify_quantum_indicators(timing_anomalies, comp_patterns, noise_analysis)
            detection_results['quantum_indicators'] = indicators
            
            # Calculate quantum probability
            quantum_prob = self._calculate_quantum_probability(detection_results)
            detection_results['quantum_probability'] = quantum_prob
            
            # Categorize artifacts
            categories = self._categorize_quantum_artifacts(indicators)
            detection_results['artifact_categories'] = categories
            
        except Exception as e:
            logging.error(f"Quantum artifact detection failed: {str(e)}")
            detection_results['error'] = str(e)
            
        return detection_results
        
    def generate_pqc_migration_plan(self, current_crypto_inventory, target_security_level='NIST_Level_3'):
        """
        Generate comprehensive PQC migration plan.
        
        Args:
            current_crypto_inventory: Current cryptographic inventory
            target_security_level: Target PQC security level
            
        Returns:
            dict: PQC migration plan
        """
        migration_plan = {
            'timestamp': datetime.utcnow().isoformat(),
            'target_security_level': target_security_level,
            'migration_phases': [],
            'algorithm_mappings': {},
            'priority_recommendations': [],
            'resource_requirements': {},
            'timeline_estimate': {},
            'risk_mitigation': [],
            'compliance_considerations': []
        }
        
        try:
            # Analyze current inventory
            inventory_analysis = self._analyze_crypto_inventory(current_crypto_inventory)
            
            # Create algorithm mappings
            algorithm_mappings = self._create_pqc_mappings(inventory_analysis, target_security_level)
            migration_plan['algorithm_mappings'] = algorithm_mappings
            
            # Generate migration phases
            phases = self._generate_migration_phases(inventory_analysis, algorithm_mappings)
            migration_plan['migration_phases'] = phases
            
            # Prioritize recommendations
            priorities = self._prioritize_migration_recommendations(inventory_analysis)
            migration_plan['priority_recommendations'] = priorities
            
            # Estimate resources
            resources = self._estimate_migration_resources(phases, algorithm_mappings)
            migration_plan['resource_requirements'] = resources
            
            # Estimate timeline
            timeline = self._estimate_migration_timeline(phases, resources)
            migration_plan['timeline_estimate'] = timeline
            
            # Generate risk mitigation strategies
            risk_mitigation = self._generate_risk_mitigation_strategies(inventory_analysis)
            migration_plan['risk_mitigation'] = risk_mitigation
            
            # Consider compliance requirements
            compliance = self._consider_compliance_requirements(target_security_level)
            migration_plan['compliance_considerations'] = compliance
            
        except Exception as e:
            logging.error(f"PQC migration plan generation failed: {str(e)}")
            migration_plan['error'] = str(e)
            
        return migration_plan
        
    def _load_weak_crypto_patterns(self):
        """Load patterns for identifying weak cryptography."""
        return {
            'symmetric': {
                'weak': ['DES', '3DES', 'RC4', 'MD5', 'SHA1'],
                'deprecated': ['AES-128-ECB', 'AES-128-CBC'],
                'quantum_vulnerable': ['AES-128', 'AES-192', 'AES-256']
            },
            'asymmetric': {
                'weak': ['RSA-1024', 'DSA-1024', 'ECDSA-P192'],
                'deprecated': ['RSA-2048', 'DSA-2048', 'ECDSA-P256'],
                'quantum_vulnerable': ['RSA-4096', 'ECDSA-P384', 'ECDSA-P521']
            },
            'hashing': {
                'weak': ['MD5', 'SHA1'],
                'deprecated': ['SHA2-224'],
                'quantum_vulnerable': ['SHA2-256', 'SHA2-384', 'SHA2-512']
            }
        }
        
    def _load_pqc_algorithms(self):
        """Load post-quantum cryptographic algorithms."""
        return {
            'signatures': {
                'Dilithium': {
                    'security_levels': ['Dilithium2', 'Dilithium3', 'Dilithium5'],
                    'nist_level': [2, 3, 5],
                    'key_size': ['2592', '4000', '4864'],
                    'signature_size': ['2420', '3293', '4595']
                },
                'Falcon': {
                    'security_levels': ['Falcon-512', 'Falcon-1024'],
                    'nist_level': [1, 5],
                    'key_size': ['1281', '2305'],
                    'signature_size': ['690', '1330']
                },
                'SPHINCS+': {
                    'security_levels': ['SPHINCS+-128s', 'SPHINCS+-192s', 'SPHINCS+-256s'],
                    'nist_level': [1, 3, 5],
                    'key_size': ['32', '48', '64'],
                    'signature_size': ['7856', '16224', '29792']
                }
            },
            'kem': {
                'Kyber': {
                    'security_levels': ['Kyber512', 'Kyber768', 'Kyber1024'],
                    'nist_level': [1, 3, 5],
                    'public_key_size': ['800', '1184', '1568'],
                    'ciphertext_size': ['768', '1088', '1568']
                },
                'NTRU': {
                    'security_levels': ['NTRU-HPS-2048-509', 'NTRU-HPS-2048-677', 'NTRU-HRSS-701'],
                    'nist_level': [1, 3, 3],
                    'public_key_size': ['699', '930', '1138'],
                    'ciphertext_size': ['699', '930', '1138']
                }
            }
        }
        
    def _scan_weak_cryptography(self, system_data, scan_depth):
        """Scan for weak cryptographic implementations."""
        weak_crypto_findings = []
        
        # Scan certificates
        certificates = system_data.get('certificates', [])
        for cert in certificates:
            algorithm = cert.get('signature_algorithm', '').upper()
            key_size = cert.get('key_size', 0)
            
            # Check for weak algorithms
            if 'SHA1' in algorithm or 'MD5' in algorithm:
                weak_crypto_findings.append({
                    'type': 'weak_certificate',
                    'location': cert.get('location', 'unknown'),
                    'algorithm': algorithm,
                    'weakness': 'Cryptographically broken hash function',
                    'severity': 'critical',
                    'quantum_vulnerable': True
                })
                
            # Check for small key sizes
            if 'RSA' in algorithm and key_size < 2048:
                weak_crypto_findings.append({
                    'type': 'weak_key_size',
                    'location': cert.get('location', 'unknown'),
                    'algorithm': f'RSA-{key_size}',
                    'weakness': 'Insufficient key size',
                    'severity': 'high',
                    'quantum_vulnerable': True
                })
                
        # Scan TLS configurations
        tls_configs = system_data.get('tls_configurations', [])
        for config in tls_configs:
            cipher_suites = config.get('cipher_suites', [])
            for cipher in cipher_suites:
                if any(weak in cipher.upper() for weak in ['RC4', '3DES', 'DES', 'MD5']):
                    weak_crypto_findings.append({
                        'type': 'weak_cipher_suite',
                        'location': config.get('service', 'unknown'),
                        'cipher_suite': cipher,
                        'weakness': 'Weak or broken cipher',
                        'severity': 'high',
                        'quantum_vulnerable': True
                    })
                    
        # Scan application cryptography
        if scan_depth in ['standard', 'deep']:
            applications = system_data.get('applications', [])
            for app in applications:
                crypto_libs = app.get('crypto_libraries', [])
                for lib in crypto_libs:
                    if lib.get('algorithm') in ['MD5', 'SHA1', 'DES', '3DES']:
                        weak_crypto_findings.append({
                            'type': 'weak_application_crypto',
                            'location': f"{app.get('name', 'unknown')} - {lib.get('component', 'unknown')}",
                            'algorithm': lib.get('algorithm'),
                            'weakness': 'Deprecated cryptographic algorithm',
                            'severity': 'medium',
                            'quantum_vulnerable': True
                        })
                        
        return weak_crypto_findings
        
    def _assess_pqc_readiness(self, system_data):
        """Assess post-quantum cryptography readiness."""
        return {
            'current_pqc_implementations': self._find_pqc_implementations(system_data),
            'pqc_library_support': self._check_pqc_library_support(system_data),
            'hardware_compatibility': self._assess_hardware_compatibility(system_data),
            'readiness_score': self._calculate_pqc_readiness_score(system_data),
            'migration_barriers': self._identify_migration_barriers(system_data)
        }
        
    def _find_pqc_implementations(self, system_data):
        """Find existing PQC implementations in the system."""
        pqc_implementations = []
        
        # Check for PQC libraries
        libraries = system_data.get('installed_libraries', [])
        pqc_library_names = ['liboqs', 'pqcrypto', 'kyber', 'dilithium', 'falcon', 'sphincs']
        
        for lib in libraries:
            lib_name = lib.get('name', '').lower()
            if any(pqc_lib in lib_name for pqc_lib in pqc_library_names):
                pqc_implementations.append({
                    'type': 'library',
                    'name': lib.get('name'),
                    'version': lib.get('version'),
                    'algorithms': self._detect_pqc_algorithms(lib_name),
                    'status': 'active'
                })
                
        # Check for PQC certificates
        certificates = system_data.get('certificates', [])
        for cert in certificates:
            algorithm = cert.get('signature_algorithm', '').lower()
            if any(pqc_alg in algorithm for pqc_alg in ['dilithium', 'falcon', 'sphincs']):
                pqc_implementations.append({
                    'type': 'certificate',
                    'algorithm': cert.get('signature_algorithm'),
                    'location': cert.get('location'),
                    'expiry': cert.get('expiry_date'),
                    'status': 'deployed'
                })
                
        return pqc_implementations
        
    def _generate_migration_phases(self, inventory_analysis, algorithm_mappings):
        """Generate phased migration plan."""
        phases = []
        
        # Phase 1: Critical Infrastructure
        phase1 = {
            'phase': 1,
            'name': 'Critical Infrastructure Migration',
            'duration': '6-12 months',
            'priority': 'critical',
            'targets': [
                'Root CA certificates',
                'Core authentication systems',
                'High-value data encryption'
            ],
            'algorithms': ['Dilithium3', 'Kyber768'],
            'success_criteria': [
                'All critical certificates migrated',
                'Authentication systems PQC-enabled',
                'No quantum-vulnerable critical assets'
            ]
        }
        phases.append(phase1)
        
        # Phase 2: Enterprise Applications
        phase2 = {
            'phase': 2,
            'name': 'Enterprise Application Migration',
            'duration': '12-18 months',
            'priority': 'high',
            'targets': [
                'Application-level encryption',
                'Database encryption',
                'API security'
            ],
            'algorithms': ['Dilithium2', 'Kyber512', 'SPHINCS+-128s'],
            'success_criteria': [
                'All enterprise apps migrated',
                'Database encryption updated',
                'API endpoints secured'
            ]
        }
        phases.append(phase2)
        
        # Phase 3: Legacy System Updates
        phase3 = {
            'phase': 3,
            'name': 'Legacy System Modernization',
            'duration': '18-24 months',
            'priority': 'medium',
            'targets': [
                'Legacy applications',
                'Embedded systems',
                'IoT devices'
            ],
            'algorithms': ['Falcon-512', 'NTRU-HPS-2048-509'],
            'success_criteria': [
                'Legacy systems assessed',
                'Migration plan for IoT devices',
                'Embedded system updates'
            ]
        }
        phases.append(phase3)
        
        return phases