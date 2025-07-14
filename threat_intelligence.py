"""
Threat Intelligence Integration Module
YARA rules, VirusTotal, MISP, and custom threat feed integration.
"""
import json
import hashlib
from datetime import datetime
import logging
import re

class ThreatIntelligence:
    def __init__(self):
        self.threat_feeds = ['virustotal', 'misp', 'alienvault', 'emergingthreats']
        self.yara_rule_categories = ['malware', 'apt', 'pua', 'exploit', 'custom']
        self.ioc_types = ['hash', 'domain', 'ip', 'url', 'email', 'registry', 'mutex']
        
    def check_threat_intelligence(self, indicators, threat_sources=None):
        """
        Check indicators against threat intelligence sources.
        
        Args:
            indicators: List of indicators to check
            threat_sources: List of threat intelligence sources to query
            
        Returns:
            dict: Threat intelligence results
        """
        if threat_sources is None:
            threat_sources = ['virustotal', 'misp', 'yara_rules']
            
        ti_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'indicators_checked': len(indicators),
            'threat_matches': [],
            'reputation_scores': {},
            'malware_families': {},
            'apt_attribution': {},
            'campaign_matches': [],
            'risk_assessment': {},
            'recommendations': []
        }
        
        try:
            for indicator in indicators:
                indicator_results = {
                    'indicator': indicator,
                    'type': self._determine_indicator_type(indicator),
                    'threat_matches': [],
                    'reputation_score': 0,
                    'first_seen': None,
                    'last_seen': None,
                    'confidence': 0
                }
                
                # Check against each threat source
                for source in threat_sources:
                    if source == 'virustotal':
                        vt_result = self._check_virustotal(indicator)
                        if vt_result:
                            indicator_results['threat_matches'].append(vt_result)
                            
                    elif source == 'misp':
                        misp_result = self._check_misp(indicator)
                        if misp_result:
                            indicator_results['threat_matches'].append(misp_result)
                            
                    elif source == 'yara_rules':
                        yara_result = self._check_yara_rules(indicator)
                        if yara_result:
                            indicator_results['threat_matches'].append(yara_result)
                            
                # Calculate overall reputation score
                indicator_results['reputation_score'] = self._calculate_reputation_score(
                    indicator_results['threat_matches']
                )
                
                ti_results['threat_matches'].append(indicator_results)
                
            # Aggregate results
            ti_results['reputation_scores'] = self._aggregate_reputation_scores(
                ti_results['threat_matches']
            )
            ti_results['malware_families'] = self._identify_malware_families(
                ti_results['threat_matches']
            )
            ti_results['apt_attribution'] = self._perform_apt_attribution(
                ti_results['threat_matches']
            )
            ti_results['campaign_matches'] = self._identify_campaign_matches(
                ti_results['threat_matches']
            )
            ti_results['risk_assessment'] = self._assess_overall_risk(ti_results)
            ti_results['recommendations'] = self._generate_recommendations(ti_results)
            
        except Exception as e:
            logging.error(f"Threat intelligence check failed: {str(e)}")
            ti_results['error'] = str(e)
            
        return ti_results
        
    def scan_with_yara_rules(self, file_data, rule_categories=None):
        """
        Scan file with YARA rules.
        
        Args:
            file_data: File data to scan
            rule_categories: Categories of YARA rules to use
            
        Returns:
            dict: YARA scan results
        """
        if rule_categories is None:
            rule_categories = ['malware', 'apt', 'pua']
            
        yara_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'file_info': {},
            'rule_matches': [],
            'malware_detected': False,
            'threat_classification': {},
            'confidence_score': 0,
            'rule_categories_used': rule_categories
        }
        
        try:
            # Get file information
            if hasattr(file_data, 'read'):
                file_content = file_data.read()
                file_data.seek(0)
            else:
                with open(file_data, 'rb') as f:
                    file_content = f.read()
                    
            yara_results['file_info'] = {
                'size': len(file_content),
                'md5': hashlib.md5(file_content).hexdigest(),
                'sha256': hashlib.sha256(file_content).hexdigest()
            }
            
            # Scan with YARA rules for each category
            for category in rule_categories:
                category_matches = self._scan_yara_category(file_content, category)
                yara_results['rule_matches'].extend(category_matches)
                
            # Analyze results
            if yara_results['rule_matches']:
                yara_results['malware_detected'] = True
                yara_results['threat_classification'] = self._classify_yara_threats(
                    yara_results['rule_matches']
                )
                yara_results['confidence_score'] = self._calculate_yara_confidence(
                    yara_results['rule_matches']
                )
                
        except Exception as e:
            logging.error(f"YARA scan failed: {str(e)}")
            yara_results['error'] = str(e)
            
        return yara_results
        
    def create_custom_indicators(self, analysis_data, indicator_types=None):
        """
        Create custom threat indicators from analysis data.
        
        Args:
            analysis_data: Forensic analysis data
            indicator_types: Types of indicators to create
            
        Returns:
            dict: Custom indicators created
        """
        if indicator_types is None:
            indicator_types = ['file_hash', 'network', 'registry', 'behavior']
            
        custom_indicators = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_analysis': 'forensic_investigation',
            'indicators': [],
            'ioc_count': 0,
            'confidence_levels': {},
            'sharing_recommendations': {}
        }
        
        try:
            # Extract file hash indicators
            if 'file_hash' in indicator_types:
                hash_indicators = self._extract_hash_indicators(analysis_data)
                custom_indicators['indicators'].extend(hash_indicators)
                
            # Extract network indicators
            if 'network' in indicator_types:
                network_indicators = self._extract_network_indicators(analysis_data)
                custom_indicators['indicators'].extend(network_indicators)
                
            # Extract registry indicators
            if 'registry' in indicator_types:
                registry_indicators = self._extract_registry_indicators(analysis_data)
                custom_indicators['indicators'].extend(registry_indicators)
                
            # Extract behavioral indicators
            if 'behavior' in indicator_types:
                behavior_indicators = self._extract_behavior_indicators(analysis_data)
                custom_indicators['indicators'].extend(behavior_indicators)
                
            custom_indicators['ioc_count'] = len(custom_indicators['indicators'])
            
            # Assess confidence levels
            custom_indicators['confidence_levels'] = self._assess_indicator_confidence(
                custom_indicators['indicators']
            )
            
            # Generate sharing recommendations
            custom_indicators['sharing_recommendations'] = self._generate_sharing_recommendations(
                custom_indicators['indicators']
            )
            
        except Exception as e:
            logging.error(f"Custom indicator creation failed: {str(e)}")
            custom_indicators['error'] = str(e)
            
        return custom_indicators
        
    def _determine_indicator_type(self, indicator):
        """Determine the type of indicator."""
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return 'md5_hash'
        elif re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return 'sha256_hash'
        elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', indicator):
            return 'ip_address'
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', indicator):
            return 'domain'
        elif indicator.startswith('http'):
            return 'url'
        elif '@' in indicator:
            return 'email'
        elif '\\' in indicator and ('HKLM' in indicator or 'HKCU' in indicator):
            return 'registry_key'
        else:
            return 'unknown'
            
    def _check_virustotal(self, indicator):
        """Check indicator against VirusTotal (simulated)."""
        # Simulated VirusTotal response
        if self._determine_indicator_type(indicator) in ['md5_hash', 'sha256_hash']:
            return {
                'source': 'virustotal',
                'detections': 45,
                'total_engines': 70,
                'detection_ratio': '45/70',
                'malware_names': ['Trojan.Generic', 'Backdoor.Agent', 'Malware.Suspicious'],
                'first_submission': '2024-01-10T08:30:00Z',
                'last_analysis': '2024-01-15T12:00:00Z',
                'reputation_score': 85,
                'community_score': -5
            }
        elif self._determine_indicator_type(indicator) == 'domain':
            return {
                'source': 'virustotal',
                'category': 'malicious',
                'detections': 12,
                'total_engines': 25,
                'detection_ratio': '12/25',
                'malware_families': ['Banker', 'Phishing'],
                'first_seen': '2024-01-05T10:00:00Z',
                'last_seen': '2024-01-15T18:30:00Z',
                'reputation_score': 75
            }
        return None
        
    def _check_misp(self, indicator):
        """Check indicator against MISP (simulated)."""
        # Simulated MISP response
        return {
            'source': 'misp',
            'event_id': 'MISP-2024-001',
            'threat_level': 'high',
            'analysis_level': 'completed',
            'categories': ['payload_delivery', 'command_and_control'],
            'tags': ['apt29', 'cozy_bear', 'targeted_attack'],
            'first_seen': '2024-01-08T14:20:00Z',
            'confidence': 85,
            'sharing_group': 'cybersec_consortium'
        }
        
    def _check_yara_rules(self, indicator):
        """Check indicator against YARA rules (simulated)."""
        # Simulated YARA rule match
        return {
            'source': 'yara_rules',
            'rule_name': 'APT_Generic_Backdoor',
            'rule_author': 'Threat Research Team',
            'rule_description': 'Detects generic APT backdoor characteristics',
            'rule_category': 'apt',
            'confidence': 90,
            'strings_matched': ['$str1', '$str2', '$hex1'],
            'rule_version': '1.2',
            'last_updated': '2024-01-10T00:00:00Z'
        }
        
    def _calculate_reputation_score(self, threat_matches):
        """Calculate overall reputation score for an indicator."""
        if not threat_matches:
            return 0
            
        total_score = 0
        weight_sum = 0
        
        for match in threat_matches:
            if match['source'] == 'virustotal':
                score = match.get('reputation_score', 0)
                weight = 0.4
            elif match['source'] == 'misp':
                score = match.get('confidence', 0)
                weight = 0.3
            elif match['source'] == 'yara_rules':
                score = match.get('confidence', 0)
                weight = 0.3
            else:
                score = 50
                weight = 0.1
                
            total_score += score * weight
            weight_sum += weight
            
        return int(total_score / weight_sum) if weight_sum > 0 else 0
        
    def _scan_yara_category(self, file_content, category):
        """Simulate YARA rule scanning for a category."""
        # Simulated YARA matches based on category
        if category == 'malware':
            return [
                {
                    'rule_name': 'Generic_Trojan',
                    'category': 'malware',
                    'description': 'Generic trojan detection',
                    'strings_matched': ['$mz', '$pe', '$suspicious_api'],
                    'confidence': 75,
                    'severity': 'high'
                }
            ]
        elif category == 'apt':
            return [
                {
                    'rule_name': 'APT29_Cozy_Bear',
                    'category': 'apt',
                    'description': 'APT29 Cozy Bear indicators',
                    'strings_matched': ['$mutex', '$c2_domain'],
                    'confidence': 90,
                    'severity': 'critical'
                }
            ]
        elif category == 'pua':
            return [
                {
                    'rule_name': 'Potentially_Unwanted',
                    'category': 'pua',
                    'description': 'Potentially unwanted application',
                    'strings_matched': ['$adware', '$browser_hijack'],
                    'confidence': 60,
                    'severity': 'medium'
                }
            ]
        return []
        
    def _classify_yara_threats(self, rule_matches):
        """Classify threats based on YARA rule matches."""
        classification = {
            'primary_threat': 'unknown',
            'threat_family': 'unknown',
            'severity': 'low',
            'categories': [],
            'apt_groups': []
        }
        
        for match in rule_matches:
            category = match.get('category', 'unknown')
            classification['categories'].append(category)
            
            if category == 'apt':
                if 'APT29' in match.get('rule_name', ''):
                    classification['apt_groups'].append('APT29')
                    classification['primary_threat'] = 'advanced_persistent_threat'
                    classification['severity'] = 'critical'
            elif category == 'malware':
                classification['primary_threat'] = 'malware'
                classification['threat_family'] = 'trojan'
                classification['severity'] = 'high'
                
        return classification
        
    def _calculate_yara_confidence(self, rule_matches):
        """Calculate confidence score based on YARA matches."""
        if not rule_matches:
            return 0
            
        # Weight matches by severity and category
        total_confidence = 0
        total_weight = 0
        
        for match in rule_matches:
            confidence = match.get('confidence', 50)
            category = match.get('category', 'unknown')
            
            # Weight by category importance
            if category == 'apt':
                weight = 1.0
            elif category == 'malware':
                weight = 0.8
            elif category == 'pua':
                weight = 0.4
            else:
                weight = 0.2
                
            total_confidence += confidence * weight
            total_weight += weight
            
        return int(total_confidence / total_weight) if total_weight > 0 else 0
        
    def _extract_hash_indicators(self, analysis_data):
        """Extract file hash indicators from analysis data."""
        indicators = []
        
        # Extract from file analysis
        if 'file_analysis' in analysis_data:
            file_info = analysis_data['file_analysis']
            if 'sha256_hash' in file_info:
                indicators.append({
                    'type': 'sha256_hash',
                    'value': file_info['sha256_hash'],
                    'description': 'Malicious file hash',
                    'confidence': 'high',
                    'source': 'file_analysis'
                })
                
        return indicators
        
    def _extract_network_indicators(self, analysis_data):
        """Extract network indicators from analysis data."""
        indicators = []
        
        # Extract from network analysis
        if 'network_analysis' in analysis_data:
            network_data = analysis_data['network_analysis']
            for domain in network_data.get('suspicious_domains', []):
                indicators.append({
                    'type': 'domain',
                    'value': domain,
                    'description': 'Malicious C2 domain',
                    'confidence': 'medium',
                    'source': 'network_analysis'
                })
                
        return indicators
        
    def _extract_registry_indicators(self, analysis_data):
        """Extract registry indicators from analysis data."""
        indicators = []
        
        # Extract from registry analysis
        if 'registry_analysis' in analysis_data:
            reg_data = analysis_data['registry_analysis']
            for key in reg_data.get('suspicious_keys', []):
                indicators.append({
                    'type': 'registry_key',
                    'value': key,
                    'description': 'Malicious registry modification',
                    'confidence': 'medium',
                    'source': 'registry_analysis'
                })
                
        return indicators
        
    def _extract_behavior_indicators(self, analysis_data):
        """Extract behavioral indicators from analysis data."""
        indicators = []
        
        # Extract from behavioral analysis
        if 'behavioral_analysis' in analysis_data:
            behavior_data = analysis_data['behavioral_analysis']
            for mutex in behavior_data.get('mutexes', []):
                indicators.append({
                    'type': 'mutex',
                    'value': mutex,
                    'description': 'Malware mutex indicator',
                    'confidence': 'low',
                    'source': 'behavioral_analysis'
                })
                
        return indicators
        
    def _aggregate_reputation_scores(self, threat_matches):
        """Aggregate reputation scores across all indicators."""
        scores = {}
        for match in threat_matches:
            indicator = match['indicator']
            score = match['reputation_score']
            scores[indicator] = score
            
        return scores
        
    def _identify_malware_families(self, threat_matches):
        """Identify malware families from threat matches."""
        families = {}
        for match in threat_matches:
            for threat in match['threat_matches']:
                if 'malware_names' in threat:
                    for name in threat['malware_names']:
                        families[name] = families.get(name, 0) + 1
                        
        return families
        
    def _perform_apt_attribution(self, threat_matches):
        """Perform APT attribution analysis."""
        apt_groups = {}
        for match in threat_matches:
            for threat in match['threat_matches']:
                if 'tags' in threat:
                    for tag in threat['tags']:
                        if 'apt' in tag.lower():
                            apt_groups[tag] = apt_groups.get(tag, 0) + 1
                            
        return apt_groups
        
    def _identify_campaign_matches(self, threat_matches):
        """Identify campaign matches."""
        campaigns = []
        # Simulated campaign matching
        campaigns.append({
            'campaign_name': 'Operation Shadow Network',
            'confidence': 75,
            'indicators_matched': 3,
            'timeframe': '2024-Q1',
            'attribution': 'APT29'
        })
        return campaigns
        
    def _assess_overall_risk(self, ti_results):
        """Assess overall risk based on threat intelligence results."""
        risk_score = 0
        risk_factors = []
        
        # Factor in reputation scores
        avg_reputation = sum(ti_results['reputation_scores'].values()) / max(len(ti_results['reputation_scores']), 1)
        if avg_reputation > 70:
            risk_score += 40
            risk_factors.append('high_reputation_threat')
            
        # Factor in APT attribution
        if ti_results['apt_attribution']:
            risk_score += 30
            risk_factors.append('apt_attributed')
            
        # Factor in campaign matches
        if ti_results['campaign_matches']:
            risk_score += 20
            risk_factors.append('campaign_match')
            
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'critical'
        elif risk_score >= 60:
            risk_level = 'high'
        elif risk_score >= 40:
            risk_level = 'medium'
        elif risk_score >= 20:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
            
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }
        
    def _generate_recommendations(self, ti_results):
        """Generate recommendations based on threat intelligence."""
        recommendations = []
        
        risk_level = ti_results['risk_assessment']['risk_level']
        
        if risk_level in ['critical', 'high']:
            recommendations.extend([
                'Immediately isolate affected systems',
                'Activate incident response procedures',
                'Coordinate with threat intelligence team',
                'Consider external assistance from cybersecurity experts'
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                'Increase monitoring of affected systems',
                'Review and update security controls',
                'Conduct additional analysis of related indicators'
            ])
        else:
            recommendations.extend([
                'Continue monitoring for related activity',
                'Document findings for future reference'
            ])
            
        return recommendations