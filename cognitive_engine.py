"""
Hyper-Intelligent & Autonomous Analysis Core - The Cognitive Engine
Self-learning behavior models, explainable AI, hypothesis generation, and digital twin reconstruction.
"""
import json
import numpy as np
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import math
import random

class CognitiveEngine:
    def __init__(self):
        self.behavior_models = {}
        self.learning_thresholds = {}
        self.hypothesis_cache = {}
        self.digital_twins = {}
        self.explanation_graphs = {}
        
    def analyze_with_self_learning(self, system_data, entity_id="default"):
        """
        Perform analysis using self-learning behavior models.
        
        Args:
            system_data: System activity data
            entity_id: Entity identifier for personalized models
            
        Returns:
            dict: Analysis results with adaptive insights
        """
        analysis_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'entity_id': entity_id,
            'behavioral_profile': {},
            'anomaly_detection': {},
            'model_evolution': {},
            'adaptive_thresholds': {},
            'learning_confidence': 0.0,
            'behavioral_insights': []
        }
        
        try:
            # Initialize or load existing behavior model
            if entity_id not in self.behavior_models:
                self.behavior_models[entity_id] = self._initialize_behavior_model()
                
            # Update model with new data
            model_updates = self._update_behavior_model(entity_id, system_data)
            analysis_results['model_evolution'] = model_updates
            
            # Detect anomalies using adaptive thresholds
            anomalies = self._detect_adaptive_anomalies(entity_id, system_data)
            analysis_results['anomaly_detection'] = anomalies
            
            # Generate behavioral profile
            profile = self._generate_behavioral_profile(entity_id, system_data)
            analysis_results['behavioral_profile'] = profile
            
            # Calculate adaptive thresholds
            thresholds = self._calculate_adaptive_thresholds(entity_id)
            analysis_results['adaptive_thresholds'] = thresholds
            
            # Generate behavioral insights
            insights = self._generate_behavioral_insights(entity_id, system_data, anomalies)
            analysis_results['behavioral_insights'] = insights
            
            # Calculate learning confidence
            analysis_results['learning_confidence'] = self._calculate_learning_confidence(entity_id)
            
        except Exception as e:
            logging.error(f"Self-learning analysis failed: {str(e)}")
            analysis_results['error'] = str(e)
            
        return analysis_results
        
    def explain_detection(self, detection_event, context_data):
        """
        Provide explainable AI analysis for detection events.
        
        Args:
            detection_event: Event that triggered detection
            context_data: Contextual information
            
        Returns:
            dict: Explanation with causality and feature attribution
        """
        explanation = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_id': detection_event.get('id', 'unknown'),
            'causality_chain': [],
            'feature_attribution': {},
            'confidence_factors': {},
            'logical_trace': [],
            'alternative_scenarios': [],
            'explanation_score': 0.0
        }
        
        try:
            # Build causality chain
            explanation['causality_chain'] = self._build_causality_chain(detection_event, context_data)
            
            # Calculate feature attribution
            explanation['feature_attribution'] = self._calculate_feature_attribution(detection_event)
            
            # Generate logical trace
            explanation['logical_trace'] = self._generate_logical_trace(detection_event, context_data)
            
            # Identify confidence factors
            explanation['confidence_factors'] = self._identify_confidence_factors(detection_event)
            
            # Generate alternative scenarios
            explanation['alternative_scenarios'] = self._generate_alternative_scenarios(detection_event)
            
            # Calculate explanation score
            explanation['explanation_score'] = self._calculate_explanation_score(explanation)
            
        except Exception as e:
            logging.error(f"Explanation generation failed: {str(e)}")
            explanation['error'] = str(e)
            
        return explanation
        
    def generate_hypotheses(self, incident_data, scenario_types=None):
        """
        Generate and validate forensic hypotheses.
        
        Args:
            incident_data: Incident data for hypothesis generation
            scenario_types: Types of scenarios to consider
            
        Returns:
            dict: Generated hypotheses with validation scores
        """
        if scenario_types is None:
            scenario_types = ['insider_threat', 'ransomware', 'apt_infiltration', 'data_exfiltration']
            
        hypothesis_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'incident_id': incident_data.get('id', 'unknown'),
            'generated_hypotheses': [],
            'validation_scores': {},
            'scenario_rankings': {},
            'evidence_mapping': {},
            'confidence_matrix': {}
        }
        
        try:
            # Generate hypotheses for each scenario type
            for scenario in scenario_types:
                hypothesis = self._generate_scenario_hypothesis(incident_data, scenario)
                if hypothesis:
                    hypothesis_results['generated_hypotheses'].append(hypothesis)
                    
            # Validate hypotheses against evidence
            for hypothesis in hypothesis_results['generated_hypotheses']:
                validation_score = self._validate_hypothesis(hypothesis, incident_data)
                hypothesis_results['validation_scores'][hypothesis['id']] = validation_score
                
            # Rank scenarios by likelihood
            hypothesis_results['scenario_rankings'] = self._rank_scenarios(
                hypothesis_results['generated_hypotheses'],
                hypothesis_results['validation_scores']
            )
            
            # Map evidence to hypotheses
            hypothesis_results['evidence_mapping'] = self._map_evidence_to_hypotheses(
                incident_data,
                hypothesis_results['generated_hypotheses']
            )
            
            # Generate confidence matrix
            hypothesis_results['confidence_matrix'] = self._generate_confidence_matrix(
                hypothesis_results['generated_hypotheses']
            )
            
        except Exception as e:
            logging.error(f"Hypothesis generation failed: {str(e)}")
            hypothesis_results['error'] = str(e)
            
        return hypothesis_results
        
    def create_digital_twin(self, breach_data, twin_id=None):
        """
        Create digital twin for breach scenario reconstruction.
        
        Args:
            breach_data: Breach incident data
            twin_id: Identifier for the digital twin
            
        Returns:
            dict: Digital twin creation results
        """
        if twin_id is None:
            twin_id = f"twin_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
        twin_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'twin_id': twin_id,
            'reconstruction_timeline': [],
            'counterfactual_scenarios': [],
            'tool_interference_analysis': {},
            'replay_checkpoints': [],
            'simulation_parameters': {},
            'accuracy_metrics': {}
        }
        
        try:
            # Create baseline twin model
            twin_model = self._create_twin_model(breach_data)
            self.digital_twins[twin_id] = twin_model
            
            # Reconstruct breach timeline
            timeline = self._reconstruct_breach_timeline(breach_data)
            twin_results['reconstruction_timeline'] = timeline
            
            # Generate counterfactual scenarios
            counterfactuals = self._generate_counterfactual_scenarios(breach_data, twin_model)
            twin_results['counterfactual_scenarios'] = counterfactuals
            
            # Analyze tool interference impact
            interference = self._analyze_tool_interference(breach_data, twin_model)
            twin_results['tool_interference_analysis'] = interference
            
            # Create replay checkpoints
            checkpoints = self._create_replay_checkpoints(timeline)
            twin_results['replay_checkpoints'] = checkpoints
            
            # Set simulation parameters
            twin_results['simulation_parameters'] = self._get_simulation_parameters(twin_model)
            
            # Calculate accuracy metrics
            twin_results['accuracy_metrics'] = self._calculate_twin_accuracy(twin_model, breach_data)
            
        except Exception as e:
            logging.error(f"Digital twin creation failed: {str(e)}")
            twin_results['error'] = str(e)
            
        return twin_results
        
    def replay_scenario(self, twin_id, scenario_parameters):
        """
        Replay scenario using digital twin.
        
        Args:
            twin_id: Digital twin identifier
            scenario_parameters: Parameters for scenario replay
            
        Returns:
            dict: Replay results and insights
        """
        replay_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'twin_id': twin_id,
            'scenario_type': scenario_parameters.get('type', 'unknown'),
            'replay_timeline': [],
            'outcome_analysis': {},
            'deviation_points': [],
            'impact_assessment': {},
            'lessons_learned': []
        }
        
        try:
            if twin_id not in self.digital_twins:
                replay_results['error'] = f"Digital twin {twin_id} not found"
                return replay_results
                
            twin_model = self.digital_twins[twin_id]
            
            # Execute scenario replay
            timeline = self._execute_scenario_replay(twin_model, scenario_parameters)
            replay_results['replay_timeline'] = timeline
            
            # Analyze outcomes
            outcomes = self._analyze_replay_outcomes(timeline, scenario_parameters)
            replay_results['outcome_analysis'] = outcomes
            
            # Identify deviation points
            deviations = self._identify_deviation_points(timeline, twin_model)
            replay_results['deviation_points'] = deviations
            
            # Assess impact
            impact = self._assess_scenario_impact(outcomes, deviations)
            replay_results['impact_assessment'] = impact
            
            # Extract lessons learned
            lessons = self._extract_lessons_learned(replay_results)
            replay_results['lessons_learned'] = lessons
            
        except Exception as e:
            logging.error(f"Scenario replay failed: {str(e)}")
            replay_results['error'] = str(e)
            
        return replay_results
        
    def _initialize_behavior_model(self):
        """Initialize a new behavior model."""
        return {
            'baseline_metrics': {},
            'activity_patterns': {},
            'threshold_history': [],
            'learning_iterations': 0,
            'model_confidence': 0.0,
            'last_updated': datetime.utcnow().isoformat()
        }
        
    def _update_behavior_model(self, entity_id, system_data):
        """Update behavior model with new data."""
        model = self.behavior_models[entity_id]
        model['learning_iterations'] += 1
        
        # Update baseline metrics
        new_metrics = self._extract_baseline_metrics(system_data)
        if model['baseline_metrics']:
            # Adaptive learning with decay factor
            decay = 0.9
            for metric, value in new_metrics.items():
                if metric in model['baseline_metrics']:
                    model['baseline_metrics'][metric] = (
                        decay * model['baseline_metrics'][metric] + 
                        (1 - decay) * value
                    )
                else:
                    model['baseline_metrics'][metric] = value
        else:
            model['baseline_metrics'] = new_metrics
            
        # Update activity patterns
        patterns = self._extract_activity_patterns(system_data)
        model['activity_patterns'] = self._merge_patterns(
            model['activity_patterns'], 
            patterns
        )
        
        # Update model confidence
        model['model_confidence'] = min(0.95, model['learning_iterations'] / 100.0)
        model['last_updated'] = datetime.utcnow().isoformat()
        
        return {
            'metrics_updated': len(new_metrics),
            'patterns_updated': len(patterns),
            'learning_iteration': model['learning_iterations'],
            'confidence_score': model['model_confidence']
        }
        
    def _detect_adaptive_anomalies(self, entity_id, system_data):
        """Detect anomalies using adaptive thresholds."""
        model = self.behavior_models[entity_id]
        anomalies = []
        
        # Calculate current metrics
        current_metrics = self._extract_baseline_metrics(system_data)
        
        # Compare against adaptive baselines
        for metric, current_value in current_metrics.items():
            if metric in model['baseline_metrics']:
                baseline = model['baseline_metrics'][metric]
                # Adaptive threshold based on historical variance
                threshold_multiplier = 2.0 + (1.0 / max(model['model_confidence'], 0.1))
                threshold = baseline * threshold_multiplier
                
                if abs(current_value - baseline) > threshold:
                    anomaly_score = abs(current_value - baseline) / threshold
                    anomalies.append({
                        'metric': metric,
                        'current_value': current_value,
                        'baseline_value': baseline,
                        'threshold': threshold,
                        'anomaly_score': anomaly_score,
                        'severity': 'high' if anomaly_score > 2.0 else 'medium'
                    })
                    
        return {
            'total_anomalies': len(anomalies),
            'anomalies': anomalies,
            'overall_anomaly_score': sum(a['anomaly_score'] for a in anomalies) / max(len(anomalies), 1)
        }
        
    def _generate_scenario_hypothesis(self, incident_data, scenario_type):
        """Generate hypothesis for specific scenario type."""
        hypothesis_id = f"{scenario_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Scenario-specific hypothesis generation
        if scenario_type == 'insider_threat':
            return {
                'id': hypothesis_id,
                'type': 'insider_threat',
                'description': 'Malicious insider with legitimate access credentials',
                'indicators': [
                    'After-hours data access patterns',
                    'Unusual file access permissions',
                    'Large data transfers to external locations',
                    'Credential sharing or privilege escalation'
                ],
                'likelihood': 0.75,
                'evidence_requirements': [
                    'User behavior analytics',
                    'Data access logs',
                    'Network traffic analysis'
                ]
            }
        elif scenario_type == 'ransomware':
            return {
                'id': hypothesis_id,
                'type': 'ransomware',
                'description': 'Ransomware deployment following initial compromise',
                'indicators': [
                    'Suspicious file encryption activity',
                    'Backup system interference',
                    'Command and control communications',
                    'Lateral movement indicators'
                ],
                'likelihood': 0.85,
                'evidence_requirements': [
                    'File system analysis',
                    'Process execution logs',
                    'Network communications'
                ]
            }
        elif scenario_type == 'apt_infiltration':
            return {
                'id': hypothesis_id,
                'type': 'apt_infiltration',
                'description': 'Advanced persistent threat with long-term access',
                'indicators': [
                    'Sophisticated evasion techniques',
                    'Long-term persistence mechanisms',
                    'Strategic data collection',
                    'Multi-stage attack progression'
                ],
                'likelihood': 0.65,
                'evidence_requirements': [
                    'Memory forensics',
                    'Timeline analysis',
                    'Threat intelligence correlation'
                ]
            }
        elif scenario_type == 'data_exfiltration':
            return {
                'id': hypothesis_id,
                'type': 'data_exfiltration',
                'description': 'Unauthorized data extraction and theft',
                'indicators': [
                    'Large outbound data transfers',
                    'Compression and staging activities',
                    'Covert channel communications',
                    'Data discovery and enumeration'
                ],
                'likelihood': 0.70,
                'evidence_requirements': [
                    'Network traffic analysis',
                    'File access patterns',
                    'Data loss prevention logs'
                ]
            }
            
        return None
        
    def _build_causality_chain(self, detection_event, context_data):
        """Build causality chain for explainable AI."""
        return [
            {
                'step': 1,
                'event': 'Initial trigger detected',
                'cause': detection_event.get('trigger', 'Unknown trigger'),
                'effect': 'Anomaly detection activated',
                'confidence': 0.9
            },
            {
                'step': 2,
                'event': 'Context analysis performed',
                'cause': 'Behavioral baseline deviation',
                'effect': 'Risk score elevated',
                'confidence': 0.8
            },
            {
                'step': 3,
                'event': 'Pattern correlation identified',
                'cause': 'Multiple indicators aligned',
                'effect': 'Alert generated',
                'confidence': 0.85
            }
        ]
        
    def _extract_baseline_metrics(self, system_data):
        """Extract baseline metrics from system data."""
        return {
            'login_frequency': len(system_data.get('logins', [])),
            'file_access_count': len(system_data.get('file_accesses', [])),
            'network_connections': len(system_data.get('network_activity', [])),
            'process_count': len(system_data.get('processes', [])),
            'data_transfer_volume': sum(p.get('bytes', 0) for p in system_data.get('network_activity', []))
        }