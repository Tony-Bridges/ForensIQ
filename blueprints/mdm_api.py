"""
MDM/EMM Integration API Blueprint
Provides REST API endpoints for Mobile Device Management integrations
"""
from flask import Blueprint, request, jsonify, g
from services.iam_service import token_required, permission_required
from services.mdm_service import MDMIntegrationService
from models import Agent
from models.tenant import Tenant
from app import db
import json

mdm_api_bp = Blueprint('mdm_api', __name__)
mdm_service = MDMIntegrationService()

@mdm_api_bp.route('/platforms', methods=['GET'])
@token_required
def get_mdm_platforms():
    """Get available MDM/EMM platforms"""
    try:
        platforms = []
        for platform_name, connector_class in mdm_service.supported_platforms.items():
            platforms.append({
                'name': platform_name,
                'display_name': platform_name.replace('_', ' ').title(),
                'description': f'{connector_class.__name__} integration',
                'supported_features': [
                    'device_management',
                    'app_deployment',
                    'compliance_monitoring',
                    'evidence_collection'
                ]
            })
        
        return jsonify({
            'success': True,
            'platforms': platforms,
            'count': len(platforms)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/integrate', methods=['POST'])
@token_required
@permission_required('mdm_integration')
def integrate_mdm_platform():
    """Integrate with MDM/EMM platform"""
    try:
        data = request.get_json() or {}
        platform_name = data.get('platform_name')
        credentials = data.get('credentials', {})
        config = data.get('config', {})
        
        if not platform_name:
            return jsonify({'error': 'Platform name is required'}), 400
        
        if platform_name not in mdm_service.supported_platforms:
            return jsonify({'error': f'Unsupported platform: {platform_name}'}), 400
        
        result = mdm_service.integrate_mdm_platform(
            g.current_user.tenant_id,
            platform_name,
            credentials,
            config
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/sync', methods=['POST'])
@token_required
@permission_required('mdm_integration')
def sync_mdm_devices():
    """Sync devices from MDM platform"""
    try:
        data = request.get_json() or {}
        platform_name = data.get('platform_name')  # Optional - if not specified, syncs all platforms
        
        result = mdm_service.sync_mdm_devices(g.current_user.tenant_id, platform_name)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/deploy-agent', methods=['POST'])
@token_required
@permission_required('deploy_agents')
def deploy_forensic_agent():
    """Deploy forensic agent to managed devices via MDM"""
    try:
        data = request.get_json() or {}
        device_ids = data.get('device_ids', [])
        platform_name = data.get('platform_name')
        
        if not device_ids:
            return jsonify({'error': 'Device IDs are required'}), 400
        
        if not platform_name:
            return jsonify({'error': 'Platform name is required'}), 400
        
        result = mdm_service.deploy_forensic_agent_via_mdm(
            g.current_user.tenant_id,
            device_ids,
            platform_name
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/collect-evidence', methods=['POST'])
@token_required
@permission_required('collect_evidence')
def collect_mobile_evidence():
    """Collect evidence from mobile device via MDM"""
    try:
        data = request.get_json() or {}
        agent_id = data.get('agent_id')
        evidence_types = data.get('evidence_types', [])
        
        if not agent_id:
            return jsonify({'error': 'Agent ID is required'}), 400
        
        if not evidence_types:
            return jsonify({'error': 'Evidence types are required'}), 400
        
        # Verify agent belongs to tenant
        agent = Agent.query.filter_by(
            agent_id=agent_id,
            tenant_id=g.current_user.tenant_id
        ).first()
        
        if not agent:
            return jsonify({'error': 'Agent not found or access denied'}), 404
        
        result = mdm_service.collect_mobile_evidence(agent_id, evidence_types)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/devices', methods=['GET'])
@token_required
def get_managed_devices():
    """Get managed devices from all integrated MDM platforms"""
    try:
        tenant = Tenant.query.get(g.current_user.tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        settings = tenant.get_settings()
        mdm_integrations = settings.get('mdm_integrations', {})
        
        all_devices = []
        
        for platform_name, integration in mdm_integrations.items():
            if not integration.get('enabled'):
                continue
            
            try:
                # Get managed devices for this platform
                agents = Agent.query.filter(
                    Agent.tenant_id == g.current_user.tenant_id,
                    Agent.agent_id.like(f'mdm_{platform_name}_%')
                ).all()
                
                for agent in agents:
                    capabilities = json.loads(agent.capabilities) if agent.capabilities else {}
                    device_info = {
                        'device_id': agent.agent_id.replace(f'mdm_{platform_name}_', ''),
                        'agent_id': agent.agent_id,
                        'platform': platform_name,
                        'hostname': agent.hostname,
                        'ip_address': agent.ip_address,
                        'status': agent.status.value,
                        'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
                        'capabilities': capabilities,
                        'mdm_managed': capabilities.get('mdm_managed', False)
                    }
                    all_devices.append(device_info)
                    
            except Exception as e:
                # Log error but continue with other platforms
                continue
        
        return jsonify({
            'success': True,
            'devices': all_devices,
            'count': len(all_devices),
            'platforms': list(mdm_integrations.keys())
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/integrations', methods=['GET'])
@token_required
def get_mdm_integrations():
    """Get current MDM integrations for tenant"""
    try:
        tenant = Tenant.query.get(g.current_user.tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        settings = tenant.get_settings()
        mdm_integrations = settings.get('mdm_integrations', {})
        
        integrations_list = []
        for platform_name, integration in mdm_integrations.items():
            device_count = Agent.query.filter(
                Agent.tenant_id == g.current_user.tenant_id,
                Agent.agent_id.like(f'mdm_{platform_name}_%')
            ).count()
            
            integrations_list.append({
                'platform': platform_name,
                'display_name': platform_name.replace('_', ' ').title(),
                'enabled': integration.get('enabled', False),
                'configured_at': integration.get('configured_at'),
                'last_sync': integration.get('last_sync'),
                'sync_status': integration.get('sync_status', 'unknown'),
                'device_count': device_count,
                'config': integration.get('config', {})
            })
        
        return jsonify({
            'success': True,
            'integrations': integrations_list,
            'count': len(integrations_list)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/integrations/<platform_name>', methods=['DELETE'])
@token_required
@permission_required('mdm_integration')
def remove_mdm_integration(platform_name):
    """Remove MDM integration"""
    try:
        tenant = Tenant.query.get(g.current_user.tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        settings = tenant.get_settings()
        mdm_integrations = settings.get('mdm_integrations', {})
        
        if platform_name not in mdm_integrations:
            return jsonify({'error': 'Integration not found'}), 404
        
        # Remove integration
        del mdm_integrations[platform_name]
        settings['mdm_integrations'] = mdm_integrations
        tenant.set_settings(settings)
        
        # Optionally remove associated agents
        Agent.query.filter(
            Agent.tenant_id == g.current_user.tenant_id,
            Agent.agent_id.like(f'mdm_{platform_name}_%')
        ).delete()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'MDM integration for {platform_name} removed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@mdm_api_bp.route('/evidence-types', methods=['GET'])
@token_required
def get_evidence_types():
    """Get available evidence types for mobile forensics"""
    try:
        evidence_types = [
            {
                'type': 'app_data',
                'display_name': 'Application Data',
                'description': 'Extract application data, databases, and user files',
                'supported_platforms': ['android', 'ios']
            },
            {
                'type': 'device_info',
                'display_name': 'Device Information',
                'description': 'System information, hardware details, and configuration',
                'supported_platforms': ['android', 'ios', 'windows', 'macos']
            },
            {
                'type': 'location_history',
                'display_name': 'Location History',
                'description': 'GPS location data and movement patterns',
                'supported_platforms': ['android', 'ios']
            },
            {
                'type': 'compliance_status',
                'display_name': 'Compliance Status',
                'description': 'Device compliance and policy enforcement status',
                'supported_platforms': ['android', 'ios', 'windows', 'macos']
            },
            {
                'type': 'network_logs',
                'display_name': 'Network Logs',
                'description': 'Network traffic and connection history',
                'supported_platforms': ['android', 'ios', 'windows', 'macos']
            }
        ]
        
        return jsonify({
            'success': True,
            'evidence_types': evidence_types,
            'count': len(evidence_types)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500