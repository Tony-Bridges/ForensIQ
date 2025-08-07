"""
Advanced Forensic API Blueprint
Provides REST API endpoints for advanced forensic modules
"""
from flask import Blueprint, render_template, request, jsonify, g
from services.iam_service import token_required, api_key_required, permission_required
from services.forensic_modules import forensic_modules_service
from models import Case, EvidenceItem, Agent
from models.tenant import Tenant
from models.user import User
from attached_assets.cloud_forensics_1754511764907 import CloudForensics
from attached_assets import cloud_forensics_1754511764907
from app import db
import json

forensic_api_bp = Blueprint('forensic_api', __name__)
cloud_handler = CloudForensics()

forensic_api_bp.route("/cloud_forensics", methods=["GET", "POST"])
def cloud_forensics():
    """Cloud forensics interface."""
    if request.method == "POST":
        cloud_provider = request.form.get("cloud_provider")
        analysis_type = request.form.get("analysis_type")

        if analysis_type == "cloud_acquisition":
            credentials = {
                "access_key": request.form.get("access_key"),
                "secret_key": request.form.get("secret_key"),
                "session_token": request.form.get("session_token", "")
            }
            regions = request.form.getlist("regions")
            resource_groups = request.form.getlist("resource_groups")
            results = cloud_handler.acquire_cloud_data(
                cloud_provider, credentials, regions, resource_groups
            )
        elif analysis_type == "cloud_analysis":
            resource_type = request.form.get("resource_type", "ec2")
            resource_ids = request.form.getlist("resource_ids")
            results = cloud_handler.analyze_cloud_resources(cloud_provider, resource_type, resource_ids)
        elif analysis_type == "cloud_log_analysis":
            log_type = request.form.get("log_type", "cloudtrail")
            start_time = request.form.get("start_time")
            end_time = request.form.get("end_time")
            results = cloud_handler.analyze_cloud_logs(cloud_provider, log_type, start_time, end_time)
        elif analysis_type == "cloud_data_preservation":
            preservation_request = {
                "account_id": request.form.get("account_id"),
                "resource_type": request.form.get("resource_type", "s3"),
                "regions": request.form.getlist("regions"),
                "resource_groups": request.form.getlist("resource_groups")
            }
            results = cloud_handler.preserve_cloud_data(cloud_provider, preservation_request)
        elif analysis_type == "cloud_security_analysis":
            security_service = request.form.get("security_service", "guardduty")
            resource_ids = request.form.getlist("resource_ids")
            results = cloud_handler.analyze_cloud_security(cloud_provider, security_service, resource_ids)
        elif analysis_type == "cloud_network_analysis":
            network_service = request.form.get("network_service", "vpc_flow_logs")
            start_time = request.form.get("start_time")
            end_time = request.form.get("end_time")
            results = cloud_handler.analyze_cloud_network(cloud_provider, network_service, start_time, end_time)
        elif analysis_type == "container_analysis":
            container_runtime = request.form.get("container_runtime", "docker")
            container_ids = request.form.getlist("container_ids")
            results = cloud_handler.analyze_containers(cloud_provider, container_runtime, container_ids)
        elif analysis_type == "serverless_analysis":
            function_names = request.form.get("function_names", "").split(",")
            results = cloud_handler.analyze_serverless_functions(cloud_provider, function_names)
        elif analysis_type == "serverless_security":
            function_names = request.form.get("function_names", "").split(",")
            results = cloud_handler.analyze_serverless_security(cloud_provider, function_names)
        elif analysis_type == "serverless_trace":
            function_names = request.form.get("function_names", "").split(",")
            results = cloud_handler.trace_serverless_functions(cloud_provider, function_names)
        elif analysis_type == "vm_analysis":
            vm_format = request.form.get("vm_format")
            disk_path = request.form.get("disk_path", "/demo/vm.vmdk")
            results = cloud_handler.analyze_vm_disks(vm_format, disk_path)
        else:
            results = {"error": "Invalid analysis type"}

        return render_template("cloud_forensics.html", results=results, analysis_type=analysis_type)

    return render_template("cloud_forensics.html")


@forensic_api_bp.route('/modules', methods=['GET'])
@token_required
def get_available_modules():
    """Get available forensic modules for current tenant"""
    try:
        modules = forensic_modules_service.get_available_modules(g.current_user.tenant_id)
        return jsonify({
            'success': True,
            'modules': modules,
            'count': len(modules)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/blockchain/analyze', methods=['POST'])
@token_required
@permission_required('blockchain_forensics')
def blockchain_analysis():
    """Execute blockchain forensics analysis"""
    try:
        data = request.get_json() or {}
        wallet_addresses = data.get('wallet_addresses', [])
        blockchain_type = data.get('blockchain_type', 'bitcoin')
        
        if not wallet_addresses:
            return jsonify({'error': 'Wallet addresses are required'}), 400
        
        result = forensic_modules_service.execute_blockchain_analysis(
            g.current_user.tenant_id,
            g.current_user.id,
            wallet_addresses,
            blockchain_type
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/cloud/investigate', methods=['GET','POST'])
@token_required
@permission_required('cloud_forensics')
def cloud_investigation():
    """Execute cloud forensics investigation"""
    try:
        data = request.get_json() or {}
        cloud_provider = data.get('cloud_provider')
        credentials = data.get('credentials', {})
        investigation_scope = data.get('investigation_scope', {})
        
        if not cloud_provider:
            return jsonify({'error': 'Cloud provider is required'}), 400
        
        result = forensic_modules_service.execute_cloud_forensics(
            g.current_user.tenant_id,
            g.current_user.id,
            cloud_provider,
            credentials,
            investigation_scope
        )
        
        if result['success']:
            return render_template('cloud_forensics.html')
                                   
        else:
            return render_template('cloud_forensics.html')
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/predator-reflex/activate', methods=['POST'])
@token_required
@permission_required('predator_reflex')
def activate_predator_reflex():
    """Activate predator reflex monitoring system"""
    try:
        data = request.get_json() or {}
        monitoring_config = data.get('monitoring_config', {})
        
        result = forensic_modules_service.activate_predator_reflex(
            g.current_user.tenant_id,
            g.current_user.id,
            monitoring_config
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/quantum-contingency/execute', methods=['POST'])
@token_required
@permission_required('quantum_contingency')
def execute_quantum_contingency():
    """Execute quantum contingency protocols"""
    try:
        data = request.get_json() or {}
        threat_scenario = data.get('threat_scenario', {})
        
        if not threat_scenario:
            return jsonify({'error': 'Threat scenario is required'}), 400
        
        result = forensic_modules_service.execute_quantum_contingency(
            g.current_user.tenant_id,
            g.current_user.id,
            threat_scenario
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/reports/generate', methods=['POST'])
@token_required
@permission_required('generate_reports')
def generate_forensic_report():
    """Generate comprehensive forensic report"""
    try:
        data = request.get_json() or {}
        case_id = data.get('case_id')
        report_config = data.get('report_config', {})
        
        if not case_id:
            return jsonify({'error': 'Case ID is required'}), 400
        
        # Verify case belongs to tenant
        case = Case.query.filter_by(
            id=case_id,
            tenant_id=g.current_user.tenant_id
        ).first()
        
        if not case:
            return jsonify({'error': 'Case not found or access denied'}), 404
        
        result = forensic_modules_service.generate_forensic_report(
            g.current_user.tenant_id,
            g.current_user.id,
            case_id,
            report_config
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/cases', methods=['GET'])
@token_required
def get_tenant_cases():
    """Get cases for current tenant"""
    try:
        cases = Case.query.filter_by(tenant_id=g.current_user.tenant_id).all()
        cases_data = []
        
        for case in cases:
            evidence_count = EvidenceItem.query.filter_by(case_id=case.id).count()
            cases_data.append({
                'id': case.id,
                'case_number': case.case_number,
                'title': case.title,
                'description': case.description,
                'priority': case.priority,
                'status': case.status,
                'evidence_count': evidence_count,
                'assigned_user': case.assigned_user.get_full_name() if case.assigned_user else None,
                'created_at': case.created_at.isoformat(),
                'updated_at': case.updated_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'cases': cases_data,
            'count': len(cases_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/cases', methods=['POST'])
@token_required
@permission_required('create_cases')
def create_case():
    """Create a new forensic case"""
    try:
        data = request.get_json() or {}
        
        # Generate case number
        case_count = Case.query.filter_by(tenant_id=g.current_user.tenant_id).count()
        case_number = f"CASE-{g.current_user.tenant_id:04d}-{case_count + 1:06d}"
        
        case = Case(
            tenant_id=g.current_user.tenant_id,
            assigned_user_id=g.current_user.id,
            case_number=case_number,
            title=data.get('title', ''),
            description=data.get('description', ''),
            priority=data.get('priority', 'medium'),
            status='active'
        )
        
        db.session.add(case)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'case': {
                'id': case.id,
                'case_number': case.case_number,
                'title': case.title,
                'description': case.description,
                'priority': case.priority,
                'status': case.status,
                'created_at': case.created_at.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/evidence', methods=['GET'])
@token_required
def get_tenant_evidence():
    """Get evidence items for current tenant"""
    try:
        case_id = request.args.get('case_id')
        evidence_type = request.args.get('type')
        
        query = EvidenceItem.query.filter_by(tenant_id=g.current_user.tenant_id)
        
        if case_id:
            query = query.filter_by(case_id=case_id)
        if evidence_type:
            query = query.filter_by(evidence_type=evidence_type)
        
        evidence_items = query.all()
        evidence_data = []
        
        for item in evidence_items:
            metadata = json.loads(item.evidence_metadata) if item.evidence_metadata else {}
            evidence_data.append({
                'id': item.id,
                'case_id': item.case_id,
                'agent_id': item.agent_id,
                'evidence_type': item.evidence_type,
                'file_path': item.file_path,
                'file_hash': item.file_hash,
                'metadata': metadata,
                'size_bytes': item.size_bytes,
                'status': item.status,
                'collected_at': item.collected_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'evidence': evidence_data,
            'count': len(evidence_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/agents', methods=['GET'])
@token_required
def get_tenant_agents():
    """Get agents for current tenant"""
    try:
        agents = Agent.query.filter_by(tenant_id=g.current_user.tenant_id).all()
        agents_data = []
        
        for agent in agents:
            capabilities = json.loads(agent.capabilities) if agent.capabilities else {}
            agents_data.append({
                'id': agent.id,
                'agent_id': agent.agent_id,
                'hostname': agent.hostname,
                'platform': agent.platform,
                'ip_address': agent.ip_address,
                'status': agent.status.value,
                'capabilities': capabilities,
                'version': agent.version,
                'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
                'created_at': agent.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'agents': agents_data,
            'count': len(agents_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@forensic_api_bp.route('/tenant/stats', methods=['GET'])
@token_required
def get_tenant_stats():
    """Get statistics for current tenant"""
    try:
        tenant = Tenant.query.get(g.current_user.tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        # Get usage statistics
        usage_stats = tenant.get_usage_stats()
        
        # Get additional metrics
        active_cases = Case.query.filter_by(
            tenant_id=g.current_user.tenant_id,
            status='active'
        ).count()
        
        total_evidence = EvidenceItem.query.filter_by(
            tenant_id=g.current_user.tenant_id
        ).count()
        
        online_agents = Agent.query.filter_by(
            tenant_id=g.current_user.tenant_id,
            status='online'
        ).count()
        
        return jsonify({
            'success': True,
            'tenant': {
                'id': tenant.id,
                'name': tenant.name,
                'domain': tenant.domain,
                'plan': tenant.plan.value,
                'status': tenant.status.value,
                'features': tenant.get_features()
            },
            'usage': usage_stats,
            'metrics': {
                'active_cases': active_cases,
                'total_evidence': total_evidence,
                'online_agents': online_agents
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500