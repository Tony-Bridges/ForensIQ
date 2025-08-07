from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from models import Agent, EvidenceItem, AgentStatus
from app import db
from datetime import datetime
import json
import uuid

agents_bp = Blueprint('agents', __name__)

@agents_bp.route('/')
def list_agents():
    """Display all agents with filtering and pagination"""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    platform_filter = request.args.get('platform', '')
    
    query = Agent.query
    
    if status_filter:
        query = query.filter_by(status=AgentStatus(status_filter))
    if platform_filter:
        query = query.filter_by(platform=platform_filter)
    
    agents = query.paginate(page=page, per_page=20, error_out=False)
    
    # Get unique platforms for filter dropdown
    platforms = db.session.query(Agent.platform).distinct().all()
    platforms = [p[0] for p in platforms]
    
    return render_template('agents.html', 
                         agents=agents, 
                         platforms=platforms,
                         current_status=status_filter,
                         current_platform=platform_filter)

@agents_bp.route('/deploy')
def deploy_form():
    """Agent deployment interface"""
    return render_template('agent_deploy.html')

@agents_bp.route('/api/deploy', methods=['POST'])
def api_deploy_agent():
    """API endpoint to deploy agents"""
    data = request.get_json()
    
    platform = data.get('platform')
    target_ips = data.get('target_ips', [])
    deployment_method = data.get('method', 'manual')
    
    if not platform or not target_ips:
        return jsonify({'error': 'Platform and target IPs required'}), 400
    
    deployed_agents = []
    
    for ip in target_ips:
        # Generate unique agent ID
        agent_id = f"{platform}_{uuid.uuid4().hex[:8]}"
        
        # Create agent record
        agent = Agent(
            agent_id=agent_id,
            hostname=f"host-{ip.replace('.', '-')}",
            platform=platform,
            ip_address=ip,
            status=AgentStatus.DEPLOYING,
            version="1.0.0",
            capabilities=json.dumps({
                'memory_capture': True,
                'file_hashing': True,
                'network_monitoring': True,
                'process_analysis': True
            })
        )
        
        db.session.add(agent)
        deployed_agents.append({
            'agent_id': agent_id,
            'ip': ip,
            'status': 'deploying'
        })
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'deployed_agents': deployed_agents,
        'message': f'Deployed {len(deployed_agents)} agents'
    })

@agents_bp.route('/api/agent/<agent_id>')
def api_agent_details(agent_id):
    """Get detailed information about a specific agent"""
    agent = Agent.query.filter_by(agent_id=agent_id).first_or_404()
    
    # Get recent evidence from this agent
    recent_evidence = EvidenceItem.query.filter_by(agent_id=agent.id).order_by(
        EvidenceItem.collected_at.desc()
    ).limit(10).all()
    
    evidence_data = []
    for item in recent_evidence:
        evidence_data.append({
            'id': item.id,
            'type': item.evidence_type,
            'file_path': item.file_path,
            'file_hash': item.file_hash,
            'size_bytes': item.size_bytes,
            'collected_at': item.collected_at.isoformat(),
            'status': item.status
        })
    
    return jsonify({
        'agent_id': agent.agent_id,
        'hostname': agent.hostname,
        'platform': agent.platform,
        'ip_address': agent.ip_address,
        'status': agent.status.value,
        'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
        'created_at': agent.created_at.isoformat(),
        'version': agent.version,
        'capabilities': json.loads(agent.capabilities) if agent.capabilities else {},
        'recent_evidence': evidence_data
    })

@agents_bp.route('/api/agent/<agent_id>/command', methods=['POST'])
def api_send_command(agent_id):
    """Send command to agent"""
    agent = Agent.query.filter_by(agent_id=agent_id).first_or_404()
    data = request.get_json()
    
    command = data.get('command')
    parameters = data.get('parameters', {})
    
    if not command:
        return jsonify({'error': 'Command required'}), 400
    
    # Here we would normally send the command via MQTT
    # For now, we'll simulate the response
    
    if command == 'collect_memory':
        # Simulate memory collection
        evidence = EvidenceItem(
            agent_id=agent.id,
            evidence_type='memory',
            file_path=f'/tmp/memory_dump_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.bin',
            file_hash=f'sha256:{uuid.uuid4().hex}',
            evidence_metadata=json.dumps({'collection_method': 'full_dump'}),
            size_bytes=1024*1024*512,  # 512MB
            status='collected'
        )
        db.session.add(evidence)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Memory collection initiated',
            'evidence_id': evidence.id
        })
    
    elif command == 'hash_files':
        # Simulate file hashing
        file_paths = parameters.get('paths', ['/etc', '/var/log'])
        evidence_items = []
        
        for path in file_paths:
            evidence = EvidenceItem(
                agent_id=agent.id,
                evidence_type='file_hash',
                file_path=path,
                file_hash=f'sha256:{uuid.uuid4().hex}',
                evidence_metadata=json.dumps({'scan_recursive': True}),
                size_bytes=1024*64,  # 64KB hash file
                status='collected'
            )
            db.session.add(evidence)
            evidence_items.append(evidence.id)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'File hashing initiated for {len(file_paths)} paths',
            'evidence_ids': evidence_items
        })
    
    return jsonify({'error': 'Unknown command'}), 400

@agents_bp.route('/api/agents/bulk-action', methods=['POST'])
def api_bulk_action():
    """Perform bulk actions on multiple agents"""
    data = request.get_json()
    agent_ids = data.get('agent_ids', [])
    action = data.get('action')
    
    if not agent_ids or not action:
        return jsonify({'error': 'Agent IDs and action required'}), 400
    
    agents = Agent.query.filter(Agent.agent_id.in_(agent_ids)).all()
    
    if action == 'update_status':
        new_status = AgentStatus(data.get('status'))
        for agent in agents:
            agent.status = new_status
    elif action == 'collect_evidence':
        evidence_type = data.get('evidence_type', 'memory')
        for agent in agents:
            evidence = EvidenceItem(
                agent_id=agent.id,
                evidence_type=evidence_type,
                file_path=f'/tmp/{evidence_type}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.bin',
                file_hash=f'sha256:{uuid.uuid4().hex}',
                evidence_metadata=json.dumps({'bulk_collection': True}),
                size_bytes=1024*1024*256,  # 256MB
                status='collected'
            )
            db.session.add(evidence)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Action {action} applied to {len(agents)} agents'
    })
