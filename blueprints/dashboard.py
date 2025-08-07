from flask import Blueprint, render_template, jsonify, request
from models import Agent, EvidenceItem, FederatedModel, AgentStatus
from app import db
from datetime import datetime, timedelta
from attached_assets.cloud_forensics_1754511764907 import CloudForensics
from attached_assets import cloud_forensics_1754511764907
import json

dashboard_bp = Blueprint('dashboard', __name__)
cloud_handler = CloudForensics()


@dashboard_bp.route('/')
def index():
    # Get agent statistics
    total_agents = Agent.query.count()
    online_agents = Agent.query.filter_by(status=AgentStatus.ONLINE).count()
    offline_agents = Agent.query.filter_by(status=AgentStatus.OFFLINE).count()
    
    # Get recent evidence
    recent_evidence = EvidenceItem.query.order_by(EvidenceItem.collected_at.desc()).limit(10).all()
    
    # Get federated model status
    active_model = FederatedModel.query.filter_by(is_active=True).first()
    
    return render_template('dashboard.html',
                         total_agents=total_agents,
                         online_agents=online_agents,
                         offline_agents=offline_agents,
                         recent_evidence=recent_evidence,
                         active_model=active_model)

@dashboard_bp.route('/api/stats')
def api_stats():
    """API endpoint for real-time dashboard statistics"""
    # Agent statistics
    agent_stats = {
        'total': Agent.query.count(),
        'online': Agent.query.filter_by(status=AgentStatus.ONLINE).count(),
        'offline': Agent.query.filter_by(status=AgentStatus.OFFLINE).count(),
        'error': Agent.query.filter_by(status=AgentStatus.ERROR).count(),
        'deploying': Agent.query.filter_by(status=AgentStatus.DEPLOYING).count()
    }
    
    # Platform distribution
    platform_stats = {}
    platforms = db.session.query(Agent.platform, db.func.count(Agent.id)).group_by(Agent.platform).all()
    for platform, count in platforms:
        platform_stats[platform] = count
    
    # Evidence collection over time (last 24 hours)
    last_24h = datetime.utcnow() - timedelta(hours=24)
    evidence_timeline = []
    for i in range(24):
        hour_start = last_24h + timedelta(hours=i)
        hour_end = hour_start + timedelta(hours=1)
        count = EvidenceItem.query.filter(
            EvidenceItem.collected_at >= hour_start,
            EvidenceItem.collected_at < hour_end
        ).count()
        evidence_timeline.append({
            'hour': hour_start.strftime('%H:00'),
            'count': count
        })
    
    return jsonify({
        'agent_stats': agent_stats,
        'platform_stats': platform_stats,
        'evidence_timeline': evidence_timeline,
        'timestamp': datetime.utcnow().isoformat()
    })

@dashboard_bp.route("/cloud_forensics", methods=["GET", "POST"])
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


@dashboard_bp.route('/api/network-topology')
def api_network_topology():
    """API endpoint for network topology visualization"""
    agents = Agent.query.all()
    nodes = []
    links = []
    
    # Add central server node
    nodes.append({
        'id': 'server',
        'type': 'server',
        'name': 'ForensIQ Server',
        'status': 'online',
        'x': 400,
        'y': 300
    })
    
    # Add agent nodes
    for i, agent in enumerate(agents):
        angle = (i * 2 * 3.14159) / len(agents)
        x = 400 + 200 * abs(hash(agent.agent_id) % 100) / 100 * abs(hash(agent.platform) % 2 - 0.5) * 2
        y = 300 + 200 * abs(hash(agent.hostname) % 100) / 100 * abs(hash(agent.ip_address) % 2 - 0.5) * 2
        
        nodes.append({
            'id': agent.agent_id,
            'type': 'agent',
            'name': agent.hostname,
            'platform': agent.platform,
            'status': agent.status.value,
            'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
            'x': x,
            'y': y
        })
        
        # Add link to server
        links.append({
            'source': 'server',
            'target': agent.agent_id,
            'type': 'connection',
            'strength': 1 if agent.status == AgentStatus.ONLINE else 0.3
        })
    
    return jsonify({
        'nodes': nodes,
        'links': links
    })
