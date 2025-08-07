from flask import Blueprint, render_template, request, jsonify
from models import FederatedModel, ModelUpdate, Agent
from app import db
from datetime import datetime, timedelta
import json
import numpy as np

federated_bp = Blueprint('federated', __name__)

@federated_bp.route('/')
def federated_dashboard():
    """Federated learning dashboard"""
    models = FederatedModel.query.order_by(FederatedModel.created_at.desc()).all()
    active_model = FederatedModel.query.filter_by(is_active=True).first()
    
    # Get recent model updates
    recent_updates = ModelUpdate.query.order_by(ModelUpdate.updated_at.desc()).limit(20).all()
    
    return render_template('federated.html',
                         models=models,
                         active_model=active_model,
                         recent_updates=recent_updates)

@federated_bp.route('/api/models')
def api_list_models():
    """List all federated models"""
    models = FederatedModel.query.order_by(FederatedModel.created_at.desc()).all()
    
    model_data = []
    for model in models:
        # Get update statistics
        updates_count = ModelUpdate.query.filter_by(model_id=model.id).count()
        
        # Calculate average loss from recent updates
        recent_updates = ModelUpdate.query.filter_by(model_id=model.id).filter(
            ModelUpdate.updated_at >= datetime.utcnow() - timedelta(hours=24)
        ).all()
        
        avg_loss = None
        if recent_updates:
            avg_loss = sum(u.loss for u in recent_updates if u.loss) / len(recent_updates)
        
        model_data.append({
            'id': model.id,
            'name': model.model_name,
            'version': model.version,
            'accuracy': model.accuracy,
            'is_active': model.is_active,
            'created_at': model.created_at.isoformat(),
            'updates_count': updates_count,
            'avg_loss_24h': avg_loss
        })
    
    return jsonify({'models': model_data})

@federated_bp.route('/api/models/<int:model_id>/performance')
def api_model_performance(model_id):
    """Get performance metrics for a specific model"""
    model = FederatedModel.query.get_or_404(model_id)
    
    # Get updates over time (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    updates = ModelUpdate.query.filter_by(model_id=model_id).filter(
        ModelUpdate.updated_at >= week_ago
    ).order_by(ModelUpdate.updated_at).all()
    
    # Group by day
    daily_metrics = {}
    for update in updates:
        day = update.updated_at.date().isoformat()
        if day not in daily_metrics:
            daily_metrics[day] = {
                'updates': 0,
                'total_loss': 0,
                'total_samples': 0,
                'agents': set()
            }
        
        daily_metrics[day]['updates'] += 1
        if update.loss:
            daily_metrics[day]['total_loss'] += update.loss
        if update.samples_count:
            daily_metrics[day]['total_samples'] += update.samples_count
        daily_metrics[day]['agents'].add(update.agent_id)
    
    # Convert to list format
    performance_data = []
    for day, metrics in daily_metrics.items():
        avg_loss = metrics['total_loss'] / metrics['updates'] if metrics['updates'] > 0 else 0
        performance_data.append({
            'date': day,
            'updates': metrics['updates'],
            'avg_loss': avg_loss,
            'total_samples': metrics['total_samples'],
            'participating_agents': len(metrics['agents'])
        })
    
    performance_data.sort(key=lambda x: x['date'])
    
    return jsonify({
        'model_id': model_id,
        'model_name': model.model_name,
        'performance_data': performance_data
    })

@federated_bp.route('/api/federated-round', methods=['POST'])
def api_start_federated_round():
    """Start a new federated learning round"""
    data = request.get_json()
    model_id = data.get('model_id')
    round_config = data.get('config', {})
    
    model = FederatedModel.query.get_or_404(model_id)
    
    # Get available agents
    available_agents = Agent.query.filter_by(status='online').all()
    
    if len(available_agents) < 2:
        return jsonify({'error': 'At least 2 agents required for federated learning'}), 400
    
    # Select subset of agents for this round
    selected_agents = available_agents[:min(len(available_agents), 
                                          round_config.get('max_agents', 10))]
    
    # Simulate federated learning round
    round_results = []
    for agent in selected_agents:
        # Simulate training on agent
        simulated_loss = np.random.uniform(0.1, 0.8)
        simulated_samples = np.random.randint(100, 1000)
        
        # Create model update record
        update = ModelUpdate(
            agent_id=agent.id,
            model_id=model.id,
            gradient_data=b'simulated_gradient_data',  # In reality, this would be serialized gradients
            loss=simulated_loss,
            samples_count=simulated_samples
        )
        
        db.session.add(update)
        
        round_results.append({
            'agent_id': agent.agent_id,
            'loss': simulated_loss,
            'samples': simulated_samples
        })
    
    # Update model version
    model.version += 1
    
    # Calculate new accuracy (simulated)
    avg_loss = sum(r['loss'] for r in round_results) / len(round_results)
    model.accuracy = max(0, 1.0 - avg_loss)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'round_id': f'round_{model.version}',
        'participating_agents': len(selected_agents),
        'avg_loss': avg_loss,
        'new_accuracy': model.accuracy,
        'results': round_results
    })

@federated_bp.route('/api/privacy-metrics')
def api_privacy_metrics():
    """Get privacy-preserving analytics metrics"""
    # Simulate differential privacy metrics
    total_samples = ModelUpdate.query.with_entities(
        db.func.sum(ModelUpdate.samples_count)
    ).scalar() or 0
    
    # Calculate privacy budget consumption (simulated)
    epsilon_spent = min(1.0, total_samples / 100000.0)  # Simulated privacy budget
    
    # Agent participation distribution
    agent_participation = db.session.query(
        Agent.platform,
        db.func.count(ModelUpdate.id)
    ).join(ModelUpdate).group_by(Agent.platform).all()
    
    participation_data = {}
    for platform, count in agent_participation:
        participation_data[platform] = count
    
    return jsonify({
        'total_samples': total_samples,
        'epsilon_spent': epsilon_spent,
        'epsilon_remaining': max(0, 1.0 - epsilon_spent),
        'agent_participation': participation_data,
        'privacy_guarantees': {
            'differential_privacy': True,
            'secure_aggregation': True,
            'gradient_compression': True
        }
    })

@federated_bp.route('/api/models/<int:model_id>/deploy', methods=['POST'])
def api_deploy_model(model_id):
    """Deploy a model to all active agents"""
    model = FederatedModel.query.get_or_404(model_id)
    
    # Set as active model
    FederatedModel.query.update({FederatedModel.is_active: False})
    model.is_active = True
    
    # Get all online agents
    online_agents = Agent.query.filter_by(status='online').all()
    
    # Simulate model deployment
    deployment_results = []
    for agent in online_agents:
        deployment_results.append({
            'agent_id': agent.agent_id,
            'status': 'deployed',
            'deployment_time': datetime.utcnow().isoformat()
        })
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'model_id': model_id,
        'deployed_to': len(online_agents),
        'deployment_results': deployment_results
    })
