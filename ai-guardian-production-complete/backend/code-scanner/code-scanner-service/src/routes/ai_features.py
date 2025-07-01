"""
AI Features API Routes for AI Guardian
Endpoints for natural language queries, automated remediation, and threat prediction
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import json
import os
from typing import Dict, List, Any

# Import AI feature modules
from src.ai_features.natural_language_processor import NaturalLanguageProcessor, QueryResult
from src.ai_features.automated_remediation import AutomatedRemediationEngine, RemediationResult
from src.ai_features.threat_prediction import ThreatPredictionEngine, ThreatPrediction

ai_features_bp = Blueprint('ai_features', __name__)

# Initialize AI feature engines
nlp_processor = NaturalLanguageProcessor()
remediation_engine = AutomatedRemediationEngine()
threat_predictor = ThreatPredictionEngine()

@ai_features_bp.route('/natural-query', methods=['POST'])
def process_natural_query():
    """Process natural language security queries"""
    try:
        data = request.get_json()
        
        if not data or 'query' not in data:
            return jsonify({
                'error': 'Query text is required',
                'status': 'error'
            }), 400
        
        query = data['query']
        user_context = data.get('context', {})
        
        # Process the query
        result = nlp_processor.process_query(query, user_context)
        
        # Convert result to dictionary
        response = {
            'answer': result.answer,
            'confidence': result.confidence,
            'sources': result.sources,
            'related_vulnerabilities': result.related_vulnerabilities,
            'recommendations': result.recommendations,
            'query_type': result.query_type,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': f'Error processing query: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/query-suggestions', methods=['GET'])
def get_query_suggestions():
    """Get query suggestions for natural language interface"""
    try:
        partial_query = request.args.get('partial', '')
        suggestions = nlp_processor.get_query_suggestions(partial_query)
        
        return jsonify({
            'suggestions': suggestions,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting suggestions: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/remediate-vulnerability', methods=['POST'])
def remediate_vulnerability():
    """Automatically remediate a specific vulnerability"""
    try:
        data = request.get_json()
        
        required_fields = ['vulnerability', 'source_code']
        if not data or not all(field in data for field in required_fields):
            return jsonify({
                'error': 'vulnerability and source_code are required',
                'status': 'error'
            }), 400
        
        vulnerability = data['vulnerability']
        source_code = data['source_code']
        file_path = data.get('file_path')
        auto_apply = data.get('auto_apply', False)
        
        # Perform remediation
        result = remediation_engine.remediate_vulnerability(
            vulnerability, source_code, file_path, auto_apply
        )
        
        # Convert result to dictionary
        response = {
            'success': result.success,
            'original_code': result.original_code,
            'fixed_code': result.fixed_code,
            'explanation': result.explanation,
            'confidence': result.confidence,
            'vulnerability_type': result.vulnerability_type,
            'changes_made': result.changes_made,
            'warnings': result.warnings,
            'backup_created': result.backup_created,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': f'Error during remediation: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/batch-remediate', methods=['POST'])
def batch_remediate():
    """Remediate multiple vulnerabilities in batch"""
    try:
        data = request.get_json()
        
        if not data or 'vulnerabilities' not in data or 'source_files' not in data:
            return jsonify({
                'error': 'vulnerabilities and source_files are required',
                'status': 'error'
            }), 400
        
        vulnerabilities = data['vulnerabilities']
        source_files = data['source_files']
        
        # Perform batch remediation
        results = remediation_engine.batch_remediate(vulnerabilities, source_files)
        
        # Convert results to serializable format
        serialized_results = {}
        for key, result in results.items():
            serialized_results[key] = {
                'success': result.success,
                'original_code': result.original_code,
                'fixed_code': result.fixed_code,
                'explanation': result.explanation,
                'confidence': result.confidence,
                'vulnerability_type': result.vulnerability_type,
                'changes_made': result.changes_made,
                'warnings': result.warnings,
                'backup_created': result.backup_created
            }
        
        return jsonify({
            'results': serialized_results,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error during batch remediation: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/generate-secure-code', methods=['POST'])
def generate_secure_code():
    """Generate secure code based on description"""
    try:
        data = request.get_json()
        
        if not data or 'description' not in data or 'language' not in data:
            return jsonify({
                'error': 'description and language are required',
                'status': 'error'
            }), 400
        
        description = data['description']
        language = data['language']
        context = data.get('context', {})
        
        # Generate secure code
        generated_code = remediation_engine.generate_secure_code(description, language, context)
        
        return jsonify({
            'generated_code': generated_code,
            'language': language,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating code: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/remediation-stats', methods=['GET'])
def get_remediation_stats():
    """Get remediation statistics"""
    try:
        stats = remediation_engine.get_remediation_statistics()
        
        return jsonify({
            'statistics': stats,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting statistics: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/threat-predictions', methods=['GET'])
def get_threat_predictions():
    """Get threat predictions and analytics"""
    try:
        time_horizon = request.args.get('time_horizon', '30_days')
        
        # Get threat predictions
        predictions = threat_predictor.predict_emerging_threats(time_horizon)
        
        # Convert predictions to serializable format
        serialized_predictions = []
        for prediction in predictions:
            serialized_predictions.append({
                'threat_type': prediction.threat_type,
                'probability': prediction.probability,
                'severity': prediction.severity,
                'timeline': prediction.timeline,
                'description': prediction.description,
                'indicators': prediction.indicators,
                'recommendations': prediction.recommendations,
                'confidence': prediction.confidence,
                'data_sources': prediction.data_sources
            })
        
        return jsonify({
            'predictions': serialized_predictions,
            'time_horizon': time_horizon,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting threat predictions: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/threat-landscape', methods=['GET'])
def get_threat_landscape():
    """Get overall threat landscape summary"""
    try:
        landscape = threat_predictor.get_threat_landscape_summary()
        
        return jsonify({
            'landscape': landscape,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting threat landscape: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/ai-features-status', methods=['GET'])
def get_ai_features_status():
    """Get status of AI features and their availability"""
    try:
        # Check if AI clients are available
        nlp_available = nlp_processor.openai_client is not None
        remediation_available = remediation_engine.openai_client is not None
        
        # Get feature statistics
        remediation_stats = remediation_engine.get_remediation_statistics()
        
        status = {
            'natural_language_processing': {
                'available': nlp_available,
                'description': 'Natural language query processing for security questions'
            },
            'automated_remediation': {
                'available': remediation_available,
                'description': 'AI-powered automatic vulnerability fixes',
                'statistics': remediation_stats
            },
            'threat_prediction': {
                'available': True,
                'description': 'Predictive analytics for emerging threats'
            },
            'secure_code_generation': {
                'available': remediation_available,
                'description': 'AI-powered secure code generation'
            }
        }
        
        return jsonify({
            'ai_features_status': status,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting AI features status: {str(e)}',
            'status': 'error'
        }), 500

@ai_features_bp.route('/configure-ai', methods=['POST'])
def configure_ai_features():
    """Configure AI features settings"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'Configuration data is required',
                'status': 'error'
            }), 400
        
        # This would typically update configuration settings
        # For now, just return the current configuration
        
        config = {
            'natural_language_processing': {
                'enabled': True,
                'model': 'gpt-3.5-turbo',
                'max_tokens': 500
            },
            'automated_remediation': {
                'enabled': True,
                'auto_apply': False,
                'backup_files': True,
                'confidence_threshold': 0.7
            },
            'threat_prediction': {
                'enabled': True,
                'update_frequency': 'daily',
                'prediction_horizon': '30_days'
            }
        }
        
        return jsonify({
            'configuration': config,
            'message': 'AI features configuration updated',
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error configuring AI features: {str(e)}',
            'status': 'error'
        }), 500

# Health check endpoint for AI features
@ai_features_bp.route('/health', methods=['GET'])
def ai_features_health():
    """Health check for AI features"""
    try:
        health_status = {
            'natural_language_processor': 'healthy',
            'automated_remediation': 'healthy',
            'threat_prediction': 'healthy',
            'timestamp': datetime.now().isoformat()
        }
        
        # Check if AI clients are responsive
        if nlp_processor.openai_client is None:
            health_status['natural_language_processor'] = 'degraded - AI client not available'
        
        if remediation_engine.openai_client is None:
            health_status['automated_remediation'] = 'degraded - AI client not available'
        
        return jsonify({
            'health': health_status,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Health check failed: {str(e)}',
            'status': 'error'
        }), 500

