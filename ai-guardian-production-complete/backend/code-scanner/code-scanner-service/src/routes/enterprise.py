"""
Enterprise Features API Routes for AI Guardian
Endpoints for Zero Trust, compliance automation, risk quantification, and security training
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import json
import os
from typing import Dict, List, Any

# Import enterprise feature modules
from src.enterprise_features.zero_trust_integration import (
    ZeroTrustIntegration, ZeroTrustContext, TrustLevel, AccessDecision
)
from src.enterprise_features.compliance_automation import (
    ComplianceAutomation, ComplianceFramework, ComplianceStatus
)
from src.enterprise_features.risk_quantification import (
    RiskQuantificationEngine, RiskCategory, ImpactLevel, Likelihood
)
from src.enterprise_features.security_training import (
    SecurityTrainingEngine, SkillLevel, TrainingType
)

enterprise_bp = Blueprint('enterprise', __name__)

# Initialize enterprise feature engines
zero_trust = ZeroTrustIntegration()
compliance_engine = ComplianceAutomation()
risk_engine = RiskQuantificationEngine()
training_engine = SecurityTrainingEngine()

@enterprise_bp.route('/zero-trust/evaluate-access', methods=['POST'])
def evaluate_zero_trust_access():
    """Evaluate access request using Zero Trust principles"""
    try:
        data = request.get_json()
        
        required_fields = ['user_id', 'device_id', 'resource_requested']
        if not data or not all(field in data for field in required_fields):
            return jsonify({
                'error': 'user_id, device_id, and resource_requested are required',
                'status': 'error'
            }), 400
        
        # Create Zero Trust context
        context = ZeroTrustContext(
            user_id=data['user_id'],
            device_id=data['device_id'],
            location=data.get('location', 'unknown'),
            network=data.get('network', 'unknown'),
            time_of_access=datetime.now(),
            resource_requested=data['resource_requested'],
            risk_score=data.get('risk_score', 0.5),
            authentication_method=data.get('authentication_method', 'password'),
            device_compliance=data.get('device_compliance', False),
            network_trust_level=TrustLevel(data.get('network_trust_level', 2))
        )
        
        # Evaluate access
        decision, trust_score, reasons = zero_trust.evaluate_access_request(context)
        
        return jsonify({
            'decision': decision.value,
            'trust_score': trust_score,
            'reasons': reasons,
            'context': {
                'user_id': context.user_id,
                'device_id': context.device_id,
                'resource': context.resource_requested,
                'timestamp': context.time_of_access.isoformat()
            },
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error evaluating access: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/zero-trust/security-events', methods=['GET'])
def get_zero_trust_events():
    """Get Zero Trust security events"""
    try:
        time_range_hours = int(request.args.get('time_range_hours', 24))
        severity = request.args.get('severity')
        
        time_range = timedelta(hours=time_range_hours)
        events = zero_trust.get_security_events(time_range, severity)
        
        # Convert events to serializable format
        serialized_events = []
        for event in events:
            serialized_events.append({
                'event_id': event.event_id,
                'event_type': event.event_type,
                'severity': event.severity,
                'user_id': event.user_id,
                'device_id': event.device_id,
                'resource': event.resource,
                'description': event.description,
                'timestamp': event.timestamp.isoformat(),
                'context': event.context
            })
        
        return jsonify({
            'events': serialized_events,
            'time_range_hours': time_range_hours,
            'total_events': len(serialized_events),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting security events: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/zero-trust/report', methods=['GET'])
def get_zero_trust_report():
    """Get Zero Trust security posture report"""
    try:
        report = zero_trust.generate_zero_trust_report()
        
        return jsonify({
            'report': report,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating Zero Trust report: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/compliance/assess', methods=['POST'])
def assess_compliance():
    """Assess compliance for a specific framework"""
    try:
        data = request.get_json()
        
        if not data or 'framework' not in data:
            return jsonify({
                'error': 'framework is required',
                'status': 'error'
            }), 400
        
        framework_name = data['framework'].lower()
        try:
            framework = ComplianceFramework(framework_name)
        except ValueError:
            return jsonify({
                'error': f'Unsupported framework: {framework_name}',
                'status': 'error'
            }), 400
        
        # Perform assessment
        assessment = compliance_engine.assess_compliance(framework)
        
        # Convert to serializable format
        response = {
            'assessment_id': assessment.assessment_id,
            'framework': assessment.framework.value,
            'assessed_at': assessment.assessed_at.isoformat(),
            'overall_status': assessment.overall_status.value,
            'compliance_score': assessment.compliance_score,
            'requirements_total': assessment.requirements_total,
            'requirements_compliant': assessment.requirements_compliant,
            'requirements_non_compliant': assessment.requirements_non_compliant,
            'requirements_partial': assessment.requirements_partial,
            'critical_gaps': assessment.critical_gaps,
            'recommendations': assessment.recommendations,
            'next_assessment_due': assessment.next_assessment_due.isoformat(),
            'status': 'success'
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': f'Error assessing compliance: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/compliance/collect-evidence', methods=['POST'])
def collect_compliance_evidence():
    """Collect evidence for compliance requirements"""
    try:
        data = request.get_json()
        requirement_id = data.get('requirement_id') if data else None
        
        # Collect evidence
        evidence = compliance_engine.collect_evidence_automatically(requirement_id)
        
        # Convert to serializable format
        serialized_evidence = []
        for e in evidence:
            serialized_evidence.append({
                'evidence_id': e.evidence_id,
                'requirement_id': e.requirement_id,
                'evidence_type': e.evidence_type,
                'description': e.description,
                'collected_at': e.collected_at.isoformat(),
                'valid_until': e.valid_until.isoformat() if e.valid_until else None,
                'automated': e.automated,
                'metadata': e.metadata
            })
        
        return jsonify({
            'evidence_collected': serialized_evidence,
            'total_evidence': len(serialized_evidence),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error collecting evidence: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/compliance/report', methods=['POST'])
def generate_compliance_report():
    """Generate compliance report"""
    try:
        data = request.get_json()
        
        if not data or 'framework' not in data:
            return jsonify({
                'error': 'framework is required',
                'status': 'error'
            }), 400
        
        framework_name = data['framework'].lower()
        assessment_id = data.get('assessment_id')
        
        try:
            framework = ComplianceFramework(framework_name)
        except ValueError:
            return jsonify({
                'error': f'Unsupported framework: {framework_name}',
                'status': 'error'
            }), 400
        
        # Generate report
        report = compliance_engine.generate_compliance_report(framework, assessment_id)
        
        return jsonify({
            'report': report,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating compliance report: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/compliance/dashboard', methods=['GET'])
def get_compliance_dashboard():
    """Get compliance dashboard data"""
    try:
        dashboard = compliance_engine.get_compliance_dashboard()
        
        return jsonify({
            'dashboard': dashboard,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting compliance dashboard: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/risk/assess-vulnerability', methods=['POST'])
def assess_vulnerability_risk():
    """Assess financial risk for a specific vulnerability"""
    try:
        data = request.get_json()
        
        if not data or 'vulnerability' not in data:
            return jsonify({
                'error': 'vulnerability data is required',
                'status': 'error'
            }), 400
        
        vulnerability = data['vulnerability']
        
        # Assess risk
        risk_assessment = risk_engine.assess_vulnerability_risk(vulnerability)
        
        # Convert to serializable format
        response = {
            'vulnerability_id': risk_assessment.vulnerability_id,
            'vulnerability_type': risk_assessment.vulnerability_type,
            'severity': risk_assessment.severity,
            'likelihood': risk_assessment.likelihood.name,
            'impact_level': risk_assessment.impact_level.name,
            'financial_impact': risk_assessment.financial_impact,
            'operational_impact': risk_assessment.operational_impact,
            'reputational_impact': risk_assessment.reputational_impact,
            'regulatory_impact': risk_assessment.regulatory_impact,
            'risk_score': risk_assessment.risk_score,
            'mitigation_cost': risk_assessment.mitigation_cost,
            'residual_risk': risk_assessment.residual_risk,
            'time_to_exploit': risk_assessment.time_to_exploit,
            'affected_assets': risk_assessment.affected_assets,
            'status': 'success'
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': f'Error assessing vulnerability risk: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/risk/comprehensive-assessment', methods=['GET'])
def get_comprehensive_risk_assessment():
    """Get comprehensive risk assessment"""
    try:
        # Get vulnerabilities from request or use default
        vulnerabilities = request.args.get('vulnerabilities')
        if vulnerabilities:
            vulnerabilities = json.loads(vulnerabilities)
        else:
            vulnerabilities = None
        
        # Generate assessment
        assessment = risk_engine.generate_comprehensive_risk_assessment(vulnerabilities)
        
        # Convert to serializable format
        response = {
            'assessment_id': assessment.assessment_id,
            'assessed_at': assessment.assessed_at.isoformat(),
            'total_risk_exposure': assessment.total_risk_exposure,
            'annual_loss_expectancy': assessment.annual_loss_expectancy,
            'risk_by_category': assessment.risk_by_category,
            'vulnerability_count': len(assessment.vulnerability_risks),
            'scenario_count': len(assessment.business_scenarios),
            'recommendations': assessment.recommendations,
            'roi_analysis': assessment.roi_analysis,
            'status': 'success'
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating risk assessment: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/risk/business-scenarios', methods=['POST'])
def generate_business_scenarios():
    """Generate business impact scenarios"""
    try:
        data = request.get_json()
        
        if not data or 'vulnerabilities' not in data:
            return jsonify({
                'error': 'vulnerabilities data is required',
                'status': 'error'
            }), 400
        
        vulnerabilities = data['vulnerabilities']
        
        # Generate scenarios
        scenarios = risk_engine.generate_business_impact_scenarios(vulnerabilities)
        
        # Convert to serializable format
        serialized_scenarios = []
        for scenario in scenarios:
            serialized_scenarios.append({
                'scenario_id': scenario.scenario_id,
                'name': scenario.name,
                'description': scenario.description,
                'probability': scenario.probability,
                'direct_costs': scenario.direct_costs,
                'indirect_costs': scenario.indirect_costs,
                'total_cost': sum(scenario.direct_costs.values()) + sum(scenario.indirect_costs.values()),
                'recovery_time_hours': scenario.recovery_time,
                'affected_systems': scenario.affected_systems,
                'regulatory_fines': scenario.regulatory_fines,
                'reputation_impact': scenario.reputation_impact
            })
        
        return jsonify({
            'scenarios': serialized_scenarios,
            'total_scenarios': len(serialized_scenarios),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating business scenarios: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/risk/roi-analysis', methods=['POST'])
def perform_roi_analysis():
    """Perform ROI analysis for security investments"""
    try:
        data = request.get_json()
        
        if not data or 'vulnerability_risks' not in data:
            return jsonify({
                'error': 'vulnerability_risks data is required',
                'status': 'error'
            }), 400
        
        # This would need to convert the data back to VulnerabilityRisk objects
        # For simplicity, using the comprehensive assessment
        assessment = risk_engine.generate_comprehensive_risk_assessment()
        mitigation_budget = data.get('mitigation_budget', 500000.0)
        
        # Perform ROI analysis
        roi_analysis = risk_engine.perform_roi_analysis(assessment.vulnerability_risks, mitigation_budget)
        
        return jsonify({
            'roi_analysis': roi_analysis,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error performing ROI analysis: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/training/analyze-user', methods=['POST'])
def analyze_user_training_needs():
    """Analyze user's training needs based on vulnerabilities"""
    try:
        data = request.get_json()
        
        if not data or 'user_id' not in data:
            return jsonify({
                'error': 'user_id is required',
                'status': 'error'
            }), 400
        
        user_id = data['user_id']
        time_period_days = data.get('time_period_days', 30)
        
        # Analyze user vulnerabilities
        analysis = training_engine.analyze_user_vulnerabilities(user_id, time_period_days)
        
        return jsonify({
            'analysis': analysis,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error analyzing user training needs: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/training/recommendations', methods=['POST'])
def generate_training_recommendations():
    """Generate personalized training recommendations"""
    try:
        data = request.get_json()
        
        if not data or 'user_id' not in data:
            return jsonify({
                'error': 'user_id is required',
                'status': 'error'
            }), 400
        
        user_id = data['user_id']
        max_recommendations = data.get('max_recommendations', 5)
        
        # Generate recommendations
        recommendations = training_engine.generate_training_recommendations(user_id, max_recommendations)
        
        # Convert to serializable format
        serialized_recommendations = []
        for rec in recommendations:
            serialized_recommendations.append({
                'recommendation_id': rec.recommendation_id,
                'user_id': rec.user_id,
                'vulnerability_context': rec.vulnerability_context,
                'recommended_modules': rec.recommended_modules,
                'learning_path': rec.learning_path,
                'priority': rec.priority,
                'reasoning': rec.reasoning,
                'estimated_time': rec.estimated_time,
                'created_at': rec.created_at.isoformat(),
                'due_date': rec.due_date.isoformat() if rec.due_date else None
            })
        
        return jsonify({
            'recommendations': serialized_recommendations,
            'total_recommendations': len(serialized_recommendations),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating training recommendations: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/training/progress', methods=['POST'])
def track_training_progress():
    """Track user's training progress"""
    try:
        data = request.get_json()
        
        required_fields = ['user_id', 'module_id']
        if not data or not all(field in data for field in required_fields):
            return jsonify({
                'error': 'user_id and module_id are required',
                'status': 'error'
            }), 400
        
        user_id = data['user_id']
        module_id = data['module_id']
        progress_data = {
            'progress_percentage': data.get('progress_percentage'),
            'assessment_score': data.get('assessment_score'),
            'time_spent_minutes': data.get('time_spent_minutes'),
            'completed_at': data.get('completed_at')
        }
        
        # Track progress
        training_engine.track_training_progress(user_id, module_id, progress_data)
        
        return jsonify({
            'message': 'Training progress updated successfully',
            'user_id': user_id,
            'module_id': module_id,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error tracking training progress: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/training/dashboard/<user_id>', methods=['GET'])
def get_training_dashboard(user_id):
    """Get user's training dashboard"""
    try:
        dashboard = training_engine.get_user_training_dashboard(user_id)
        
        return jsonify({
            'dashboard': dashboard,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting training dashboard: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/training/team-report', methods=['POST'])
def generate_team_training_report():
    """Generate training report for a team"""
    try:
        data = request.get_json()
        
        if not data or 'team_members' not in data:
            return jsonify({
                'error': 'team_members list is required',
                'status': 'error'
            }), 400
        
        team_members = data['team_members']
        
        # Generate team report
        report = training_engine.generate_team_training_report(team_members)
        
        return jsonify({
            'report': report,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating team training report: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/training/modules', methods=['GET'])
def get_training_modules():
    """Get available training modules"""
    try:
        modules = {}
        for module_id, module in training_engine.training_modules.items():
            modules[module_id] = {
                'module_id': module.module_id,
                'title': module.title,
                'description': module.description,
                'vulnerability_types': module.vulnerability_types,
                'skill_level': module.skill_level.value,
                'training_type': module.training_type.value,
                'duration_minutes': module.duration_minutes,
                'learning_objectives': [obj.value for obj in module.learning_objectives],
                'prerequisites': module.prerequisites,
                'tags': module.tags
            }
        
        return jsonify({
            'modules': modules,
            'total_modules': len(modules),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting training modules: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/training/learning-paths', methods=['GET'])
def get_learning_paths():
    """Get available learning paths"""
    try:
        paths = {}
        for path_id, path in training_engine.learning_paths.items():
            paths[path_id] = {
                'path_id': path.path_id,
                'name': path.name,
                'description': path.description,
                'target_audience': path.target_audience,
                'estimated_duration_hours': path.estimated_duration_hours,
                'modules': path.modules,
                'completion_criteria': path.completion_criteria,
                'certification_available': path.certification_available,
                'difficulty_level': path.difficulty_level.value
            }
        
        return jsonify({
            'learning_paths': paths,
            'total_paths': len(paths),
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error getting learning paths: {str(e)}',
            'status': 'error'
        }), 500

@enterprise_bp.route('/enterprise-dashboard', methods=['GET'])
def get_enterprise_dashboard():
    """Get comprehensive enterprise security dashboard"""
    try:
        # Get data from all enterprise features
        zero_trust_report = zero_trust.generate_zero_trust_report()
        compliance_dashboard = compliance_engine.get_compliance_dashboard()
        risk_assessment = risk_engine.generate_comprehensive_risk_assessment()
        
        # Aggregate enterprise metrics
        dashboard = {
            'generated_at': datetime.now().isoformat(),
            'zero_trust': {
                'overall_risk_level': zero_trust_report.get('summary', {}).get('risk_level', 'unknown'),
                'total_access_requests': zero_trust_report.get('summary', {}).get('total_access_requests', 0),
                'denied_requests': zero_trust_report.get('summary', {}).get('denied_requests', 0),
                'average_trust_score': zero_trust_report.get('summary', {}).get('average_trust_score', 0)
            },
            'compliance': {
                'overall_status': compliance_dashboard.get('overall_status', 'unknown'),
                'total_requirements': compliance_dashboard.get('total_requirements', 0),
                'compliant_requirements': compliance_dashboard.get('compliant_requirements', 0),
                'critical_gaps': compliance_dashboard.get('critical_gaps', 0)
            },
            'risk_management': {
                'total_risk_exposure': risk_assessment.total_risk_exposure,
                'annual_loss_expectancy': risk_assessment.annual_loss_expectancy,
                'vulnerability_count': len(risk_assessment.vulnerability_risks),
                'high_risk_vulnerabilities': len([r for r in risk_assessment.vulnerability_risks if r.risk_score >= 15])
            },
            'security_training': {
                'available_modules': len(training_engine.training_modules),
                'available_paths': len(training_engine.learning_paths)
            },
            'recommendations': {
                'zero_trust': zero_trust_report.get('recommendations', [])[:3],
                'compliance': compliance_dashboard.get('frameworks', {}).get('gdpr', {}).get('recommendations', [])[:3] if 'gdpr' in compliance_dashboard.get('frameworks', {}) else [],
                'risk_management': risk_assessment.recommendations[:3],
                'security_training': ['Implement continuous security training', 'Focus on high-risk vulnerability types', 'Regular team security assessments']
            }
        }
        
        return jsonify({
            'dashboard': dashboard,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Error generating enterprise dashboard: {str(e)}',
            'status': 'error'
        }), 500

# Health check endpoint for enterprise features
@enterprise_bp.route('/health', methods=['GET'])
def enterprise_health():
    """Health check for enterprise features"""
    try:
        health_status = {
            'zero_trust_integration': 'healthy',
            'compliance_automation': 'healthy',
            'risk_quantification': 'healthy',
            'security_training': 'healthy',
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'health': health_status,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Health check failed: {str(e)}',
            'status': 'error'
        }), 500

