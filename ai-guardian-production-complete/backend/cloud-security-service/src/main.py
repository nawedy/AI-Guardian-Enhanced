"""
Multi-Cloud Security Service for AI Guardian Enhanced v4.0.0
Comprehensive cloud security posture management across AWS, Azure, GCP, and more
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import cloud-specific analyzers
from src.aws.aws_security_analyzer import AWSSecurityAnalyzer
from src.azure.azure_security_analyzer import AzureSecurityAnalyzer
from src.gcp.gcp_security_analyzer import GCPSecurityAnalyzer
from src.multi_cloud.unified_analyzer import UnifiedCloudAnalyzer
from src.compliance.cloud_compliance import CloudComplianceAnalyzer
from src.monitoring.cloud_monitor import CloudSecurityMonitor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize analyzers
aws_analyzer = AWSSecurityAnalyzer()
azure_analyzer = AzureSecurityAnalyzer()
gcp_analyzer = GCPSecurityAnalyzer()
unified_analyzer = UnifiedCloudAnalyzer()
compliance_analyzer = CloudComplianceAnalyzer()
security_monitor = CloudSecurityMonitor()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "4.0.0",
    })

@app.route('/api/v1/cloud/scan', methods=['POST'])
def scan_cloud_environment():
    """Scan cloud environment for security issues"""
    try:
        data = request.get_json()
        
        cloud_provider = data.get('cloud_provider')
        scan_config = data.get('scan_config', {})
        credentials = data.get('credentials', {})
        
        if cloud_provider == 'aws':
            result = aws_analyzer.scan_environment(credentials, scan_config)
        elif cloud_provider == 'azure':
            result = azure_analyzer.scan_environment(credentials, scan_config)
        elif cloud_provider == 'gcp':
            result = gcp_analyzer.scan_environment(credentials, scan_config)
        elif cloud_provider == 'multi':
            result = unified_analyzer.scan_multi_cloud(data.get('cloud_configs', {}))
        else:
            return jsonify({"error": "Unsupported cloud provider"}), 400
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in cloud scan: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/compliance', methods=['POST'])
def assess_cloud_compliance():
    """Assess cloud compliance against frameworks"""
    try:
        data = request.get_json()
        
        cloud_provider = data.get('cloud_provider')
        compliance_frameworks = data.get('frameworks', ['cis', 'nist'])
        scan_results = data.get('scan_results', {})
        
        result = compliance_analyzer.assess_compliance(
            cloud_provider, compliance_frameworks, scan_results
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in compliance assessment: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/posture', methods=['POST'])
def analyze_security_posture():
    """Analyze overall cloud security posture"""
    try:
        data = request.get_json()
        
        cloud_environments = data.get('environments', [])
        analysis_depth = data.get('analysis_depth', 'comprehensive')
        
        result = unified_analyzer.analyze_security_posture(
            cloud_environments, analysis_depth
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in posture analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/monitor/start', methods=['POST'])
def start_monitoring():
    """Start continuous cloud security monitoring"""
    try:
        data = request.get_json()
        
        monitoring_config = data.get('config', {})
        cloud_environments = data.get('environments', [])
        
        result = security_monitor.start_monitoring(
            cloud_environments, monitoring_config
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/monitor/status', methods=['GET'])
def get_monitoring_status():
    """Get current monitoring status"""
    try:
        result = security_monitor.get_monitoring_status()
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/remediation', methods=['POST'])
def get_remediation_recommendations():
    """Get remediation recommendations for cloud security issues"""
    try:
        data = request.get_json()
        
        security_findings = data.get('findings', [])
        cloud_provider = data.get('cloud_provider')
        remediation_level = data.get('level', 'detailed')
        
        if cloud_provider == 'aws':
            result = aws_analyzer.get_remediation_recommendations(
                security_findings, remediation_level
            )
        elif cloud_provider == 'azure':
            result = azure_analyzer.get_remediation_recommendations(
                security_findings, remediation_level
            )
        elif cloud_provider == 'gcp':
            result = gcp_analyzer.get_remediation_recommendations(
                security_findings, remediation_level
            )
        else:
            result = unified_analyzer.get_unified_remediation(
                security_findings, cloud_provider, remediation_level
            )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting remediation recommendations: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/cost-security', methods=['POST'])
def analyze_cost_security():
    """Analyze cost implications of security recommendations"""
    try:
        data = request.get_json()
        
        recommendations = data.get('recommendations', [])
        cloud_provider = data.get('cloud_provider')
        
        result = unified_analyzer.analyze_cost_security_impact(
            recommendations, cloud_provider
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in cost-security analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/threat-intelligence', methods=['POST'])
def get_threat_intelligence():
    """Get cloud-specific threat intelligence"""
    try:
        data = request.get_json()
        
        cloud_provider = data.get('cloud_provider')
        threat_categories = data.get('categories', ['all'])
        
        result = security_monitor.get_threat_intelligence(
            cloud_provider, threat_categories
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting threat intelligence: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/benchmark', methods=['POST'])
def run_security_benchmark():
    """Run security benchmarks against cloud environment"""
    try:
        data = request.get_json()
        
        cloud_provider = data.get('cloud_provider')
        benchmark_type = data.get('benchmark', 'cis')
        credentials = data.get('credentials', {})
        
        if cloud_provider == 'aws':
            result = aws_analyzer.run_security_benchmark(
                credentials, benchmark_type
            )
        elif cloud_provider == 'azure':
            result = azure_analyzer.run_security_benchmark(
                credentials, benchmark_type
            )
        elif cloud_provider == 'gcp':
            result = gcp_analyzer.run_security_benchmark(
                credentials, benchmark_type
            )
        else:
            return jsonify({"error": "Unsupported cloud provider"}), 400
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error running security benchmark: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/inventory', methods=['POST'])
def get_cloud_inventory():
    """Get comprehensive cloud resource inventory"""
    try:
        data = request.get_json()
        
        cloud_provider = data.get('cloud_provider')
        credentials = data.get('credentials', {})
        include_security_analysis = data.get('include_security', True)
        
        if cloud_provider == 'aws':
            result = aws_analyzer.get_resource_inventory(
                credentials, include_security_analysis
            )
        elif cloud_provider == 'azure':
            result = azure_analyzer.get_resource_inventory(
                credentials, include_security_analysis
            )
        elif cloud_provider == 'gcp':
            result = gcp_analyzer.get_resource_inventory(
                credentials, include_security_analysis
            )
        elif cloud_provider == 'multi':
            result = unified_analyzer.get_multi_cloud_inventory(
                data.get('cloud_configs', {}), include_security_analysis
            )
        else:
            return jsonify({"error": "Unsupported cloud provider"}), 400
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting cloud inventory: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/report', methods=['POST'])
def generate_security_report():
    """Generate comprehensive cloud security report"""
    try:
        data = request.get_json()
        
        report_scope = data.get('scope', {})
        report_format = data.get('format', 'comprehensive')
        include_remediation = data.get('include_remediation', True)
        
        result = unified_analyzer.generate_security_report(
            report_scope, report_format, include_remediation
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/drift-detection', methods=['POST'])
def detect_configuration_drift():
    """Detect configuration drift in cloud environments"""
    try:
        data = request.get_json()
        
        baseline_config = data.get('baseline', {})
        current_config = data.get('current', {})
        cloud_provider = data.get('cloud_provider')
        
        result = security_monitor.detect_configuration_drift(
            baseline_config, current_config, cloud_provider
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error detecting configuration drift: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/cloud/attack-surface', methods=['POST'])
def analyze_attack_surface():
    """Analyze cloud attack surface"""
    try:
        data = request.get_json()
        
        cloud_environment = data.get('environment', {})
        analysis_depth = data.get('depth', 'comprehensive')
        
        result = unified_analyzer.analyze_attack_surface(
            cloud_environment, analysis_depth
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error analyzing attack surface: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Multi-Cloud Security Service v4.0.0")
    app.run(host='0.0.0.0', port=5006, debug=False)

