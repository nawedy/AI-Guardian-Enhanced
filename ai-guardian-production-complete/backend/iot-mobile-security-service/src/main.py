"""
IoT and Mobile Security Service for AI Guardian Enhanced v4.0.0
Comprehensive IoT Device and Mobile Application Security Analysis
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
import sys
from datetime import datetime

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from iot.iot_device_analyzer import IoTDeviceAnalyzer
from iot.firmware_analyzer import FirmwareAnalyzer
from mobile.android_analyzer import AndroidAnalyzer
from mobile.ios_analyzer import iOSAnalyzer
from mobile.mobile_app_analyzer import MobileAppAnalyzer
from network.network_security_analyzer import NetworkSecurityAnalyzer
from network.protocol_analyzer import ProtocolAnalyzer

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global service instances
iot_device_analyzer = None
firmware_analyzer = None
android_analyzer = None
ios_analyzer = None
mobile_app_analyzer = None
network_security_analyzer = None
protocol_analyzer = None

def initialize_services():
    """Initialize all IoT and mobile security services"""
    global iot_device_analyzer, firmware_analyzer, android_analyzer
    global ios_analyzer, mobile_app_analyzer, network_security_analyzer, protocol_analyzer
    
    try:
        logger.info("Initializing IoT and Mobile Security Services...")
        
        # Initialize IoT analyzers
        iot_device_analyzer = IoTDeviceAnalyzer()
        firmware_analyzer = FirmwareAnalyzer()
        
        # Initialize mobile analyzers
        android_analyzer = AndroidAnalyzer()
        ios_analyzer = iOSAnalyzer()
        mobile_app_analyzer = MobileAppAnalyzer()
        
        # Initialize network analyzers
        network_security_analyzer = NetworkSecurityAnalyzer()
        protocol_analyzer = ProtocolAnalyzer()
        
        logger.info("All IoT and mobile security services initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing services: {e}")
        raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "4.0.0",
    })

@app.route('/api/iot/scan-device', methods=['POST'])
def scan_iot_device():
    """Scan IoT device for security vulnerabilities"""
    try:
        data = request.get_json()
        
        if not data or 'device_info' not in data:
            return jsonify({"error": "Device information is required"}), 400
        
        device_info = data['device_info']
        scan_type = data.get('scan_type', 'comprehensive')
        include_firmware = data.get('include_firmware', True)
        
        # Perform IoT device security scan
        scan_result = iot_device_analyzer.scan_device(
            device_info=device_info,
            scan_type=scan_type,
            include_firmware=include_firmware
        )
        
        return jsonify({
            "scan_result": scan_result,
            "device_info": device_info,
            "scan_type": scan_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in IoT device scan: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot/analyze-firmware', methods=['POST'])
def analyze_firmware():
    """Analyze IoT device firmware for vulnerabilities"""
    try:
        data = request.get_json()
        
        if not data or 'firmware_data' not in data:
            return jsonify({"error": "Firmware data is required"}), 400
        
        firmware_data = data['firmware_data']
        analysis_type = data.get('analysis_type', 'static')
        
        # Perform firmware analysis
        analysis_result = firmware_analyzer.analyze_firmware(
            firmware_data=firmware_data,
            analysis_type=analysis_type
        )
        
        return jsonify({
            "analysis_result": analysis_result,
            "analysis_type": analysis_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in firmware analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/mobile/analyze-android-app', methods=['POST'])
def analyze_android_app():
    """Analyze Android application for security vulnerabilities"""
    try:
        data = request.get_json()
        
        if not data or 'app_data' not in data:
            return jsonify({"error": "Android app data is required"}), 400
        
        app_data = data['app_data']
        analysis_depth = data.get('analysis_depth', 'comprehensive')
        include_permissions = data.get('include_permissions', True)
        
        # Perform Android app analysis
        analysis_result = android_analyzer.analyze_app(
            app_data=app_data,
            analysis_depth=analysis_depth,
            include_permissions=include_permissions
        )
        
        return jsonify({
            "analysis_result": analysis_result,
            "platform": "android",
            "analysis_depth": analysis_depth,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in Android app analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/mobile/analyze-ios-app', methods=['POST'])
def analyze_ios_app():
    """Analyze iOS application for security vulnerabilities"""
    try:
        data = request.get_json()
        
        if not data or 'app_data' not in data:
            return jsonify({"error": "iOS app data is required"}), 400
        
        app_data = data['app_data']
        analysis_depth = data.get('analysis_depth', 'comprehensive')
        include_entitlements = data.get('include_entitlements', True)
        
        # Perform iOS app analysis
        analysis_result = ios_analyzer.analyze_app(
            app_data=app_data,
            analysis_depth=analysis_depth,
            include_entitlements=include_entitlements
        )
        
        return jsonify({
            "analysis_result": analysis_result,
            "platform": "ios",
            "analysis_depth": analysis_depth,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in iOS app analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/mobile/cross-platform-analysis', methods=['POST'])
def cross_platform_analysis():
    """Perform cross-platform mobile security analysis"""
    try:
        data = request.get_json()
        
        if not data or 'apps' not in data:
            return jsonify({"error": "App data for multiple platforms is required"}), 400
        
        apps = data['apps']
        comparison_type = data.get('comparison_type', 'security_posture')
        
        # Perform cross-platform analysis
        analysis_result = mobile_app_analyzer.cross_platform_analysis(
            apps=apps,
            comparison_type=comparison_type
        )
        
        return jsonify({
            "analysis_result": analysis_result,
            "comparison_type": comparison_type,
            "platforms_analyzed": len(apps),
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in cross-platform analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/network/analyze-iot-network', methods=['POST'])
def analyze_iot_network():
    """Analyze IoT network security"""
    try:
        data = request.get_json()
        
        if not data or 'network_config' not in data:
            return jsonify({"error": "Network configuration is required"}), 400
        
        network_config = data['network_config']
        scan_protocols = data.get('scan_protocols', ['mqtt', 'coap', 'zigbee', 'wifi'])
        
        # Perform network security analysis
        analysis_result = network_security_analyzer.analyze_iot_network(
            network_config=network_config,
            scan_protocols=scan_protocols
        )
        
        return jsonify({
            "analysis_result": analysis_result,
            "protocols_scanned": scan_protocols,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in IoT network analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/network/analyze-protocol', methods=['POST'])
def analyze_protocol():
    """Analyze specific IoT protocol security"""
    try:
        data = request.get_json()
        
        if not data or 'protocol' not in data:
            return jsonify({"error": "Protocol type is required"}), 400
        
        protocol = data['protocol']
        traffic_data = data.get('traffic_data', {})
        analysis_type = data.get('analysis_type', 'security_assessment')
        
        # Perform protocol analysis
        analysis_result = protocol_analyzer.analyze_protocol(
            protocol=protocol,
            traffic_data=traffic_data,
            analysis_type=analysis_type
        )
        
        return jsonify({
            "analysis_result": analysis_result,
            "protocol": protocol,
            "analysis_type": analysis_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in protocol analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot/device-discovery', methods=['POST'])
def discover_iot_devices():
    """Discover IoT devices on network"""
    try:
        data = request.get_json()
        
        network_range = data.get('network_range', '192.168.1.0/24')
        discovery_methods = data.get('discovery_methods', ['nmap', 'mdns', 'upnp'])
        
        # Perform device discovery
        discovery_result = iot_device_analyzer.discover_devices(
            network_range=network_range,
            discovery_methods=discovery_methods
        )
        
        return jsonify({
            "discovery_result": discovery_result,
            "network_range": network_range,
            "methods_used": discovery_methods,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in device discovery: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/mobile/privacy-analysis', methods=['POST'])
def mobile_privacy_analysis():
    """Analyze mobile app privacy practices"""
    try:
        data = request.get_json()
        
        if not data or 'app_data' not in data:
            return jsonify({"error": "App data is required"}), 400
        
        app_data = data['app_data']
        privacy_frameworks = data.get('privacy_frameworks', ['gdpr', 'ccpa', 'coppa'])
        
        # Perform privacy analysis
        privacy_result = mobile_app_analyzer.analyze_privacy(
            app_data=app_data,
            privacy_frameworks=privacy_frameworks
        )
        
        return jsonify({
            "privacy_analysis": privacy_result,
            "frameworks_checked": privacy_frameworks,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in privacy analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot/vulnerability-assessment', methods=['POST'])
def iot_vulnerability_assessment():
    """Comprehensive IoT vulnerability assessment"""
    try:
        data = request.get_json()
        
        if not data or 'targets' not in data:
            return jsonify({"error": "Assessment targets are required"}), 400
        
        targets = data['targets']
        assessment_type = data.get('assessment_type', 'comprehensive')
        include_penetration_testing = data.get('include_penetration_testing', False)
        
        # Perform vulnerability assessment
        assessment_result = iot_device_analyzer.vulnerability_assessment(
            targets=targets,
            assessment_type=assessment_type,
            include_penetration_testing=include_penetration_testing
        )
        
        return jsonify({
            "assessment_result": assessment_result,
            "targets_assessed": len(targets),
            "assessment_type": assessment_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in vulnerability assessment: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/mobile/malware-detection', methods=['POST'])
def mobile_malware_detection():
    """Detect malware in mobile applications"""
    try:
        data = request.get_json()
        
        if not data or 'app_data' not in data:
            return jsonify({"error": "App data is required"}), 400
        
        app_data = data['app_data']
        detection_methods = data.get('detection_methods', ['static', 'dynamic', 'behavioral'])
        
        # Perform malware detection
        detection_result = mobile_app_analyzer.detect_malware(
            app_data=app_data,
            detection_methods=detection_methods
        )
        
        return jsonify({
            "malware_detection": detection_result,
            "detection_methods": detection_methods,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in malware detection: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot/security-audit', methods=['POST'])
def iot_security_audit():
    """Comprehensive IoT security audit"""
    try:
        data = request.get_json()
        
        if not data or 'audit_scope' not in data:
            return jsonify({"error": "Audit scope is required"}), 400
        
        audit_scope = data['audit_scope']
        compliance_frameworks = data.get('compliance_frameworks', ['nist', 'iot_security_foundation'])
        
        # Perform security audit
        audit_result = iot_device_analyzer.security_audit(
            audit_scope=audit_scope,
            compliance_frameworks=compliance_frameworks
        )
        
        return jsonify({
            "audit_result": audit_result,
            "compliance_frameworks": compliance_frameworks,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in security audit: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/mobile/app-store-analysis', methods=['POST'])
def app_store_analysis():
    """Analyze mobile app from app store"""
    try:
        data = request.get_json()
        
        if not data or 'app_identifier' not in data:
            return jsonify({"error": "App identifier is required"}), 400
        
        app_identifier = data['app_identifier']
        store_platform = data.get('store_platform', 'google_play')
        analysis_depth = data.get('analysis_depth', 'standard')
        
        # Perform app store analysis
        analysis_result = mobile_app_analyzer.analyze_from_store(
            app_identifier=app_identifier,
            store_platform=store_platform,
            analysis_depth=analysis_depth
        )
        
        return jsonify({
            "analysis_result": analysis_result,
            "app_identifier": app_identifier,
            "store_platform": store_platform,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in app store analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/generate-iot-report', methods=['POST'])
def generate_iot_report():
    """Generate comprehensive IoT security report"""
    try:
        data = request.get_json()
        
        if not data or 'report_scope' not in data:
            return jsonify({"error": "Report scope is required"}), 400
        
        report_scope = data['report_scope']
        report_format = data.get('report_format', 'comprehensive')
        include_recommendations = data.get('include_recommendations', True)
        
        # Generate IoT security report
        report = iot_device_analyzer.generate_security_report(
            report_scope=report_scope,
            report_format=report_format,
            include_recommendations=include_recommendations
        )
        
        return jsonify({
            "report": report,
            "report_scope": report_scope,
            "report_format": report_format,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error generating IoT report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/generate-mobile-report', methods=['POST'])
def generate_mobile_report():
    """Generate comprehensive mobile security report"""
    try:
        data = request.get_json()
        
        if not data or 'apps' not in data:
            return jsonify({"error": "App data is required"}), 400
        
        apps = data['apps']
        report_type = data.get('report_type', 'security_assessment')
        include_compliance = data.get('include_compliance', True)
        
        # Generate mobile security report
        report = mobile_app_analyzer.generate_security_report(
            apps=apps,
            report_type=report_type,
            include_compliance=include_compliance
        )
        
        return jsonify({
            "report": report,
            "apps_analyzed": len(apps),
            "report_type": report_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error generating mobile report: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Initialize services on startup
    initialize_services()
    
    # Start the Flask app
    port = int(os.environ.get('PORT', 5005))
    app.run(host='0.0.0.0', port=port, debug=False)

