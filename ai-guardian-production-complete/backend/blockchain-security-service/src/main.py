"""
Blockchain Security Service for AI Guardian Enhanced v4.0.0
Comprehensive Smart Contract and DeFi Security Analysis
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
import sys
from datetime import datetime

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzers.smart_contract_analyzer import SmartContractAnalyzer
from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.vyper_analyzer import VyperAnalyzer
from defi.defi_security_analyzer import DeFiSecurityAnalyzer
from defi.liquidity_pool_analyzer import LiquidityPoolAnalyzer
from monitoring.blockchain_monitor import BlockchainMonitor
from monitoring.transaction_analyzer import TransactionAnalyzer

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
smart_contract_analyzer = None
solidity_analyzer = None
vyper_analyzer = None
defi_security_analyzer = None
liquidity_pool_analyzer = None
blockchain_monitor = None
transaction_analyzer = None

def initialize_services():
    """Initialize all blockchain security services"""
    global smart_contract_analyzer, solidity_analyzer, vyper_analyzer
    global defi_security_analyzer, liquidity_pool_analyzer, blockchain_monitor, transaction_analyzer
    
    try:
        logger.info("Initializing Blockchain Security Services...")
        
        # Initialize contract analyzers
        smart_contract_analyzer = SmartContractAnalyzer()
        solidity_analyzer = SolidityAnalyzer()
        vyper_analyzer = VyperAnalyzer()
        
        # Initialize DeFi analyzers
        defi_security_analyzer = DeFiSecurityAnalyzer()
        liquidity_pool_analyzer = LiquidityPoolAnalyzer()
        
        # Initialize monitoring services
        blockchain_monitor = BlockchainMonitor()
        transaction_analyzer = TransactionAnalyzer()
        
        logger.info("All blockchain security services initialized successfully")
        
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

@app.route('/api/blockchain/analyze-smart-contract', methods=['POST'])
def analyze_smart_contract():
    """Analyze smart contract for vulnerabilities"""
    try:
        data = request.get_json()
        
        if not data or 'contract_code' not in data:
            return jsonify({"error": "Contract code is required"}), 400
        
        contract_code = data['contract_code']
        language = data.get('language', 'solidity')
        contract_address = data.get('contract_address')
        
        # Choose appropriate analyzer based on language
        if language.lower() == 'solidity':
            analyzer = solidity_analyzer
        elif language.lower() == 'vyper':
            analyzer = vyper_analyzer
        else:
            analyzer = smart_contract_analyzer
        
        # Perform comprehensive analysis
        analysis_result = analyzer.analyze_contract(
            contract_code=contract_code,
            contract_address=contract_address
        )
        
        return jsonify({
            "analysis": analysis_result,
            "language": language,
            "timestamp": datetime.utcnow().isoformat(),
            "analyzer_version": "4.0.0"
        })
        
    except Exception as e:
        logger.error(f"Error in smart contract analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/analyze-defi-protocol', methods=['POST'])
def analyze_defi_protocol():
    """Analyze DeFi protocol for security issues"""
    try:
        data = request.get_json()
        
        if not data or 'protocol_address' not in data:
            return jsonify({"error": "Protocol address is required"}), 400
        
        protocol_address = data['protocol_address']
        protocol_type = data.get('protocol_type', 'unknown')
        analysis_depth = data.get('analysis_depth', 'comprehensive')
        
        # Perform DeFi security analysis
        defi_analysis = defi_security_analyzer.analyze_protocol(
            protocol_address=protocol_address,
            protocol_type=protocol_type,
            analysis_depth=analysis_depth
        )
        
        return jsonify({
            "defi_analysis": defi_analysis,
            "protocol_type": protocol_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in DeFi protocol analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/analyze-liquidity-pool', methods=['POST'])
def analyze_liquidity_pool():
    """Analyze liquidity pool for risks"""
    try:
        data = request.get_json()
        
        if not data or 'pool_address' not in data:
            return jsonify({"error": "Pool address is required"}), 400
        
        pool_address = data['pool_address']
        dex_platform = data.get('dex_platform', 'uniswap')
        
        # Analyze liquidity pool
        pool_analysis = liquidity_pool_analyzer.analyze_pool(
            pool_address=pool_address,
            dex_platform=dex_platform
        )
        
        return jsonify({
            "pool_analysis": pool_analysis,
            "dex_platform": dex_platform,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in liquidity pool analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/monitor-transactions', methods=['POST'])
def monitor_transactions():
    """Monitor blockchain transactions for suspicious activity"""
    try:
        data = request.get_json()
        
        blockchain = data.get('blockchain', 'ethereum')
        addresses = data.get('addresses', [])
        time_range = data.get('time_range', '24h')
        
        # Monitor transactions
        monitoring_result = transaction_analyzer.monitor_transactions(
            blockchain=blockchain,
            addresses=addresses,
            time_range=time_range
        )
        
        return jsonify({
            "monitoring_result": monitoring_result,
            "blockchain": blockchain,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in transaction monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/detect-rug-pull', methods=['POST'])
def detect_rug_pull():
    """Detect potential rug pull schemes"""
    try:
        data = request.get_json()
        
        if not data or 'token_address' not in data:
            return jsonify({"error": "Token address is required"}), 400
        
        token_address = data['token_address']
        blockchain = data.get('blockchain', 'ethereum')
        
        # Detect rug pull indicators
        rug_pull_analysis = defi_security_analyzer.detect_rug_pull(
            token_address=token_address,
            blockchain=blockchain
        )
        
        return jsonify({
            "rug_pull_analysis": rug_pull_analysis,
            "token_address": token_address,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in rug pull detection: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/analyze-flash-loan', methods=['POST'])
def analyze_flash_loan():
    """Analyze flash loan transactions for attacks"""
    try:
        data = request.get_json()
        
        if not data or 'transaction_hash' not in data:
            return jsonify({"error": "Transaction hash is required"}), 400
        
        transaction_hash = data['transaction_hash']
        blockchain = data.get('blockchain', 'ethereum')
        
        # Analyze flash loan transaction
        flash_loan_analysis = transaction_analyzer.analyze_flash_loan(
            transaction_hash=transaction_hash,
            blockchain=blockchain
        )
        
        return jsonify({
            "flash_loan_analysis": flash_loan_analysis,
            "transaction_hash": transaction_hash,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in flash loan analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/audit-report', methods=['POST'])
def generate_audit_report():
    """Generate comprehensive blockchain security audit report"""
    try:
        data = request.get_json()
        
        if not data or 'target' not in data:
            return jsonify({"error": "Audit target is required"}), 400
        
        target = data['target']
        target_type = data.get('target_type', 'smart_contract')
        audit_scope = data.get('audit_scope', 'comprehensive')
        
        # Generate audit report
        if target_type == 'smart_contract':
            audit_report = smart_contract_analyzer.generate_audit_report(
                contract_address=target,
                audit_scope=audit_scope
            )
        elif target_type == 'defi_protocol':
            audit_report = defi_security_analyzer.generate_audit_report(
                protocol_address=target,
                audit_scope=audit_scope
            )
        else:
            return jsonify({"error": "Invalid target type"}), 400
        
        return jsonify({
            "audit_report": audit_report,
            "target": target,
            "target_type": target_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error generating audit report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/real-time-alerts', methods=['GET'])
def get_real_time_alerts():
    """Get real-time blockchain security alerts"""
    try:
        blockchain = request.args.get('blockchain', 'ethereum')
        alert_types = request.args.getlist('alert_types')
        
        # Get real-time alerts
        alerts = blockchain_monitor.get_real_time_alerts(
            blockchain=blockchain,
            alert_types=alert_types
        )
        
        return jsonify({
            "alerts": alerts,
            "blockchain": blockchain,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting real-time alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/compliance-check', methods=['POST'])
def compliance_check():
    """Check blockchain compliance with regulations"""
    try:
        data = request.get_json()
        
        if not data or 'address' not in data:
            return jsonify({"error": "Address is required"}), 400
        
        address = data['address']
        regulations = data.get('regulations', ['AML', 'KYC', 'FATF'])
        blockchain = data.get('blockchain', 'ethereum')
        
        # Perform compliance check
        compliance_result = blockchain_monitor.check_compliance(
            address=address,
            regulations=regulations,
            blockchain=blockchain
        )
        
        return jsonify({
            "compliance_result": compliance_result,
            "address": address,
            "regulations": regulations,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in compliance check: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/blockchain/gas-optimization', methods=['POST'])
def gas_optimization():
    """Analyze and suggest gas optimizations"""
    try:
        data = request.get_json()
        
        if not data or 'contract_code' not in data:
            return jsonify({"error": "Contract code is required"}), 400
        
        contract_code = data['contract_code']
        language = data.get('language', 'solidity')
        
        # Analyze gas optimization opportunities
        if language.lower() == 'solidity':
            optimization_result = solidity_analyzer.analyze_gas_optimization(
                contract_code=contract_code
            )
        else:
            optimization_result = smart_contract_analyzer.analyze_gas_optimization(
                contract_code=contract_code
            )
        
        return jsonify({
            "optimization_result": optimization_result,
            "language": language,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in gas optimization analysis: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Initialize services on startup
    initialize_services()
    
    # Start the Flask app
    port = int(os.environ.get('PORT', 5004))
    app.run(host='0.0.0.0', port=port, debug=False)

