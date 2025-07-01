"""
Advanced ML Service for AI Guardian Enhanced v4.0.0
Custom Neural Networks for Vulnerability Detection
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
import sys
from datetime import datetime

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.vulnerability_transformer import VulnerabilityTransformer
from models.code_bert_enhanced import CodeBERTEnhanced
from models.graph_neural_network import GraphNeuralNetwork
from models.ensemble_detector import EnsembleDetector
from training.model_trainer import ModelTrainer
from inference.prediction_engine import PredictionEngine
from data.data_processor import DataProcessor

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global model instances
vulnerability_transformer = None
code_bert_enhanced = None
graph_neural_network = None
ensemble_detector = None
prediction_engine = None
data_processor = None

def initialize_models():
    """Initialize all ML models"""
    global vulnerability_transformer, code_bert_enhanced, graph_neural_network
    global ensemble_detector, prediction_engine, data_processor
    
    try:
        logger.info("Initializing Advanced ML Models...")
        
        # Initialize data processor
        data_processor = DataProcessor()
        
        # Initialize individual models
        vulnerability_transformer = VulnerabilityTransformer()
        code_bert_enhanced = CodeBERTEnhanced()
        graph_neural_network = GraphNeuralNetwork()
        
        # Initialize ensemble detector
        ensemble_detector = EnsembleDetector([
            vulnerability_transformer,
            code_bert_enhanced,
            graph_neural_network
        ])
        
        # Initialize prediction engine
        prediction_engine = PredictionEngine(ensemble_detector)
        
        logger.info("All ML models initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing models: {e}")
        raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "4.0.0",
    })

@app.route('/api/ml/predict-vulnerability', methods=['POST'])
def predict_vulnerability():
    """Predict vulnerabilities using advanced ML models"""
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({"error": "Code is required"}), 400
        
        code = data['code']
        language = data.get('language', 'python')
        context = data.get('context', {})
        
        # Process code through prediction engine
        prediction = prediction_engine.predict(
            code=code,
            language=language,
            context=context
        )
        
        return jsonify({
            "prediction": prediction,
            "timestamp": datetime.utcnow().isoformat(),
            "model_version": "4.0.0"
        })
        
    except Exception as e:
        logger.error(f"Error in vulnerability prediction: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml/analyze-code-patterns', methods=['POST'])
def analyze_code_patterns():
    """Analyze code patterns using transformer models"""
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({"error": "Code is required"}), 400
        
        code = data['code']
        analysis_type = data.get('analysis_type', 'comprehensive')
        
        # Analyze using vulnerability transformer
        patterns = vulnerability_transformer.analyze_patterns(
            code=code,
            analysis_type=analysis_type
        )
        
        return jsonify({
            "patterns": patterns,
            "analysis_type": analysis_type,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in pattern analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml/graph-analysis', methods=['POST'])
def graph_analysis():
    """Perform graph-based code analysis"""
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({"error": "Code is required"}), 400
        
        code = data['code']
        language = data.get('language', 'python')
        
        # Perform graph analysis
        graph_result = graph_neural_network.analyze_code_graph(
            code=code,
            language=language
        )
        
        return jsonify({
            "graph_analysis": graph_result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in graph analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml/ensemble-prediction', methods=['POST'])
def ensemble_prediction():
    """Get ensemble prediction from multiple models"""
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({"error": "Code is required"}), 400
        
        code = data['code']
        language = data.get('language', 'python')
        confidence_threshold = data.get('confidence_threshold', 0.7)
        
        # Get ensemble prediction
        ensemble_result = ensemble_detector.predict_ensemble(
            code=code,
            language=language,
            confidence_threshold=confidence_threshold
        )
        
        return jsonify({
            "ensemble_prediction": ensemble_result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in ensemble prediction: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml/train-model', methods=['POST'])
def train_model():
    """Train or retrain ML models"""
    try:
        data = request.get_json()
        
        model_type = data.get('model_type', 'vulnerability_transformer')
        training_data_path = data.get('training_data_path')
        epochs = data.get('epochs', 10)
        
        if not training_data_path:
            return jsonify({"error": "Training data path is required"}), 400
        
        # Initialize trainer
        trainer = ModelTrainer()
        
        # Start training
        training_result = trainer.train_model(
            model_type=model_type,
            training_data_path=training_data_path,
            epochs=epochs
        )
        
        return jsonify({
            "training_result": training_result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in model training: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml/model-metrics', methods=['GET'])
def get_model_metrics():
    """Get performance metrics for all models"""
    try:
        metrics = {
            "vulnerability_transformer": vulnerability_transformer.get_metrics() if vulnerability_transformer else None,
            "code_bert_enhanced": code_bert_enhanced.get_metrics() if code_bert_enhanced else None,
            "graph_neural_network": graph_neural_network.get_metrics() if graph_neural_network else None,
            "ensemble_detector": ensemble_detector.get_metrics() if ensemble_detector else None
        }
        
        return jsonify({
            "metrics": metrics,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting model metrics: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml/update-model', methods=['POST'])
def update_model():
    """Update model with new data"""
    try:
        data = request.get_json()
        
        model_type = data.get('model_type')
        update_data = data.get('update_data')
        
        if not model_type or not update_data:
            return jsonify({"error": "Model type and update data are required"}), 400
        
        # Update the specified model
        if model_type == 'vulnerability_transformer':
            result = vulnerability_transformer.update_model(update_data)
        elif model_type == 'code_bert_enhanced':
            result = code_bert_enhanced.update_model(update_data)
        elif model_type == 'graph_neural_network':
            result = graph_neural_network.update_model(update_data)
        else:
            return jsonify({"error": "Invalid model type"}), 400
        
        return jsonify({
            "update_result": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error updating model: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Initialize models on startup
    initialize_models()
    
    # Start the Flask app
    port = int(os.environ.get('PORT', 5003))
    app.run(host='0.0.0.0', port=port, debug=False)

