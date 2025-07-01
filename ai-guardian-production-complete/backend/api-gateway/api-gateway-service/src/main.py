import os
import sys
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
from flask_migrate import Migrate

# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.models.user import db
from src.routes.user import user_bp
from src.routes.ide import ide_bp
from src.routes.sso import sso_bp
from src.routes.analytics import analytics_bp
from src.routes.rate_limiting import rate_limit_bp
from src.routes.multi_tenant import multi_tenant_bp


app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), 'static')
)
app.config['SECRET_KEY'] = 'ai-guardian-api-gateway-secret-key-2025'

# Enable CORS for all routes
CORS(app)

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(ide_bp, url_prefix='/api/ide')
app.register_blueprint(sso_bp, url_prefix='/api/sso')
app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
app.register_blueprint(rate_limit_bp, url_prefix='/api/rate-limit')
app.register_blueprint(multi_tenant_bp, url_prefix='/api/tenant')


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "version": "4.0.0"})


# Database configuration
# Use DATABASE_URL from environment for production, fallback to local SQLite
DB_URL = os.environ.get(
    'DATABASE_URL',
    f"sqlite:///{os.path.join(os.path.dirname(__file__), 'database', 'app.db')}"
)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    static_folder_path = app.static_folder
    if not static_folder_path:
        return "Static folder not configured", 404

    if path and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, 'index.html')
        else:
            return "index.html not found", 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)
