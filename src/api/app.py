import os
import logging
from flask import Flask, Response, jsonify
from flask_cors import CORS
from src.config.settings import settings
from .routes.proxy import proxy_bp
from .routes.internal import internal_bp
from .routes.dashboard import dashboard_bp

def create_app() -> Flask:
    """Application factory for the WAF Flask app."""
    app = Flask(__name__, static_folder=None)
    
    # Configure CORS
    CORS(app, resources={r"/*": {"origins": settings.CORS_ORIGINS}})
    
    # Register blueprints (Internal/Dashboard first to take precedence over proxy)
    app.register_blueprint(internal_bp, url_prefix='/biubo-cgi')
    app.register_blueprint(dashboard_bp, url_prefix='/biubo-cgi')
    app.register_blueprint(proxy_bp)


    
    # Load global assets (Error pages)
    app.config['ERR_PAGES'] = _load_error_pages()
    
    return app

def _load_error_pages() -> dict:
    pages = {}
    page_files = {
        "404": "404.html", "400": "400.html", "403": "403.html", 
        "429": "429.html", "500": "500.html", "challenge": "challenge.html",
        "captcha": "captcha.html", "loading": "loading.html"
    }
    
    for key, filename in page_files.items():
        path = os.path.join(settings.PAGE_ROOT, filename)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                pages[key] = f.read()
        except Exception:
            pages[key] = f"<h1>{key} Error (Template Missing)</h1>"
            
    return pages
