import logging
import sys
import os
from waitress import serve
from src.api.app import create_app
from src.config.settings import settings

# Configure Root Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

if __name__ == "__main__":
    logger = logging.getLogger("WAF.Main")
    logger.info("Starting Biubo WAF Protective Proxy (Refactored)...")
    
    app = create_app()
    
    # Get port from settings
    port = settings.WAF_PORT
    
    logger.info(f"Serving on host 0.0.0.0, port {port}...")
    serve(app, host="0.0.0.0", port=port, threads=8)
