# api/index.py - Gmail App Entry Point for Vercel
import os
import sys
from flask import Flask

# Add parent directory to Python path for importing gmail.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import the full Gmail app
try:
    from gmail import app
    print("✅ Successfully imported Gmail app")
except ImportError as e:
    print(f"❌ Failed to import Gmail app: {e}")
    # Fallback: Create a simple error reporting app
    app = Flask(__name__)
    
    @app.route("/")
    def fallback_home():
        return {
            "error": "Failed to load Gmail app",
            "details": str(e),
            "env_check": {
                "GEMINI_API_KEY": "Set" if os.getenv("GEMINI_API_KEY") else "Missing",
                "FLASK_SECRET_KEY": "Set" if os.getenv("FLASK_SECRET_KEY") else "Missing",
                "GOOGLE_OAUTH_CREDENTIALS": "Set" if os.getenv("GOOGLE_OAUTH_CREDENTIALS") else "Missing"
            }
        }
    
    @app.route("/health")
    def health():
        return {"status": "error", "message": "Gmail app failed to load"}

# Add a health check endpoint to the main app if it loaded successfully
if 'gmail' in sys.modules:
    @app.route("/health")
    def health():
        return {"status": "success", "message": "Gmail app loaded successfully"}
