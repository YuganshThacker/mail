# api/index.py - Gmail App Entry Point for Vercel
import os
import sys
from flask import Flask

# Create a simple test app first to debug
app = Flask(__name__)

@app.route("/")
def home():
    return {
        "message": "Gmail app test deployment", 
        "status": "running",
        "env_vars": {
            "GEMINI_API_KEY": "Set" if os.getenv("GEMINI_API_KEY") else "Not set",
            "FLASK_SECRET_KEY": "Set" if os.getenv("FLASK_SECRET_KEY") else "Not set", 
            "GOOGLE_OAUTH_CREDENTIALS": "Set" if os.getenv("GOOGLE_OAUTH_CREDENTIALS") else "Not set"
        }
    }

@app.route("/test-import")
def test_import():
    try:
        # Add parent directory to Python path
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Try importing gmail module
        import gmail
        return {"status": "success", "message": "Gmail module imported successfully"}
    except Exception as e:
        return {"status": "error", "message": str(e), "type": type(e).__name__}

# For later: uncomment when basic test works
# try:
#     sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
#     from gmail import app as gmail_app
#     app = gmail_app
# except Exception as e:
#     print(f"Failed to import gmail app: {e}")
#     pass
