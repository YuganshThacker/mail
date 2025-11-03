# api/index.py - Main Gmail App for Vercel Deployment
import os
import sys

# Add the parent directory to the path so we can import from gmail.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gmail import app

# Vercel function entrypoint
def handler(request):
    # The app from gmail.py is already configured
    return app(request.environ, lambda status, headers: None)
