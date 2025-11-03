# Vercel Deployment Guide

## Overview
This Gmail app is now configured to deploy on Vercel with proper credential management.

## Prerequisites
1. Vercel CLI installed: `npm i -g vercel`
2. Vercel account set up
3. Google Cloud Project with Gmail API enabled

## Configuration Files Updated
- ✅ `api/index.py` - Updated to use the main Gmail app
- ✅ `vercel.json` - Configured for Python Flask deployment
- ✅ `gmail.py` - Added environment variable support for credentials
- ✅ `.env` and `.env.example` - Environment variables documented
- ✅ `.gitignore` - Protects sensitive files

## Environment Variables for Vercel

Set these in your Vercel dashboard under Project Settings > Environment Variables:

### Required Variables:
```bash
GEMINI_API_KEY=AIzaSyBc4XCu2aOs6eKJqu1AXJ2Vwa5qK1bamB8
FLASK_SECRET_KEY=3f53a49fcc79d010a6d68229769067a8df67101cfc9463bc9c1b91fd6b2faa33
GOOGLE_OAUTH_CREDENTIALS=eyJpbnN0YWxsZWQiOnsiY2xpZW50X2lkIjoiMzAyNDI2MTc1MzE1LWhkaXE3dG85YmczMDh0MWt0OHZudWZsMzFoMW45OWk4LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwicHJvamVjdF9pZCI6ImZldGNoaW5nLTQ3NjYxNSIsImF1dGhfdXJpIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vb2F1dGgyL2F1dGgiLCJ0b2tlbl91cmkiOiJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL29hdXRoMi92MS9jZXJ0cyIsImNsaWVudF9zZWNyZXQiOiJHT0NTUFgtTnk1VHJTN1hsNXdpMUtHSnBuaG1ta1hSVUloVSIsInJlZGlyZWN0X3VyaXMiOlsiaHR0cDovL2xvY2FsaG9zdCJdfX0=
```

## Deployment Steps

### 1. Create GitHub Repository ✅ COMPLETED
The repository is ready with all necessary files and proper security setup.

### 2. Connect to GitHub
After creating your GitHub repository, run these commands:
```bash
# Replace YOURUSERNAME with your actual GitHub username
git remote add origin https://github.com/YOURUSERNAME/gmail-clone-app.git
git branch -M main
git push -u origin main
```

### 3. Deploy to Vercel
```bash
# Login to Vercel (visit vercel.com/device and enter code TNNG-CWLJ)
vercel login

# Deploy from GitHub (recommended) or directly
vercel --prod
```

**OR** Deploy via Vercel Dashboard:
1. Go to [vercel.com/new](https://vercel.com/new)
2. Import your GitHub repository
3. Configure environment variables
4. Deploy

### 3. Update Google Cloud Console
After deployment, update your Google Cloud Console:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to APIs & Services > Credentials
3. Edit your OAuth 2.0 client
4. Add your Vercel domain to "Authorized redirect URIs":
   - `https://your-app-name.vercel.app/oauth2callback`

### 4. Test the Deployment
1. Visit your Vercel URL
2. Click "Authorize" to test OAuth flow
3. Verify Gmail functionality

## Local Development
For local development:
```bash
# Copy environment variables
cp .env.example .env

# Install dependencies
pip install -r requirements.txt

# Run locally
python gmail.py
```

## Security Notes
- ✅ Credentials are loaded from environment variables in production
- ✅ Sensitive files are in `.gitignore`
- ✅ Session-based authentication (no local file storage)
- ❌ **Warning**: Your credentials are currently in this guide - remove them after deployment

## Troubleshooting

### OAuth Redirect URI Mismatch
- Make sure your Vercel domain is added to Google Cloud Console
- Use the exact URL: `https://your-domain.vercel.app/oauth2callback`

### Environment Variables Not Loading
- Check Vercel dashboard > Project Settings > Environment Variables
- Redeploy after adding environment variables

### Import Errors
- Make sure all dependencies are in `requirements.txt`
- Vercel automatically installs Python packages

## File Storage Limitation
Note: Vercel functions are stateless. The app currently tries to save files like:
- `ai_cache.json`
- `keyword_labels.json` 
- `sent_reminders.json`

For production use, consider replacing file storage with:
- Vercel KV (Redis)
- External database (MongoDB, PostgreSQL)
- Cloud storage (Google Cloud Storage, AWS S3)
