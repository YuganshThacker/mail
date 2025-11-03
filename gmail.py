from flask import Flask, request, redirect, url_for, flash, render_template_string, jsonify, session, Response
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from email.mime.text import MIMEText
import email.utils
import os
import base64
from html import escape
import re
import json
from datetime import datetime, timedelta, timezone 
import dateutil.parser 
from collections import Counter 
import atexit # Kept for local testing, ignored by Render main process

# --- SCHEDULER: DISABLED FOR RENDER WEB SERVICE DEPLOYMENT ---
# For reminders to work on Render, you must deploy this logic to a separate Worker service.
try:
    from apscheduler.schedulers.background import BackgroundScheduler 
except ImportError:
    BackgroundScheduler = None
    
# AI Imports
import google.generativeai as genai

# --- CONFIGURATION (CRUCIAL: USES ENVIRONMENT VARIABLES) ---
# CRUCIAL: Must be set as environment variables on Render 
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") 
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "supersecretkey_fallback") 
# We assume 'credentials.json' is in the root directory for deployment
CLIENT_SECRETS_FILE = os.getenv("CLIENT_SECRETS_FILE_PATH", "credentials.json") 
# Variables for local file saving are ignored (kept for function signature compatibility)
AI_CACHE_FILE = 'ai_cache.json'
KEYWORD_FILE = 'keyword_labels.json'
SENT_REMINDERS_FILE = 'sent_reminders.json'
TOKEN_FILE = "token_gmail_clone.json"


SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/userinfo.email", 
    "openid" 
]

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY # Use ENV variable

# --- AI INITIALIZATION ---
try:
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        ai_model = genai.GenerativeModel('gemini-2.5-flash') 
    else:
        print("Warning: GEMINI_API_KEY is empty. AI features will be disabled.")
        ai_model = None
except Exception as e:
    print(f"FATAL ERROR: AI Model Initialization failed: {e}")
    ai_model = None


# ---------------- Utility Functions (NON-PERSISTENT FOR RENDER) ----------------

# WARNING: All file I/O functions below are modified to be non-persistent.
# Data like cache and keywords will be lost on service restart.

def strip_html(html_content):
    cleanr = re.compile('<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});')
    cleantext = re.sub(cleanr, '', html_content)
    return cleantext

# --- NON-PERSISTENT DUMMY FUNCTIONS ---
# You can replace this with a cloud database (like Render PostgreSQL) for persistence
# but for basic deployment, we disable file I/O.
def load_ai_cache(): return {} 
def save_ai_cache(cache_data): pass 
def load_sent_reminders(): return {} 
def save_sent_reminders(cache_data): pass 
def load_keywords(): return {} 
def save_keywords(data): pass 

# ---------------- AI Agent Function (Logic remains the same) ----------------

def analyze_email_with_ai(subject, body, current_time_for_ai):
    """
    Analyzes email content to generate a category, extract urgency info,
    and suggest smart replies.
    """
    if not ai_model:
        return {"category": None, "is_urgent": False, "due_date": None, "urgency_reason": None, "replies": []}

    body_text = strip_html(body)[:4000] 
    prompt = f"""
    Analyze the following email content and provide a structured JSON response.
    The current date and time is: {current_time_for_ai.isoformat()}
    **Email Subject:** {subject}
    **Email Body Snippet:** {body_text}
    **Instructions:** [1. Category: Choose one of 'Work', 'Promotions', 'Personal', 'Social', or 'Updates'. 2. Urgency: true/false. 3. Due Date: ISO format or null. 4. Reason: string or null. 5. Smart Replies: array of 3 strings or [].]
    Return the output in a single, valid JSON format.
    """
    try:
        response = ai_model.generate_content(prompt)
        match = re.search(r'\{.*\}', response.text, re.DOTALL)
        if match:
            ai_data = json.loads(match.group(0))
            ai_data.setdefault("category", None)
            ai_data.setdefault("is_urgent", False)
            ai_data.setdefault("due_date", None)
            ai_data.setdefault("urgency_reason", None)
            ai_data.setdefault("replies", [])
            return ai_data
        else:
            raise ValueError("No JSON object found in AI response.")
    except Exception as e:
        print(f"AI analysis failed: {e}")
        return {"category": None, "is_urgent": False, "due_date": None, "urgency_reason": None, "replies": []}

def generate_email_body(recipient, subject):
    """Generates a draft email body based on a subject and recipient."""
    if not ai_model:
        return "AI model is not available. Please check your API key."

    prompt = f"""Write a professional and concise email body for an email to: '{recipient}'\nThe subject of the email is: '{subject}'\nInstructions:\n1. Write only the email body.\n2. Do NOT include a "Subject:" line.\n3. Do NOT include a signature line (e.g., "Sincerely," or "Best,")."""
    try:
        response = ai_model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"AI body generation failed: {e}")
        return "Error generating email body."

# ---------------- Gmail API Setup (CRUCIAL RENDER REFACTOR) ----------------

@app.route("/authorize")
def authorize():
    """Initiates the web-based OAuth 2.0 flow for Vercel/Render."""
    try:
        flow = create_flow_from_secrets(SCOPES)
        # 1. Use _external=True to get the full deployment URL for the callback
        flow.redirect_uri = url_for("oauth2callback", _external=True) 
        
        # 2. Requesting offline access to get a refresh token
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
        
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        flash("❌ OAuth setup failed. Ensure credentials are configured properly.")
        return redirect(url_for('index'))

@app.route("/oauth2callback")
def oauth2callback():
    """Handles the callback from Google and stores credentials in the session."""
    state = session.pop('oauth_state', None)
    if not state or state != request.args.get('state'):
        flash("❌ OAuth state mismatch. Please try again.")
        return redirect(url_for('index'))
        
    try:
        flow = create_flow_from_secrets(SCOPES)
        flow.redirect_uri = url_for("oauth2callback", _external=True)
        
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        # 3. Store credentials in the **user's session** (not a file)
        session['credentials'] = creds.to_json()
        flash("✅ Authentication successful!")
        return redirect(url_for('index'))
    except Exception as e:
        flash(f"❌ Authentication failed: {e}")
        return redirect(url_for('index'))

def get_service():
    """Retrieves Gmail service object, checking/refreshing token in session."""
    if 'credentials' not in session:
        flash("Please authenticate with Google to use the application.")
        return redirect(url_for('authorize')) 

    try:
        creds = Credentials.from_authorized_user_info(json.loads(session['credentials']), SCOPES)
    except Exception:
        session.pop('credentials', None)
        return redirect(url_for('authorize'))

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            session['credentials'] = creds.to_json() # Update token in session
        except Exception:
            session.pop('credentials', None)
            flash("Your session expired. Please re-authenticate.")
            return redirect(url_for('authorize'))

    return build("gmail", "v1", credentials=creds)

def get_user_email(service):
    """Fetches the authenticated user's email address."""
    if isinstance(service, Response): return None # FIX APPLIED
    try:
        # Requires the "https://www.googleapis.com/auth/userinfo.email" scope
        user_info = service.users().getProfile(userId='me').execute()
        return user_info.get('emailAddress')
    except Exception as e:
        print(f"Error fetching user email: {e}")
        return None

# ---------------- Label Management Functions (Modified to check for Response) ----------------

def get_user_labels():
    service = get_service()
    if isinstance(service, Response): return service, [] 
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        return service, [l for l in labels if l['type'] == 'user']
    except Exception as e:
        print(f"Error fetching user labels: {e}")
        return service, []

def get_or_create_label_id(service, label_name, all_labels):
    if isinstance(service, Response): return None # FIX APPLIED
    existing_label = next((l for l in all_labels if l['name'].lower() == label_name.lower()), None)
    if existing_label:
        return existing_label['id']
    else:
        label_body = {'name': label_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
        created_label = service.users().labels().create(userId='me', body=label_body).execute()
        all_labels.append(created_label) 
        return created_label['id']

def create_label(name):
    service = get_service()
    if isinstance(service, Response): return service # FIX APPLIED
    label_body = {'name': name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
    try:
        service.users().labels().create(userId='me', body=label_body).execute()
        flash(f"Label '{name}' created successfully.")
    except Exception as e:
        flash(f"Error creating label: {e}")
    return None # Return None if successful, to be handled by route

def delete_label_api(label_id):
    service = get_service()
    if isinstance(service, Response): return service # FIX APPLIED
    try:
        service.users().labels().delete(userId='me', id=label_id).execute()
        flash("Label deleted successfully.")
    except Exception as e:
        flash(f"Error deleting label: {e}")
    return None

# ---------------- Fetch Emails ----------------
def fetch_emails(label="inbox", search_query="", max_results=50):
    service = get_service()
    if isinstance(service, Response): return service, []
    
    # ... rest of the function ...
    
    # --- Load AI cache to check for urgency (will always be empty on service restart) ---
    ai_cache = load_ai_cache()
    
    label_map = {
        "inbox": "INBOX", "sent": "SENT", "drafts": "DRAFT",
        "starred": "STARRED", "trash": "TRASH", "spam": "SPAM", "archive": None
    }
    label_ids_param = [label_map.get(label)] if label in label_map and label_map.get(label) else [label]
    q_param = search_query if search_query else None
    if label == "archive":
        q_param = "-label:INBOX -label:TRASH -label:SENT -label:DRAFT"
        label_ids_param = None
    
    email_list = []
    try:
        res = service.users().messages().list(userId="me", labelIds=label_ids_param, q=q_param, maxResults=max_results).execute()
        messages = res.get("messages", [])
        for m in messages:
            try:
                # ... [Email fetching and parsing logic remains the same] ...
                msg_data = service.users().messages().get(userId="me", id=m["id"], format="metadata", metadataHeaders=["Subject", "From", "Date"]).execute()
                headers = msg_data.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "(No Subject)")
                sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "(Unknown Sender)")
                date_raw = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
                try: 
                    parsed_date = email.utils.parsedate_to_datetime(date_raw)
                    date_str = parsed_date.astimezone().strftime("%b %d") 
                except: 
                    date_str = date_raw
                
                is_urgent = ai_cache.get(m["id"], {}).get("is_urgent", False)
                
                email_list.append({
                    "id": m["id"], "subject": subject, "sender": sender, "date": date_str, 
                    "date_raw": date_raw, "snippet": msg_data.get("snippet", ""), 
                    "labels": msg_data.get("labelIds", []), "is_urgent": is_urgent
                })
            except Exception as e: 
                print(f"Error fetching metadata for message {m['id']}: {e}")
    except Exception as e: 
        print(f"Error listing emails: {e}")
        flash("Error fetching emails.")
    return service, email_list # Return service and list

# ---------------- Decode Email Body ----------------
def get_email_body(payload):
    # ... [Same recursive body decoding logic] ...
    body = {"html_body": "", "text_body": "", "inline_images": {}}
    
    if "parts" in payload:
        for part in payload['parts']:
            part_body = get_email_body(part)
            body["html_body"] += part_body["html_body"]
            body["text_body"] += part_body["text_body"]
            body["inline_images"].update(part_body["inline_images"])
    
    mime_type = payload.get("mimeType", "")
    part_headers = payload.get("headers", [])
    content_id_header = next((h['value'] for h in part_headers if h['name'].lower() == 'content-id'), None)

    if payload.get('body') and payload['body'].get('data'):
        data = payload['body']['data']
        decoded_data = base64.urlsafe_b64decode(data.encode('UTF-8')).decode('utf-8', errors='ignore')
        if 'text/html' in mime_type: body['html_body'] += decoded_data
        elif 'text/plain' in mime_type: body['text_body'] += decoded_data
    
    if content_id_header and payload.get('body', {}).get('attachmentId'):
        cid = content_id_header.strip('<>')
        attachment_id = payload['body']['attachmentId']
        body['inline_images'][cid] = attachment_id
        
    return body

# ---------------- Fetch Single Email (Modified to check for Response) ----------------
def fetch_single_email(email_id):
    service = get_service()
    if isinstance(service, Response): return service # FIX APPLIED
    try:
        msg = service.users().messages().get(userId="me", id=email_id, format="full").execute()
        payload = msg.get('payload', {})
        headers = payload.get("headers", [])

        # ... [Email header parsing logic remains the same] ...
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "(No Subject)")
        sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "(Unknown Sender)")
        date_raw = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
        try: 
            date = email.utils.parsedate_to_datetime(date_raw).astimezone().strftime("%A, %B %d, %Y at %I:%M %p")
        except: 
            date = date_raw

        # Get all parts of the body
        body_parts = get_email_body(payload)
        html_body = body_parts['html_body']

        # ... [Inline image replacement logic remains the same] ...
        for cid, attachment_id in body_parts['inline_images'].items():
            try:
                attachment = service.users().messages().attachments().get(userId='me', messageId=email_id, id=attachment_id).execute()
                data = attachment['data']
                mime_type = next((p.get('mimeType', 'image/jpeg') for p in payload.get('parts', []) if p.get('body', {}).get('attachmentId') == attachment_id), 'image/jpeg')
                img_data_uri = f"data:{mime_type};base64,{data.replace('-', '+').replace('_', '/')}"
                html_body = html_body.replace(f'cid:{cid}', img_data_uri)
            except Exception as e:
                print(f"Failed to embed image for cid {cid}: {e}")

        final_body = html_body if html_body else f"<pre>{escape(body_parts['text_body'])}</pre>"
        
        return {"id": email_id, "subject": subject, "sender": sender, "date": date, "body": final_body, "labels": msg.get("labelIds", []), "text_for_ai": body_parts["text_body"] or strip_html(html_body)}
    except Exception as e:
        print(f"Error fetching single email {email_id}: {e}")
        return None

# ---------------- Email Actions (Modified to check for Response) ----------------

def send_email(to, subject, message_text):
    service = get_service()
    if isinstance(service, Response): return service, "Authentication required." # FIX APPLIED
    try:
        if not (message_text.strip().startswith('<') and message_text.strip().endswith('>')):
             message_text = f"<pre>{escape(message_text)}</pre>"

        msg = MIMEText(message_text, "html")
        msg["to"], msg["subject"] = to, subject
        raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        service.users().messages().send(userId="me", body={"raw": raw_message}).execute()
        return True, None
    except Exception as e: 
        print(f"Error sending email: {e}")
        return False, str(e)

def modify_email_labels(email_id, labels_to_add=None, labels_to_remove=None):
    service = get_service()
    if isinstance(service, Response): return service # FIX APPLIED
    body = {}
    if labels_to_add: body["addLabelIds"] = labels_to_add
    if labels_to_remove: body["removeLabelIds"] = labels_to_remove
    if body: 
        try:
            service.users().messages().modify(userId="me", id=email_id, body=body).execute()
        except Exception as e:
            print(f"Error modifying labels: {e}")
    return None

def toggle_star(email_id):
    service = get_service()
    if isinstance(service, Response): return service # FIX APPLIED
    msg = service.users().messages().get(userId="me", id=email_id, format="metadata", metadataHeaders=["labelIds"]).execute()
    labels = msg.get("labelIds", [])
    if "STARRED" in labels: 
        return modify_email_labels(email_id, labels_to_remove=["STARRED"])
    else: 
        return modify_email_labels(email_id, labels_to_add=["STARRED"])

def delete_email(email_id):
    service = get_service()
    if isinstance(service, Response): return service # FIX APPLIED
    service.users().messages().trash(userId="me", id=email_id).execute()
    return None

def unspam_email(email_id): return modify_email_labels(email_id, labels_to_add=['INBOX'], labels_to_remove=['SPAM'])
def spam_email(email_id): return modify_email_labels(email_id, labels_to_add=['SPAM'], labels_to_remove=['INBOX', 'STARRED'])
def archive_email(email_id): return modify_email_labels(email_id, labels_to_remove=['INBOX'])

# ---------------- HTML Template (Remains the same) ----------------
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Gmail Clone</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        /* [CSS STYLES HERE - REMOVED FOR BREVITY] */
        /* --- NEW DARK THEME --- */
        body { 
            background-color: #1a202c; 
            color: #e2e8f0; 
            font-family: 'Roboto', Arial, sans-serif; 
        }
        .sidebar { 
            position: fixed; top: 0; left: 0; height: 100vh; 
            background: #2d3748; 
            padding-top: 20px; 
            border-right: 1px solid #4a5568; 
        }
        .sidebar-link { 
            display: flex; align-items: center; padding: 8px 25px; 
            color: #cbd5e0; 
            text-decoration: none; border-radius: 0 25px 25px 0; 
            font-weight: 500; margin-right: 15px; 
        }
        .sidebar-link:hover, .sidebar-link-wrapper:hover .sidebar-link { 
            background-color: #4a5568; 
            color: #ffffff;
        }
        .sidebar-link.active { 
            background-color: #2b6cb0; 
            color: #ffffff; 
            font-weight: bold; 
        }
        .sidebar-link .material-icons { margin-right: 18px; font-size: 20px; }
        .main-content { margin-left: 250px; padding: 20px; }
        
        .email-item { 
            padding: 10px; 
            border-bottom: 1px solid #4a5568; 
            transition: background-color 0.2s; 
        }
        .email-item:hover { 
            background-color: #2d3748; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.2); 
            cursor: pointer; 
        }
        /* ... rest of styles ... */
    </style>
    <script>
        function confirmDelete(emailId) { if (confirm('Are you sure you want to move this email to Trash?')) { window.location.href = '/delete/' + emailId; } } 
        function viewEmail(emailId) { window.location.href = '/email/' + emailId; }
    </script>
</head>
<body>
<div class="flash-message">{% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-info alert-dismissible fade show" role="alert">{{ message }}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>{% endfor %}{% endif %}{% endwith %}</div>
<div class="container-fluid"><div class="row">
<div class="col-2 sidebar">
    <div class="text-center mb-4"><a href="{{ url_for('compose') }}" class="btn btn-danger shadow-sm" style="padding: 10px 24px; border-radius: 24px;">✉️ Compose</a></div>
    <a href="{{ url_for('index', label='inbox') }}" class="sidebar-link {% if label=='inbox' %}active{% endif %}"><span class="material-icons">inbox</span>Inbox</a>
    <a href="{{ url_for('index', label='starred') }}" class="sidebar-link {% if label=='starred' %}active{% endif %}"><span class="material-icons">star_border</span>Starred</a>
    <a href="{{ url_for('index', label='sent') }}" class="sidebar-link {% if label=='sent' %}active{% endif %}"><span class="material-icons">send</span>Sent</a>
    <a href="{{ url_for('index', label='drafts') }}" class="sidebar-link {% if label=='drafts' %}active{% endif %}"><span class="material-icons">drafts</span>Drafts</a>
    <a href="{{ url_for('index', label='archive') }}" class="sidebar-link {% if label=='archive' %}active{% endif %}"><span class="material-icons">archive</span>Archive</a>
    <a href="{{ url_for('index', label='trash') }}" class="sidebar-link {% if label=='trash' %}active{% endif %}"><span class="material-icons">delete</span>Trash</a>
    <a href="{{ url_for('index', label='spam') }}" class="sidebar-link {% if label=='spam' %}active{% endif %}"><span class="material-icons">report</span>Spam</a>
    <hr class="my-2">
    <h6 class="ps-4 mb-2 text-muted small">Labels</h6>
    {% for l in user_labels %}<div class="d-flex justify-content-between align-items-center sidebar-link-wrapper">
        <a href="{{ url_for('index', label=l.id) }}" class="sidebar-link flex-grow-1 {% if label==l.id %}active{% endif %}"><span class="material-icons">label_outline</span>{{ l.name }}</a>
        <a href="{{ url_for('delete_label', label_id=l.id) }}" class="btn btn-sm text-danger label-delete-btn me-2" onclick="return confirm('Delete label \'{{ l.name }}\'?');" title="Delete Label">&times;</a>
    </div>{% endfor %}
    <form action="{{ url_for('create_label_route') }}" method="POST" class="p-3">
        <div class="input-group input-group-sm">
            <input type="text" name="label_name" class="form-control" placeholder="Create new label" required>
            <button class="btn btn-outline-secondary" type="submit">+</button>
        </div>
    </form>
    <hr class="my-2">
    <h6 class="ps-4 mb-2 text-muted small">AI Tools</h6>
    <a href="{{ url_for('set_keywords') }}" class="sidebar-link {% if label=='set_keywords' %}active{% endif %}"><span class="material-icons">vpn_key</span>Set Keywords</a>
    <a href="{{ url_for('dashboard') }}" class="sidebar-link {% if label=='dashboard' %}active{% endif %}"><span class="material-icons">bar_chart</span>Insights</a>
</div>
<div class="col-10 main-content">{{ content|safe }}</div>
</div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# --- CREDENTIAL HELPER FUNCTIONS ---
def get_client_secrets():
    """Get client secrets from environment variable or file for deployment flexibility."""
    # First try to get from environment variable (for Vercel/production)
    encoded_creds = os.getenv("GOOGLE_OAUTH_CREDENTIALS")
    if encoded_creds:
        try:
            # Decode base64 encoded credentials
            decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
            return json.loads(decoded_creds)
        except Exception as e:
            print(f"Warning: Failed to decode GOOGLE_OAUTH_CREDENTIALS: {e}")
    
    # Fallback to file-based credentials (for local development)
    try:
        with open(CLIENT_SECRETS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: {CLIENT_SECRETS_FILE} not found")
        return None
    except Exception as e:
        print(f"Warning: Failed to load {CLIENT_SECRETS_FILE}: {e}")
        return None

def create_flow_from_secrets(scopes):
    """Create OAuth flow from secrets (environment or file)."""
    client_secrets = get_client_secrets()
    if not client_secrets:
        raise Exception("No valid client secrets found")
    
    # Create flow from client config dictionary
    flow = InstalledAppFlow.from_client_config(client_secrets, scopes)
    return flow

# ---------------- Routes (All routes updated to check for 'Response') ----------------

@app.route("/")
def index():
    # Check authentication first
    if 'credentials' not in session:
        # Show welcome page instead of redirect loop
        welcome_html = f"""
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-8 text-center">
                    <h1 class="mb-4">📧 Gmail Clone</h1>
                    <p class="lead mb-4">A powerful Gmail client with AI-powered features</p>
                    <div class="card bg-dark text-white p-4 mb-4">
                        <h5>Features:</h5>
                        <ul class="list-unstyled">
                            <li>📧 Full Gmail API integration</li>
                            <li>🤖 AI-powered email analysis</li>
                            <li>🏷️ Smart email categorization</li>
                            <li>📱 Modern responsive interface</li>
                        </ul>
                    </div>
                    <a href="{url_for('authorize')}" class="btn btn-primary btn-lg">
                        🔐 Connect with Gmail
                    </a>
                    <p class="mt-3 text-muted small">
                        Click above to securely connect your Gmail account
                    </p>
                </div>
            </div>
        </div>
        """
        return render_template_string(BASE_TEMPLATE, label="welcome", content=welcome_html, user_labels=[])
    
    label = request.args.get("label", "inbox")
    service, emails = fetch_emails(label=label, search_query=request.args.get("search", ""))
    if isinstance(service, Response): return service # FIX APPLIED
    
    service_label, user_labels = get_user_labels()
    if isinstance(service_label, Response): return service_label # FIX APPLIED

    # ... [Rest of index logic remains the same] ...
    current_label_name = label.capitalize()
    system_labels = ["inbox", "sent", "drafts", "starred", "trash", "archive", "spam"]
    if label not in system_labels:
        found_label = next((l['name'] for l in user_labels if l['id'] == label), None)
        if found_label:
            current_label_name = found_label

    inbox_html = f"<h3>{current_label_name}</h3><hr>"
    if emails:
        for e in emails:
            star_icon, star_color = ("star", "#fbbc04") if "STARRED" in e["labels"] else ("star_border", "#a0aec0")
            sender_name = escape(e['sender'].split('<')[0].strip().replace('"', ''))
            urgent_class = "email-item-urgent" if e.get("is_urgent") else ""

            inbox_html += f"""
            <div class="email-item row align-items-center {urgent_class}" onclick="viewEmail('{e['id']}')">
                <div class="col-auto"><a href='{url_for('star_email', email_id=e['id'])}' class='btn btn-light btn-sm' onclick="event.stopPropagation();"><span class='material-icons' style='color:{star_color};'>{star_icon}</span></a></div>
                <div class="col-3"><b>{sender_name}</b></div>
                <div class="col"><b>{escape(e['subject'])}</b> - <span class='text-muted'>{escape(e['snippet'])}</span></div>
                <div class="col-2 text-end text-muted small">{e['date']}</div>
            </div>"""
    else:
        inbox_html += "<p class='text-muted text-center mt-5'>No emails found in this view.</p>"

    return render_template_string(BASE_TEMPLATE, label=label, content=inbox_html, user_labels=user_labels, user_email=get_user_email(service))

@app.route("/email/<email_id>")
def view_email(email_id):
    service_check = get_service()
    if isinstance(service_check, Response): return service_check # FIX APPLIED
    
    service_label, all_user_labels = get_user_labels()
    if isinstance(service_label, Response): return service_label # FIX APPLIED

    email_data = fetch_single_email(email_id)
    if email_data is None: 
        flash("❌ Error fetching email details.")
        return redirect(url_for('index'))
    if isinstance(email_data, Response): return email_data # FIX APPLIED

    # ... [AI Analysis and HTML generation logic remains the same] ...
    # 1. AI Analysis Data (from non-persistent cache)
    ai_cache = load_ai_cache()
    analysis = ai_cache.get(email_id, {})
    
    ai_highlight_html = ""
    smart_reply_html = ""
    
    # Check for urgency/deadline info
    due_date_str = analysis.get("due_date")
    reason = analysis.get("urgency_reason")
    
    if due_date_str:
        alert_class, alert_title, due_date_display = "alert-warning", "💡 AI Highlight: Task/Deadline Found", None
        try:
            due_date_obj = dateutil.parser.parse(due_date_str)
            now = datetime.now(timezone.utc)
            time_difference = due_date_obj.astimezone(timezone.utc) - now
            hours_remaining = time_difference.total_seconds() / 3600
            
            if 0 < hours_remaining <= 12:
                alert_class, alert_title = "alert-danger", f"🚨 DEADLINE IMMINENT (Due in approx. {int(hours_remaining)} hours)"
            elif hours_remaining <= 0:
                alert_class, alert_title = "alert-dark", "🚩 This task is OVERDUE."
                
            due_date_display = due_date_obj.astimezone().strftime("%A, %B %d, %Y at %I:%M %p %Z")
            
        except Exception as e:
            print(f"Dateutil parsing failed for '{due_date_str}': {e}")
            
        ai_highlight_html = f'<div class="alert {alert_class}" role="alert"><h5 class="alert-heading">{escape(alert_title)}</h5>'
        if reason:
            ai_highlight_html += f"<p><strong>Summary:</strong> {escape(reason)}</p>"
        if due_date_display:
            ai_highlight_html += f"<p class='mb-0'><strong>Due Date / Timeline:</strong> {escape(due_date_display)}</p>"
        ai_highlight_html += '</div>'

    # 2. Smart Reply Logic
    replies = analysis.get("replies", [])
    if replies:
        smart_reply_html = '<div class="mt-3"><h5>🤖 Smart Replies:</h5>'
        for reply_text in replies:
            reply_url = url_for('reply_email', email_id=email_id, suggestion=reply_text)
            smart_reply_html += f'<a href="{reply_url}" class="btn btn-outline-secondary btn-sm me-2 mb-2">{escape(reply_text)}</a>'
        smart_reply_html += '</div>'


    # Label management section
    # ... [HTML generation for labels, actions, etc. remains the same] ...
    label_management_html = "<h5>Manage Labels</h5>"
    current_labels = [l for l in all_user_labels if l['id'] in email_data['labels']]
    label_management_html += "<p>"
    for l in current_labels:
        label_management_html += f"<span class='badge bg-secondary me-2'>{escape(l['name'])}</span>"
    label_management_html += "</p>"
    
    label_management_html += f"""
        <div class="dropdown">
            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                Apply Label
            </button>
            <ul class="dropdown-menu">
                {''.join([f"<li><a class='dropdown-item' href='{url_for('add_label_to_email', email_id=email_id, label_id=l.id)}'>{escape(l.name)}</a></li>" 
                    for l in all_user_labels if l.id not in email_data['labels']])}
            </ul>
        </div>
    """

    email_html = f"""
        <div class="card bg-light-dark text-white shadow">
            <div class="card-header border-bottom-0">
                <h4 class="mb-0">{escape(email_data['subject'])}</h4>
                <p class="mb-1 text-muted small">From: {escape(email_data['sender'])}</p>
                <p class="mb-0 text-muted small">Date: {email_data['date']}</p>
            </div>
            <div class="card-body">
                {ai_highlight_html}
                <div class="email-body bg-body-tertiary p-3 rounded">{email_data['body']}</div>
                {smart_reply_html}
            </div>
            <div class="card-footer d-flex justify-content-between align-items-center">
                <div>
                    <a href="{url_for('reply_email', email_id=email_id)}" class="btn btn-primary me-2">Reply</a>
                    <a href="{url_for('compose')}" class="btn btn-secondary me-2">Forward</a>
                    <a href="{url_for('star_email', email_id=email_id)}" class="btn btn-outline-warning me-2" title="Star/Unstar"><span class="material-icons">star</span></a>
                    <a href="{url_for('archive_route', email_id=email_id)}" class="btn btn-outline-secondary me-2" title="Archive"><span class="material-icons">archive</span></a>
                    <a href="{url_for('delete_route', email_id=email_id)}" class="btn btn-outline-danger" title="Delete" onclick="return confirm('Move to Trash?');"><span class="material-icons">delete</span></a>
                </div>
                {label_management_html}
            </div>
        </div>
    """
    return render_template_string(BASE_TEMPLATE, label="view", content=email_html, user_labels=all_user_labels)

def get_compose_html(to_email="", subject="", message="", original_body=""):
    """Generate HTML for the compose email form."""
    return f"""
    <h3>✉️ Compose Email</h3>
    <hr>
    <form method="POST" action="{url_for('compose')}" class="needs-validation" novalidate>
        <div class="row g-3">
            <div class="col-12">
                <label for="to_email" class="form-label">To:</label>
                <input type="email" class="form-control" id="to_email" name="to_email" 
                       value="{escape(to_email)}" placeholder="recipient@example.com" required>
                <div class="invalid-feedback">Please provide a valid email address.</div>
            </div>
            <div class="col-12">
                <label for="subject" class="form-label">Subject:</label>
                <div class="input-group">
                    <input type="text" class="form-control" id="subject" name="subject" 
                           value="{escape(subject)}" placeholder="Enter subject..." required>
                    <button type="button" class="btn btn-outline-secondary" onclick="generateAIBody()" 
                            title="Generate email body with AI">🤖 AI</button>
                </div>
                <div class="invalid-feedback">Please provide a subject.</div>
            </div>
            <div class="col-12">
                <label for="message" class="form-label">Message:</label>
                <textarea class="form-control" id="message" name="message" rows="12" 
                          placeholder="Type your message here..." required>{escape(message)}</textarea>
                <div class="invalid-feedback">Please provide a message.</div>
            </div>
            {f'<div class="col-12"><label class="form-label">Original Message:</label><div class="bg-light p-3 rounded"><pre>{escape(original_body)}</pre></div></div>' if original_body else ''}
            <div class="col-12">
                <button type="submit" class="btn btn-primary me-2">📤 Send Email</button>
                <a href="{url_for('index')}" class="btn btn-secondary">Cancel</a>
            </div>
        </div>
    </form>
    
    <script>
    // Form validation
    (function() {{
        'use strict';
        window.addEventListener('load', function() {{
            var forms = document.getElementsByClassName('needs-validation');
            var validation = Array.prototype.filter.call(forms, function(form) {{
                form.addEventListener('submit', function(event) {{
                    if (form.checkValidity() === false) {{
                        event.preventDefault();
                        event.stopPropagation();
                    }}
                    form.classList.add('was-validated');
                }}, false);
            }});
        }}, false);
    }})();
    
    // AI Body Generation
    function generateAIBody() {{
        const toEmail = document.getElementById('to_email').value;
        const subject = document.getElementById('subject').value;
        
        if (!subject) {{
            alert('Please enter a subject first to generate AI content.');
            return;
        }}
        
        const button = event.target;
        button.disabled = true;
        button.textContent = '🤖 Generating...';
        
        fetch('/ai-generate-body', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{to: toEmail, subject: subject}})
        }})
        .then(response => response.json())
        .then(data => {{
            if (data.body) {{
                document.getElementById('message').value = data.body;
            }} else {{
                alert('Error generating body: ' + (data.error || 'Unknown error'));
            }}
        }})
        .catch(error => {{
            alert('Error: ' + error.message);
        }})
        .finally(() => {{
            button.disabled = false;
            button.textContent = '🤖 AI';
        }});
    }}
    </script>
    """

# ---------------- Original Email Action Routes (Modified to check for Response) ----------------

@app.route("/compose", methods=["GET", "POST"])
def compose():
    service, user_labels = get_user_labels()
    if isinstance(service, Response): return service # FIX APPLIED
    
    if request.method == "POST":
        to_email = request.form.get("to_email")
        subject = request.form.get("subject")
        message = request.form.get("message")
        
        success, error = send_email(to_email, subject, message)
        
        if success:
            flash(f"✅ Email sent successfully to {to_email}!")
            return redirect(url_for('index', label='sent'))
        else:
            flash(f"❌ Error sending email: {error}")
            # Keep user on the compose page with their data
            return render_template_string(BASE_TEMPLATE, label="compose", content=get_compose_html(to_email, subject, message), user_labels=user_labels)

    return render_template_string(BASE_TEMPLATE, label="compose", content=get_compose_html(), user_labels=user_labels)

@app.route("/reply/<email_id>")
@app.route("/reply/<email_id>/<suggestion>")
def reply_email(email_id, suggestion=None):
    service, user_labels = get_user_labels()
    if isinstance(service, Response): return service # FIX APPLIED

    email_data = fetch_single_email(email_id)
    if isinstance(email_data, Response): return email_data # FIX APPLIED
    if email_data is None: 
        flash("❌ Error fetching email details for reply.")
        return redirect(url_for('index'))

    # Extract sender's email for reply-to
    sender_match = re.search(r'[\w\.-]+@[\w\.-]+', email_data['sender'])
    reply_to = sender_match.group(0) if sender_match else ""
    
    original_subject = email_data['subject']
    reply_subject = f"Re: {original_subject}" if not original_subject.startswith("Re:") else original_subject
    
    # Format original message for reply
    original_body_html = email_data['body']
    original_body = f"\n\n\n--- Original Message from {email_data['sender']} ({email_data['date']}) ---\n" + strip_html(original_body_html)
    
    # Pre-fill message body with AI suggestion if provided
    initial_message = suggestion if suggestion else ""
    
    return render_template_string(BASE_TEMPLATE, label="compose", content=get_compose_html(reply_to, reply_subject, initial_message, original_body), user_labels=user_labels)


# ---------------- Dashboard Route ----------------

@app.route("/dashboard")
def dashboard():
    service_check = get_service()
    if isinstance(service_check, Response): return service_check # FIX APPLIED

    # Get labels for the sidebar
    service, user_labels = get_user_labels()
    if isinstance(service, Response): return service # FIX APPLIED

    ai_cache = load_ai_cache()

    # 1. Fetch data
    service, emails = fetch_emails(label="inbox", max_results=100)
    if isinstance(service, Response): return service # FIX APPLIED

    # 2. Process data (logic remains the same)
    email_days_counter = Counter()
    sender_counter = Counter()
    category_counter = Counter()
    today = datetime.now(timezone.utc)
    day_labels = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    day_labels_simple = [(today - timedelta(days=i)).strftime('%b %d') for i in range(6, -1, -1)]

    for e in emails:
        # Sender Stats
        sender_raw = e.get("sender", "")
        match = re.search(r'[\w\.-]+@[\w\.-]+', sender_raw)
        if match:
            sender_counter[match.group(0).lower()] += 1

        # Trend Stats
        date_raw = e.get("date_raw")
        if date_raw:
            try:
                parsed_date = email.utils.parsedate_to_datetime(date_raw)
                day_str = parsed_date.strftime('%Y-%m-%d')
                if day_str in day_labels:
                    email_days_counter[day_str] += 1
            except:
                pass

        # Category Stats
        analysis = ai_cache.get(e['id'])
        category = analysis.get("category") if analysis else None
        category_counter[category if category else "Not Analyzed"] += 1
        
    # 3. Prepare Chart Data
    trends_data = [email_days_counter.get(d, 0) for d in day_labels]
    trends_labels = day_labels_simple
    
    categories_sorted = category_counter.most_common()
    categories_labels = [c[0] for c in categories_sorted]
    categories_data = [c[1] for c in categories_sorted]
    
    senders_sorted = sender_counter.most_common(5)
    senders_labels = [s[0] for s in senders_sorted]
    senders_data = [s[1] for s in senders_sorted]

    # 4. Generate HTML and Chart.js script
    dashboard_html = f"""
        <h3>📊 Inbox Insights Dashboard</h3>
        <hr>
        <div class="row g-4">
            <div class="col-lg-8">
                <div class="chart-container">
                    <h5>Email Volume Trend (Last 7 Days)</h5>
                    <canvas id="trendsChart" height="200"></canvas>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="chart-container">
                    <h5>Email Category Breakdown</h5>
                    <canvas id="categoryChart" height="200"></canvas>
                </div>
            </div>
            <div class="col-lg-12">
                <div class="chart-container">
                    <h5>Top 5 Senders</h5>
                    <canvas id="sendersChart" height="150"></canvas>
                </div>
            </div>
        </div>
        <script>
        // Trend Chart
        new Chart(document.getElementById('trendsChart'), {{
            type: 'line', data: {{ labels: {json.dumps(trends_labels)}, datasets: [{{ label: 'Emails Received', data: {json.dumps(trends_data)}, borderColor: '#2b6cb0', tension: 0.1 }}] }}, 
            options: {{ responsive: true, maintainAspectRatio: false, scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }} }}
        }});

        // Category Chart
        new Chart(document.getElementById('categoryChart'), {{
            type: 'pie', data: {{ labels: {json.dumps(categories_labels)}, datasets: [{{ data: {json.dumps(categories_data)}, backgroundColor: ['#2b6cb0', '#dd6b20', '#48bb78', '#6b46c1', '#e53e3e', '#ecc94b'] }}] }}, 
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});

        // Senders Chart (Bar)
        new Chart(document.getElementById('sendersChart'), {{
            type: 'bar', data: {{ labels: {json.dumps(senders_labels)}, datasets: [{{ label: 'Emails Received', data: {json.dumps(senders_data)}, backgroundColor: '#2b6cb0' }}] }}, 
            options: {{ responsive: true, maintainAspectRatio: false, scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }} }}
        }});
        </script>
    """

    return render_template_string(BASE_TEMPLATE, label="dashboard", content=dashboard_html, user_labels=user_labels)

# ---------------- Background Scheduler Logic (DISABLED IN MAIN PROCESS) ----------------

# The full function is included here for completeness, but it is **NEVER CALLED** # in the main web service process to prevent instability.
def check_deadlines_and_send_reminders():
    """ This function is intended for a separate Render Worker service. """
    print("WARNING: Reminder check is running. This should be run on a dedicated Worker service on Render.")
    
    # We must ensure the API key is available in the worker process's environment
    if not GEMINI_API_KEY:
        print("Scheduler Error: GEMINI_API_KEY is missing. Aborting job.")
        return
    
    # Only run if not already running (protects against race conditions)
    if app.config.get('IS_BACKGROUND_JOB', False):
        print("Scheduler: Job already running. Skipping.")
        return
        
    app.config['IS_BACKGROUND_JOB'] = True
    
    print("Scheduler: Starting deadline check...")

    # NOTE: This token file logic will fail on Render's ephemeral storage
    # and requires a persistent token/session-based authentication flow.
    # The following block is simplified to only run if the token file *exists* (for local testing).

    try:
        # 1. Re-authenticate / Get Service
        # In a real worker, the token must be pulled from a database, not a file/session.
        # For this simplified worker demonstration, we rely on the logic in get_service to handle auth.
        service = get_service() # Tries to get service from session (will fail in a real worker process)
        user_email = get_user_email(service)

        if not user_email:
            raise Exception("Could not authenticate or get user email.")

        # 2. Get emails flagged as "Urgent"
        service, emails = fetch_emails(label="Urgent", max_results=100)
        
        # 3. Load cache and reminders
        ai_cache = load_ai_cache()
        sent_reminders = load_sent_reminders()
        now = datetime.now(timezone.utc)
        reminders_to_send = []

        # 4. Check deadlines
        for email in emails:
            email_id = email['id']
            analysis = ai_cache.get(email_id)
            
            if not analysis:
                continue

            due_date_str = analysis.get("due_date")

            if due_date_str:
                try:
                    due_date_obj = dateutil.parser.parse(due_date_str).astimezone(timezone.utc)
                    
                    # Check if reminder already sent for this deadline
                    last_sent_iso = sent_reminders.get(email_id)
                    if last_sent_iso:
                        last_sent_time = dateutil.parser.parse(last_sent_iso).astimezone(timezone.utc)
                        # Don't send if a reminder was sent recently for this deadline
                        if last_sent_time > now - timedelta(hours=12): 
                            continue

                    # Check if deadline is within 24 hours
                    time_to_deadline = due_date_obj - now
                    if timedelta(hours=0) < time_to_deadline <= timedelta(hours=24):
                        
                        reminders_to_send.append({
                            "email_id": email_id,
                            "subject": f"⚠️ URGENT REMINDER: Deadline Imminent!",
                            "body": (
                                f"Hello,\n\nThis is an automated reminder that a task/deadline related to the email below is due soon.\n\n"
                                f"<b>Original Subject:</b> {analysis.get('original_subject', 'N/A')}\n"
                                f"<b>Due Date:</b> {due_date_obj.astimezone().strftime('%A, %B %d at %I:%M %p %Z')}"
                            ),
                            "due_time_iso": now.isoformat()
                        })
                        
                except Exception as e:
                    print(f"Scheduler: Could not parse date '{due_date_str}' for email {email_id}: {e}")

        # 5. Send all pending reminders
        if reminders_to_send:
            print(f"Scheduler: Found {len(reminders_to_send)} reminders to send.")
            for reminder in reminders_to_send:
                success, error = send_email(user_email, reminder["subject"], reminder["body"])
                if success:
                    print(f"Scheduler: Sent reminder for {reminder['email_id']}")
                    sent_reminders[reminder['email_id']] = reminder['due_time_iso']
                else:
                    print(f"Scheduler: FAILED to send reminder for {reminder['email_id']}: {error}")
            
            save_sent_reminders(sent_reminders)
        else:
            print("Scheduler: No imminent deadlines found.")
            
    except Exception as e:
        print(f"Scheduler Error: Job failed. Token might be expired. {e}")
    
    app.config['IS_BACKGROUND_JOB'] = False
    
# ---------------- APP STARTUP FOR RENDER ----------------

if __name__ == "__main__":
    # Render automatically provides the PORT environment variable
    port = int(os.environ.get("PORT", 8080))
    
    # --- SCHEDULER: Only runs locally, not on Render main service ---
    # if BackgroundScheduler:
    #     scheduler = BackgroundScheduler()
    #     scheduler.add_job(func=check_deadlines_and_send_reminders, trigger="interval", minutes=30)
    #     scheduler.start()
    #     atexit.register(lambda: scheduler.shutdown())
        
    app.run(host="0.0.0.0", port=port, debug=True)