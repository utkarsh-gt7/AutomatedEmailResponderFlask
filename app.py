# Import required libraries
from flask import Flask, jsonify, request, redirect, session, url_for, render_template_string
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import openai  # Import OpenAI for email classification
from dotenv import load_dotenv
import os
import base64
from email.mime.text import MIMEText
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for Flask sessions
load_dotenv()
CLIENT_SECRETS_FILE = "client_secret_google.json"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
    "https://www.googleapis.com/auth/gmail.send"
]

openai.api_key = os.getenv("OPENAI_API_KEY")
redirectURL = 'https://automatedemailresponderflask.onrender.com/oauth2callback'

@app.route('/')
def home():
    return render_template_string('''
        <html>
        <body>
            <h1>Welcome to the Automated Email Responder</h1>
            <button onclick="window.location.href='/google_login'">Login with Google</button>
        </body>
        </html>
    ''')

@app.route('/google_login')
def google_login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
    flow.redirect_uri = redirectURL
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES, state=state)
    flow.redirect_uri = redirectURL
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials

    credentials_info = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    session['credentials'] = credentials_info
    process_result = process_emails(credentials_info)
    
    message = process_result.get('message', 'No message returned.')
    error = process_result.get('error', '')

    return redirect(url_for('result', message=message, error=error))

def process_emails(credentials_info):
    credentials = Credentials(
        token=credentials_info['token'],
        refresh_token=credentials_info['refresh_token'],
        token_uri=credentials_info['token_uri'],
        client_id=credentials_info['client_id'],
        client_secret=credentials_info['client_secret']
    )
    service = build('gmail', 'v1', credentials=credentials)

    try:
        results = service.users().messages().list(userId='me', maxResults=2).execute()
        messages = results.get('messages', [])

        if not messages:
            return {"message": "No messages found."}

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            email_content = msg['snippet']
            label = classify_email(email_content)
            response_message = generate_response(label)
            
            reply_to_email(service, msg, response_message)

        return {"message": "Processed emails successfully."}

    except HttpError as error:
        return {"error": f"An error occurred: {error}"}

@app.route('/result')
def result():
    message = request.args.get('message', 'No message provided.')
    error = request.args.get('error', None)
    return render_template_string('''
        <html>
        <body>
            <h1>Result</h1>
            <p>{{ message }}</p>
            {% if error %}
                <p style="color: red;">Error: {{ error }}</p>
            {% endif %}
            <button onclick="window.location.href='/'">Back to Home</button>
        </body>
        </html>
    ''', message=message, error=error)

def classify_email(email_content):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": f"Classify this email content: {email_content}. Labels: Interested, Not Interested, More Information."}],
            max_tokens=50
        )
        label = response.choices[0].message['content'].strip()
        return label
    except Exception as e:
        print(f"Error classifying email: {e}")
        return "Unknown"

def generate_response(label):
    if label == "Interested":
        return "Thank you for your interest! Would you like to schedule a demo?"
    elif label == "Not Interested":
        return "We understand you're not interested. If that changes, feel free to reach out!"
    elif label == "More Information":
        return "I'd be happy to provide more information. Could you specify what you'd like to know?"
    else:
        return "Thank you for your email!"

def reply_to_email(service, msg, response_message):
    thread_id = msg['threadId']
    sender_email = None
    for header in msg['payload']['headers']:
        if header['name'] == 'From':
            sender_email = header['value']
            break

    if not sender_email:
        print("Sender email address not found.")
        return

    message = MIMEText(response_message)
    message['To'] = sender_email
    message['Subject'] = f"Re: {msg['snippet']}"
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    message_body = {
        'raw': encoded_message,
        'threadId': thread_id
    }
    
    service.users().messages().send(userId='me', body=message_body).execute()

if __name__ == '__main__':
    app.run()
