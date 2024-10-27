# Import required libraries
from flask import Flask, jsonify, request, redirect, session, url_for, render_template_string
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import openai  # Import OpenAI for email classification
from dotenv import load_dotenv
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for Flask sessions
load_dotenv()
# Set your client secrets file path and required Gmail scopes
CLIENT_SECRETS_FILE = "client_secret_google.json"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
    "https://www.googleapis.com/auth/gmail.send"
]



# Initialize OpenAI API key
openai.api_key = os.getenv("OPENAIKEY")
redirectURL = 'https://automatedemailresponderflask.onrender.com/oauth2callback'

# Home route with login button
@app.route('/')
def home():
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Home</title>
        </head>
        <body>
            <h1>Welcome to the Automated Email Responder</h1>
            <button onclick="window.location.href='/google_login'">Login with Google</button>
        </body>
        </html>
    ''')

# Initialize OAuth flow
@app.route('/google_login')
def google_login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
    flow.redirect_uri = redirectURL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

# Handle OAuth2 callback
@app.route('/oauth2callback')
def oauth2callback():
    print("OAuth callback received")
    state = session['state']
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES, state=state)
    flow.redirect_uri = redirectURL

    # Exchange the authorization code for credentials
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials

    # Convert credentials to a dictionary and return it
    credentials_info = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    # Save the credentials securely
    session['credentials'] = credentials_info

    # Call process_emails and redirect to result
    process_result = process_emails(credentials_info)
    
    # Safely access message and error
    message = process_result.get('message', 'No message returned.')
    error = process_result.get('error', '')

    return redirect(url_for('result', message=message, error=error))


# Route to process emails
def process_emails(credentials_info):
    # Create Credentials object from stored information
    credentials = Credentials(
        token=credentials_info['token'],
        refresh_token=credentials_info['refresh_token'],
        token_uri=credentials_info['token_uri'],
        client_id=credentials_info['client_id'],
        client_secret=credentials_info['client_secret']
    )

    # Build the Gmail API service
    service = build('gmail', 'v1', credentials=credentials)

    try:
        # Get the user's email messages
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])

        if not messages:
            return {"message": "No messages found."}

        # Parse messages and reply to them
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            email_content = msg['snippet']  # Use snippet or actual email body as needed
            label = classify_email(email_content)  # Classify the email
            response_message = generate_response(label)  # Generate response based on label
            
            # Example logic to reply to an email
            reply_to_email(service, msg, response_message)

        return {"message": "Processed emails successfully."}

    except Exception as error:
        return {"error": f"An error occurred: {error}"}

# Route to display result after processing
@app.route('/result')
def result():
    message = request.args.get('message', 'No message provided.')
    error = request.args.get('error', None)

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Result</title>
        </head>
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
    """Classify the email content using OpenAI API."""
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=f"Classify this email content: {email_content}. Labels: Interested, Not Interested, More Information.",
        max_tokens=50
    )
    label = response.choices[0].text.strip()
    return label

def generate_response(label):
    """Generate a response based on the email classification."""
    if label == "Interested":
        return "Thank you for your interest! Would you like to schedule a demo?"
    elif label == "Not Interested":
        return "We understand you're not interested. If that changes, feel free to reach out!"
    elif label == "More Information":
        return "I'd be happy to provide more information. Could you specify what you'd like to know?"
    else:
        return "Thank you for your email!"

def reply_to_email(service, msg, response_message):
    """Function to reply to an email."""
    thread_id = msg['threadId']
    
    # Create a message to send
    message_body = {
        'raw': encode_message(response_message),  # Encode the message content
        'threadId': thread_id
    }
    
    # Uncomment to send the email
    # service.users().messages().send(userId='me', body=message_body).execute()

def encode_message(message):
    """Encode the message in base64url format."""
    import base64
    from email.mime.text import MIMEText

    message = MIMEText(message)
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return raw

if __name__ == '__main__':
    app.run()
