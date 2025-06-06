from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import bcrypt
import logging
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
import random
from datetime import datetime, timedelta
import datetime as dt
from flask import Flask, render_template, request, jsonify, send_file
import os
import google.generativeai as genai
from io import BytesIO
from PIL import Image
from gtts import gTTS
from langdetect import detect
from deep_translator import GoogleTranslator
import tempfile
from flask_cors import CORS
import logging
import base64
from datetime import datetime
from functools import wraps
from flask.cli import with_appcontext
import click
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import json
import requests

# Load environment variables from .env file
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a file handler
handler = logging.FileHandler('app.log')
handler.setLevel(logging.DEBUG)

# Create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_new.db'
app.config['SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)

# Configure OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

logger.info("Google OAuth client configured")
if not os.getenv('GOOGLE_CLIENT_ID') or not os.getenv('GOOGLE_CLIENT_SECRET'):
    logger.warning("Google OAuth credentials not set. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env file.")

# Email configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.getenv('EMAIL_USER'),
    MAIL_PASSWORD=os.getenv('EMAIL_PASSWORD'),
    # MAIL_DEFAULT_SENDER=os.environ.get('EMAIL_USER'),
    MAIL_MAX_EMAILS=None,
    MAIL_ASCII_ATTACHMENTS=False
)

if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
    logger.warning('Email credentials not set. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.')
    
# Initialize Flask-Mail after configuration
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=True)  # Can be null for OAuth users
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    reset_otp = db.Column(db.String(6), nullable=True)
    otp_created_at = db.Column(db.DateTime, nullable=True)
    oauth_provider = db.Column(db.String(20), nullable=True)  # 'google', etc.
    oauth_id = db.Column(db.String(100), nullable=True)  # Provider-specific unique ID
    oauth_data = db.Column(db.Text, nullable=True)  # JSON data from provider

    def _init_(self, username, email, password=None, is_admin=False, oauth_provider=None, oauth_id=None, oauth_data=None):
        self.username = username
        self.email = email
        if password:
            self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.is_admin = is_admin
        self.oauth_provider = oauth_provider
        self.oauth_id = oauth_id
        self.oauth_data = oauth_data

    def _repr_(self):
        return f"User('{self.username}', '{self.email}')"
    
    def check_password(self, password):
        if self.password:
            return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
        return False
    
with app.app_context():
    db.create_all()
    
    # Add migration code to add OAuth columns if they don't exist
    inspector = db.inspect(db.engine)
    columns = [column['name'] for column in inspector.get_columns('user')]
    
    # Check if we need to add the OAuth columns
    if 'oauth_provider' not in columns:
        logger.info("Adding OAuth columns to User table")
        try:
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE user ADD COLUMN oauth_provider VARCHAR(20)'))
                conn.execute(db.text('ALTER TABLE user ADD COLUMN oauth_id VARCHAR(100)'))
                conn.execute(db.text('ALTER TABLE user ADD COLUMN oauth_data TEXT'))
                # SQLite doesn't support modifying columns, so we skip this for SQLite
                if db.engine.name != 'sqlite':
                    conn.execute(db.text('ALTER TABLE user MODIFY COLUMN password VARCHAR(50) NULL'))
                conn.commit()
            logger.info("OAuth columns added successfully")
        except Exception as e:
            # SQLite has limited ALTER TABLE support
            logger.warning(f"Could not alter table directly: {str(e)}")
            logger.info("Recreating database with new schema")
            
            # For SQLite, the easiest way is to delete the DB file and recreate
            if db.engine.name == 'sqlite':
                logger.info("Please delete the database file and restart the application to update the schema")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first() or User.query.filter_by(email=username).first()
        if user and user.check_password(password):
            session['username'] = user.username
            session['logged_in'] = True
            session['is_admin'] = user.is_admin
            user.last_login = datetime.utcnow()
            db.session.commit()
            logger.info(f"User {user.username} logged in successfully via password")
            return redirect(url_for('index'))
        logger.warning(f"Failed login attempt for username/email: {username}")
        return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    logger.info("Google login initiated")
    try:
        redirect_uri = url_for('google_authorize', _external=True)
        logger.info(f"Google OAuth redirect URI: {redirect_uri}")
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        logger.error(f"Error initiating Google login: {str(e)}")
        flash('Failed to connect to Google. Please try again later.', 'error')
        return redirect(url_for('login'))

@app.route('/login/google/authorize')
def google_authorize():
    try:
        logger.info("Processing Google OAuth callback")
        
        token = google.authorize_access_token()
        if not token:
            logger.error("No token received from Google")
            flash('Authentication failed. No token received.', 'error')
            return redirect(url_for('login'))
            
        logger.debug(f"Google OAuth token received: {token['access_token'][:10]}...")
        
        resp = google.get('userinfo')
        if not resp:
            logger.error("Failed to get user info from Google")
            flash('Failed to get user information', 'error')
            return redirect(url_for('login'))
            
        user_info = resp.json()
        logger.info(f"Google user info received: email={user_info.get('email')}, name={user_info.get('name')}")
        
        # Check if user exists with this Google ID
        google_id = user_info.get('id')
        email = user_info.get('email')
        
        if not email:
            logger.error("No email received from Google")
            flash('Could not get email from Google', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(oauth_id=google_id, oauth_provider='google').first()
        
        if not user:
            # Check if user with this email exists
            user = User.query.filter_by(email=email).first()
            if user:
                # Update existing user with Google OAuth info
                logger.info(f"Linking Google account to existing user: {user.username}")
                user.oauth_provider = 'google'
                user.oauth_id = google_id
                user.oauth_data = json.dumps(user_info)
            else:
                # Create new user
                username = email.split('@')[0]
                # Ensure username is unique
                base_username = username
                counter = 1
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{counter}"
                    counter += 1
                
                logger.info(f"Creating new user via Google OAuth: {username}")
                user = User(
                    username=username,
                    email=email,
                    oauth_provider='google',
                    oauth_id=google_id,
                    oauth_data=json.dumps(user_info)
                )
                db.session.add(user)
                
        # Update login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Set session
        session['username'] = user.username
        session['logged_in'] = True
        session['is_admin'] = user.is_admin
        logger.info(f"User {user.username} logged in successfully via Google")
        
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Google OAuth error: {str(e)}")
        logger.exception("Detailed OAuth error:")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    logger.info(f"User {session.get('username')} logging out")
    session.pop('username', None)
    session.pop('logged_in', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        conform_password = request.form['confirm_password']
        if password != conform_password:
            return render_template('register.html', error='Passwords do not match')
        try:
            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                return render_template('register.html', error='Username already exists')
        except:
            pass
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        logger.info(f"New user registered: {username}")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')


#FOR UPLOAADING

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max file size

# Creates the uploads folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Configure Gemini API
genai.configure(api_key="AIzaSyD4i5vCeP-dl8QRDetOdVc5gpjRe7SNe5o")
generation_config = {
"temperature": 0.4,
"top_p": 0.8,
"top_k": 40,
"max_output_tokens": 2048,
}

# Define the available languages
indian_languages = {
"Hindi": "hi",
"English": "en",
"Marathi": "mr",
"Telugu": "te",
"Tamil": "ta",
"Bengali": "bn",
"Gujarati": "gu",
"Kannada": "kn",
"Malayalam": "ml",
"Odia": "or",
"Punjabi": "pa",
"Urdu": "ur"
}

# Create a reverse mapping for language codes to names
language_codes = {v: k for k, v in indian_languages.items()}

def upload_to_gemini(image_file):
    try:
        logger.debug("Starting upload_to_gemini function")
        logger.debug(f"Image file type: {type(image_file)}")
        
        # Save the uploaded file temporarily
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_image.jpg')
        image_file.save(temp_path)
        
        # Open with PIL and convert to base64
        with Image.open(temp_path) as image:
            logger.debug(f"Image opened successfully: {image.format}, size: {image.size}")
            
            # Convert to RGB if necessary
            if image.mode in ('RGBA', 'LA') or (image.mode == 'P' and 'transparency' in image.info):
                logger.debug("Converting image to RGB")
                image = image.convert('RGB')
            
            # Save to bytes
            image_bytes = BytesIO()
            image.save(image_bytes, format='JPEG', quality=95)
            image_bytes.seek(0)
            
            # Convert to base64
            image_base64 = base64.b64encode(image_bytes.getvalue()).decode('utf-8')
            logger.debug("Image converted to base64 successfully")
            
            # Clean up temp file
            os.remove(temp_path)
            
            # Return Gemini-compatible parts
            return [{"mime_type": "image/jpeg", "data": image_base64}]
            
    except Exception as e:
        logger.error(f"Error in upload_to_gemini: {str(e)}")
        logger.exception("Detailed error:")
        return None

#detect_language
def detect_language(text):
    try:
        return detect(text)
    except Exception as e:
        return None

#translate_text
def translate_text(text, dest_language):
    try:
        return GoogleTranslator(source='auto', target=dest_language).translate(text)
    except Exception as e:
        return None
    
#text_to_speech
def text_to_speech(text, language):
    try:
        tts = gTTS(text=text, lang=language, slow=False)
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".mp3")
        tts.save(temp_file.name)
        return temp_file.name
    except Exception as e:
        return None    
    

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(f'uploads/{filename}')
            return redirect(url_for('home'))
    return render_template('upload.html')

@app.route('/process', methods=['POST'])
def process_image():
    logger.debug("Request received")
    logger.debug("Files in request: %s", list(request.files.keys()))
    logger.debug("Form data in request: %s", list(request.form.keys()))
    
    try:
        if 'file' not in request.files:
            logger.error("No file part in the request")
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        selected_language_code = request.form.get('language')
        
        logger.debug(f"File name: {file.filename}")
        logger.debug(f"Selected language code: {selected_language_code}")
        
        if not file or file.filename == '':
            logger.error("No file selected")
            return jsonify({'error': 'No file selected'}), 400
            
        if not selected_language_code or selected_language_code not in language_codes:
            logger.error("Invalid language selection")
            return jsonify({'error': f'Invalid language selection: {selected_language_code}'}), 400

        # Process with Gemini
        image_parts = upload_to_gemini(file)
        if not image_parts:
            logger.error("Failed to process image")
            return jsonify({'error': 'Failed to process image'}), 400

        # Create a new model instance for each request with the new model name
        model = genai.GenerativeModel('gemini-1.5-flash', generation_config=generation_config)
        
        # First detect text from image
        detect_prompt = "Extract and return only the text from this image. If there are multiple lines, preserve the line breaks."
        detect_response = model.generate_content([detect_prompt] + image_parts)
        detected_text = detect_response.text.strip()
        logger.debug(f"Detected text: {detected_text}")
        
        if not detected_text:
            logger.error("No text detected in image")
            return jsonify({'error': 'No text detected in image'}), 400
            
        # Detect language
        detected_lang = detect_language(detected_text) or "unknown"
        logger.debug(f"Detected language: {detected_lang}")

        # Get the language name for the translation prompt
        selected_language_name = language_codes[selected_language_code]

        # Translate text
        translate_prompt = f"Translate this text to {selected_language_name}. Return only the translated text, nothing else."
        translate_response = model.generate_content([translate_prompt, detected_text])
        translated_text = translate_response.text.strip()
        logger.debug(f"Translated text: {translated_text}")

        # Generate audio
        audio_file = text_to_speech(translated_text, selected_language_code)
        
        if not audio_file:
            logger.error("Failed to generate audio")
            return jsonify({'error': 'Failed to generate audio'}), 400

        # Save audio file
        temp_audio_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_audio.mp3')
        with open(audio_file, 'rb') as src, open(temp_audio_path, 'wb') as dst:
            dst.write(src.read())
        os.remove(audio_file)

        return jsonify({
            'detected_language': detected_lang,
            'translated_text': translated_text,
            'audio_path': 'static/uploads/temp_audio.mp3'
        })

    except Exception as e:
        logger.exception("Error processing request")
        return jsonify({'error': str(e)}), 500

@app.route('/download_audio')
def download_audio():
    audio_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_audio.mp3')
    if (os.path.exists(audio_path)):
        return send_file(audio_path, as_attachment=True, download_name='translated_audio.mp3')
    return jsonify({'error': 'Audio file not found'}), 404

@app.route('/results')
def results():
    return render_template('result.html')

# Admin middleware
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        username = session.get('username')
        user = User.query.filter_by(username=username).first()
        if not user or not user.is_admin:
            flash('Admin access required')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>/toggle_status', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.username != session.get('username'):  # Prevent admin from deactivating themselves
        user.is_active = not user.is_active
        db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username != session.get('username'):  # Prevent admin from deleting themselves
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('admin_users'))

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices('0123456789', k=6))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate OTP
            otp = generate_otp()
            print(f"Generated OTP: {otp}")  # For debugging purposes
            user.reset_otp = otp
            user.otp_created_at = datetime.now(dt.UTC)
            db.session.commit()
            
            # Store email in session for verification
            session['reset_email'] = email
            
            print("Sending OTP email...")
            try:
                # Send OTP via email
                msg = Message('LOCOTO - Password Reset OTP',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[email])
                msg.body = f'''Your OTP for password reset is: {otp}

This OTP will expire in 10 minutes.

If you did not request this password reset, please ignore this email.

Best regards,
LOCOTO Team'''
                
                # Log email attempt
                logger.info(f"Attempting to send OTP email to: {email}")
                mail.send(msg)
                flash('An OTP has been sent to your email address.', 'info')
                logger.info(f"Successfully sent OTP email to: {email}")
                return redirect(url_for('verify_otp'))
            except Exception as e:
                logger.error(f"Error sending email: {str(e)}")
                # Rollback the OTP changes since email failed
                user.reset_otp = None
                user.otp_created_at = None
                db.session.commit()
                # Log full error details
                logger.error(f"Detailed email error: {str(e)}")
                flash('Error sending OTP email. Please try again later.', 'error')
                return redirect(url_for('forgot_password'))
        else:
            flash('If an account exists with that email, you will receive an OTP.', 'info')
            return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        otp = request.form['otp']
        email = session.get('reset_email')
        if not email:
            flash('Invalid request. Please try again.', 'error')
            return redirect(url_for('forgot_password'))
            
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.reset_otp:
            flash('Invalid request. Please try again.', 'error')
            return redirect(url_for('forgot_password'))
            
        # Check if OTP is expired (10 minutes validity)
        current_time = datetime.now(dt.UTC)
        otp_time = user.otp_created_at
        if otp_time is None:
            flash('Invalid request. Please try again.', 'error')
            return redirect(url_for('forgot_password'))
            
        otp_time = otp_time.replace(tzinfo=dt.UTC)
        if current_time - otp_time > timedelta(minutes=10):
            user.reset_otp = None
            user.otp_created_at = None
            db.session.commit()
            flash('OTP has expired. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))
            
        if user.reset_otp == otp:
            session['otp_verified'] = True
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
            
    return render_template('verify_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session or 'otp_verified' not in session:
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')
            
        user = User.query.filter_by(email=session['reset_email']).first()
        if not user:
            return redirect(url_for('forgot_password'))
            
        # Update password
        user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.reset_otp = None
        user.otp_created_at = None
        db.session.commit()
        
        # Clear session
        session.pop('reset_email', None)
        session.pop('otp_verified', None)
        
        flash('Your password has been updated! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.cli.command("create-admin")
@click.argument("username")
@with_appcontext
def create_admin(username):
    """Promote a user to admin status."""
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_admin = True
        db.session.commit()
        click.echo(f"User {username} has been promoted to admin.")
    else:
        click.echo(f"User {username} not found.")

@app.route('/test-email')
def test_email():
    try:
        # Log current configuration
        logger.info(f"Testing email configuration...")
        logger.info(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
        logger.info(f"MAIL_PORT: {app.config['MAIL_PORT']}")
        logger.info(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
        logger.info(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
        
        # Try to send a test email
        msg = Message('LOCOTO - Test Email',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[app.config['MAIL_USERNAME']])
        msg.body = 'This is a test email to verify the email configuration.'
        mail.send(msg)
        return 'Email sent successfully! Check your inbox.'
    except Exception as e:
        logger.error(f"Test email error: {str(e)}")
        return f'Error sending email: {str(e)}'

@app.route('/test-oauth')
@admin_required
def test_oauth():
    """Route to check Google OAuth configuration status"""
    try:
        oauth_status = {
            'google_client_id': bool(os.getenv('GOOGLE_CLIENT_ID')),
            'google_client_secret': bool(os.getenv('GOOGLE_CLIENT_SECRET')),
        }
        
        logger.info(f"OAuth configuration status: Client ID set: {oauth_status['google_client_id']}, Client Secret set: {oauth_status['google_client_secret']}")
        
        return jsonify({
            'status': 'ok',
            'oauth_configured': all(oauth_status.values()),
            'details': {
                'client_id_set': oauth_status['google_client_id'],
                'client_secret_set': oauth_status['google_client_secret'],
            }
        })
    except Exception as e:
        logger.error(f"Error checking OAuth configuration: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False)