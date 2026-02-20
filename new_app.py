import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from groq import Groq
from dotenv import load_dotenv
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables - check system environment first (for production), then .env1 file (for development)
load_dotenv(".env1", override=False)  # Don't override existing environment variables
groq_api_key = os.getenv("GROQ_API_KEY")
unsplash_access_key = os.getenv("UNSPLASH_ACCESS_KEY")
youtube_api_key = os.getenv("YOUTUBE_API_KEY")
secret_key = os.getenv("SECRET_KEY", "your_secret_key")
email_otp_api_key = os.getenv("EMAIL_OTP_API_KEY")

# Debug: Print API key status (without revealing actual keys)
print(f"API Keys Status:")
print(f"  GROQ_API_KEY: {'✓ Set' if groq_api_key else '✗ Missing'}")
print(f"  UNSPLASH_ACCESS_KEY: {'✓ Set' if unsplash_access_key else '✗ Missing'}")
print(f"  YOUTUBE_API_KEY: {'✓ Set' if youtube_api_key else '✗ Missing'}")
print(f"  SECRET_KEY: {'✓ Set' if secret_key != 'your_secret_key' else '✗ Using default'}")
print(f"  EMAIL_OTP_API_KEY: {'✓ Set' if email_otp_api_key else '✗ Missing'}")

app = Flask(__name__)

# Flask configuration
app.config["SECRET_KEY"] = secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Groq client (None if key missing)
client = Groq(api_key=groq_api_key) if groq_api_key else None


# -----------------------------
# Helper functions for validation
# -----------------------------
def is_valid_email(email: str) -> bool:
    """Validate email format with domain ending like @gmail.com, @yahoo.com, etc."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password: str, username: str = "") -> tuple:
    """Validate password against basic security rules."""
    import re
    reasons = []
    
    if len(password) < 8:
        reasons.append("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        reasons.append("Must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        reasons.append("Must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        reasons.append("Must contain at least one number.")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
        reasons.append("Must contain at least one special character.")
    
    return ("REJECTED", reasons) if reasons else ("ACCEPTED", [])


def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    """Send OTP to user's email using SMTP"""
    try:
        # Email configuration
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = os.getenv("SENDER_EMAIL", "your_email@gmail.com")
        sender_password = email_otp_api_key
        
        print(f"\nAttempting to send email to: {email}")
        print(f"Using sender: {sender_email}")
        
        if not sender_password or sender_password == "replace_with_16_char_gmail_app_password":
            print("Email service not configured - no valid EMAIL_OTP_API_KEY")
            return False, "Email service not configured. Please set EMAIL_OTP_API_KEY in .env1"
        
        # Create message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = email
        message["Subject"] = "Password Reset OTP - Your App"
        
        body = f"""
Hello,

You requested to reset your password for your account.

Your OTP for password reset is: {otp}

This OTP is valid for 10 minutes.

If you didn't request this, please ignore this email or contact support.

Best regards,
Your App Team
        """
        
        message.attach(MIMEText(body, "plain"))
        
        # Send email
        print("Connecting to Gmail SMTP...")
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        print("Logging into Gmail...")
        server.login(sender_email, sender_password)
        print("Sending email...")
        server.sendmail(sender_email, email, message.as_string())
        server.quit()
        
        print(f"Email sent successfully to {email}")
        return True, "OTP has been sent to your email"
        
    except Exception as e:
        print(f"Email sending failed: {str(e)}")
        return False, f"Failed to send OTP: {str(e)}"


def is_otp_valid(email, otp_code):
    """Check if OTP is valid"""
    otp_record = OTP.query.filter_by(email=email, otp_code=otp_code, is_used=False).first()
    
    if not otp_record:
        return False, "Invalid OTP"
    
    if datetime.utcnow() - otp_record.created_at > timedelta(minutes=10):
        return False, "OTP expired"
    
    return True, "Valid OTP"


def mark_otp_as_used(email, otp_code):
    """Mark OTP as used"""
    otp_record = OTP.query.filter_by(email=email, otp_code=otp_code).first()
    if otp_record:
        otp_record.is_used = True
        db.session.commit()


# -----------------------------
# Database model
# -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)


# -----------------------------
# Helper functions for external APIs
# -----------------------------
def fetch_image(query: str):
    """Fetch image URL from Unsplash. Returns None if no key or no result."""
    print(f"DEBUG: fetch_image called with query: '{query}'")
    print(f"DEBUG: UNSPLASH_ACCESS_KEY status: {'Set' if unsplash_access_key else 'Not set'}")
    
    if not unsplash_access_key:
        print("DEBUG: No Unsplash API key available")
        return None

    try:
        print(f"DEBUG: Making request to Unsplash API...")
        response = requests.get(
            "https://api.unsplash.com/search/photos",
            params={"query": query, "client_id": unsplash_access_key, "per_page": 1},
            timeout=10,
        )
        print(f"DEBUG: Response status code: {response.status_code}")
        
        if response.status_code != 200:
            print(f"DEBUG: API Error - Status: {response.status_code}, Response: {response.text[:200]}")
            return None
            
        data = response.json()
        results = data.get("results")
        print(f"DEBUG: Found {len(results) if results else 0} results")
        
        if results:
            image_url = results[0]["urls"]["regular"]
            print(f"DEBUG: Successfully fetched image URL: {image_url[:50]}...")
            return image_url
    except Exception as e:
        print(f"DEBUG: Exception in fetch_image: {type(e).__name__}: {str(e)}")
        return None

    print("DEBUG: No images found")
    return None


def fetch_video(query: str):
    """Fetch YouTube video URL. Returns None if no key or no result."""
    if not youtube_api_key:
        return None

    try:
        search_url = "https://www.googleapis.com/youtube/v3/search"
        params = {
            "part": "snippet",
            "q": query,
            "key": youtube_api_key,
            "type": "video",
            "maxResults": 1,
        }
        response = requests.get(search_url, params=params, timeout=10)
        data = response.json()
        items = data.get("items")
        if items:
            video_id = items[0]["id"]["videoId"]
            return f"https://www.youtube.com/watch?v={video_id}"
    except Exception:
        return None

    return None


# -----------------------------
# Routes: auth + pages
# -----------------------------
@app.route("/")
def home():
    # Always redirect to login page first
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    # Only allow logged in users to access chat
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("new_index.html", username=session["username"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            return render_template("register.html", error="All fields are required.")

        # Validate email format
        if not is_valid_email(email):
            return render_template("register.html", error="Please enter a valid email address (e.g., sample@gmail.com).")

        # Validate password security
        password_status, password_reasons = validate_password(password, username)
        if password_status == "REJECTED":
            error_message = "Password validation failed:<br><ul>"
            for reason in password_reasons:
                error_message += f"<li>{reason}</li>"
            error_message += "</ul>"
            return render_template("register.html", 
                                 error="Password validation failed.",
                                 password_errors=password_reasons,
                                 username=username,
                                 email=email)

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            return render_template(
                "register.html",
                error="Username or email already exists. Please use another.",
            )

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["username"] = user.username
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/test-otp")
def test_otp():
    """Test route to verify OTP system is working"""
    test_email = "test@example.com"
    test_otp = generate_otp()
    
    print(f"\nTESTING OTP SYSTEM")
    print(f"Test Email: {test_email}")
    print(f"Test OTP: {test_otp}")
    
    # Test OTP generation
    success, message = send_otp_email(test_email, test_otp)
    print(f"Result: {success} - {message}")
    
    return f"""
    <h1>OTP System Test</h1>
    <p><strong>Test Email:</strong> {test_email}</p>
    <p><strong>Test OTP:</strong> {test_otp}</p>
    <p><strong>Result:</strong> {message}</p>
    <p><strong>Check console for detailed output</strong></p>
    <a href="/login">Back to Login</a>
    """


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        print(f"\nForgot password request for email: {email}")
        
        if not email:
            print("Email is empty")
            return render_template("forgot_password.html", error="Email is required.")
        
        if not is_valid_email(email):
            print(f"Invalid email format: {email}")
            return render_template("forgot_password.html", error="Please enter a valid email address.")
        
        # Check if email exists in database
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"Email not found in database: {email}")
            return render_template("forgot_password.html", error="Email not found in our records.")
        
        print(f"User found: {user.username}")
        
        # Generate and send OTP
        otp = generate_otp()
        print(f"Generated OTP: {otp}")
        
        # Mark previous OTPs as used
        old_otps = OTP.query.filter_by(email=email, is_used=False).all()
        for old_otp in old_otps:
            old_otp.is_used = True
        
        # Save new OTP
        new_otp = OTP(email=email, otp_code=otp)
        db.session.add(new_otp)
        db.session.commit()
        print(f"OTP saved to database")
        
        # Send OTP email
        success, message = send_otp_email(email, otp)
        print(f"Email send result: {success} - {message}")
        
        if success:
            session['reset_email'] = email
            return render_template("verify_otp.html", email=email, success="OTP has been sent to your email.")
        else:
            return render_template("forgot_password.html", error=f"Failed to send OTP: {message}")
    
    return render_template("forgot_password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if 'reset_email' not in session:
        return redirect(url_for("forgot_password"))
    
    email = session['reset_email']
    
    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()
        
        if not otp_code:
            return render_template("verify_otp.html", email=email, error="OTP is required.")
        
        # Validate OTP
        is_valid, message = is_otp_valid(email, otp_code)
        if not is_valid:
            return render_template("verify_otp.html", email=email, error=message)
        
        # Mark OTP as used
        mark_otp_as_used(email, otp_code)
        session['otp_verified'] = True
        
        return redirect(url_for("reset_password"))
    
    return render_template("verify_otp.html", email=email)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if 'reset_email' not in session or not session.get('otp_verified'):
        return redirect(url_for("forgot_password"))
    
    email = session['reset_email']
    
    if request.method == "POST":
        new_password = request.form.get("password", "").strip()
        
        if not new_password:
            return render_template("reset_password.html", error="Password is required.")
        
        # Validate password
        user = User.query.filter_by(email=email).first()
        password_status, password_reasons = validate_password(new_password, user.username)
        
        if password_status == "REJECTED":
            error_message = "Password validation failed:<br><ul>"
            for reason in password_reasons:
                error_message += f"<li>{reason}</li>"
            error_message += "</ul>"
            return render_template("reset_password.html", error=error_message)
        
        # Update password
        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        user.password = hashed_password
        db.session.commit()
        
        # Clear session
        session.pop('reset_email', None)
        session.pop('otp_verified', None)
        
        return render_template("login.html", success="Password has been reset successfully. Please login with your new password.")
    
    return render_template("reset_password.html")


# -----------------------------
# Chat API
# -----------------------------
def should_end_conversation(message: str) -> tuple:
    """Check if the user wants to end the conversation and return (should_end, message, should_redirect)."""
    exit_commands = {
        'bye': ("Goodbye! It was nice chatting with you. Have a great day!", False),
        'end': ("Thanks for stopping by! Remember, every ending is just the start of another great conversation… see you soon!", False),
        'exit': ("Goodbye! Logging you out automatically...", True)
    }
    
    message_lower = message.lower().strip()
    if message_lower in exit_commands:
        # If it's an exit command, clear the session to logout
        if message_lower == 'exit':
            session.clear()
        return True, exit_commands[message_lower][0], exit_commands[message_lower][1]
    return False, "", False


@app.route("/chat", methods=["POST"])
def chat():
    # Only allow logged in users
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not client:
        return jsonify({"error": "GROQ_API_KEY is not configured in .env1 file."}), 500

    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()
    generate_image = data.get("generate_image", False)

    if not user_message:
        return jsonify({"error": "Message is required."}), 400

    # Check if user wants to end conversation
    should_end, goodbye_message, should_redirect = should_end_conversation(user_message)
    if should_end:
        return jsonify({
            "message": goodbye_message,
            "end_conversation": True,
            "should_redirect": should_redirect
        })

    try:
        chat_completion = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful and friendly assistant called BotFriend.",
                },
                {"role": "user", "content": user_message},
            ],
            timeout=30,  # Add timeout to prevent hanging
        )

        bot_message = chat_completion.choices[0].message.content

        response = {"message": bot_message}
        
        # Only generate image if explicitly requested via the image button
        if generate_image:
            image_url = fetch_image(user_message)
            if image_url:
                response["image_url"] = image_url
            else:
                response["message"] = bot_message + "\n\nSorry, I couldn't generate an image for your request. Please try again with a different description."
        
        # Optional video (always available)
        video_url = fetch_video(user_message)
        if video_url:
            response["video_url"] = video_url

        return jsonify(response)
    except Exception as e:
        print(f"Chat API Error: {type(e).__name__}: {str(e)}")
        return (
            jsonify(
                {
                    "error": f"Unable to get response from Groq API. {type(e).__name__}: {e}"
                }
            ),
            500,
        )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Database tables created/verified")
        print("Available tables:")
        print(f"   - User table: {User.query.count()} users")
        print(f"   - OTP table: {OTP.query.count()} OTP records")
    app.run(debug=True, port=5000)
