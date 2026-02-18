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

# Load environment variables
load_dotenv()   # ✅ CHANGED (was load_dotenv(".env1"))

groq_api_key = os.getenv("GROQ_API_KEY")
unsplash_access_key = os.getenv("UNSPLASH_ACCESS_KEY")
youtube_api_key = os.getenv("YOUTUBE_API_KEY")
secret_key = os.getenv("SECRET_KEY", "your_secret_key")
email_otp_api_key = os.getenv("EMAIL_OTP_API_KEY")

app = Flask(__name__)

# Flask configuration
app.config["SECRET_KEY"] = secret_key

# ✅ CHANGED: Safe DB config for Render + local
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///users.db"
)
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
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password: str, username: str = "") -> tuple:
    import re
    reasons = []

    if len(password) < 8 or len(password) > 64:
        reasons.append("Password length must be between 8 and 64 characters.")
    if not re.search(r'[A-Z]', password):
        reasons.append("Must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        reasons.append("Must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        reasons.append("Must contain at least one number.")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
        reasons.append("Must contain at least one special character.")
    if password != password.strip():
        reasons.append("Must not contain leading or trailing spaces.")
    if username and username.lower() in password.lower():
        reasons.append(f"Must not contain your username '{username}'.")
    if re.search(r'(012|123|234|345|456|567|678|789)', password):
        reasons.append("Must not contain sequential numbers (e.g., 123, 456).")
    if re.search(r'(abc|bcd|cde|def)', password.lower()):
        reasons.append("Must not contain sequential letters (e.g., abc, xyz).")
    if re.search(r'@123|@456|@789', password):
        reasons.append("Must not use common patterns like '@123'.")

    common_passwords = ['password', '123456', 'qwerty', 'abc123', 'admin', 'welcome']
    if any(common in password.lower() for common in common_passwords):
        reasons.append("Must not contain common passwords.")

    return ("REJECTED", reasons) if reasons else ("ACCEPTED", [])


def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = os.getenv("SENDER_EMAIL", "your_email@gmail.com")
        sender_password = email_otp_api_key

        if not sender_password:
            return False, "Email service not configured"

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = email
        message["Subject"] = "Password Reset OTP"

        body = f"""
Hello,

Your OTP for password reset is: {otp}

This OTP is valid for 10 minutes.
"""
        message.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())
        server.quit()

        return True, "OTP sent successfully"

    except Exception as e:
        return False, str(e)


def is_otp_valid(email, otp_code):
    otp_record = OTP.query.filter_by(
        email=email, otp_code=otp_code, is_used=False
    ).first()

    if not otp_record:
        return False, "Invalid OTP"

    if datetime.utcnow() - otp_record.created_at > timedelta(minutes=10):
        return False, "OTP expired"

    return True, "Valid OTP"


def mark_otp_as_used(email, otp_code):
    otp_record = OTP.query.filter_by(email=email, otp_code=otp_code).first()
    if otp_record:
        otp_record.is_used = True
        db.session.commit()


# -----------------------------
# Database models
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
# Routes
# -----------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
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

        if not is_valid_email(email):
            return render_template("register.html", error="Invalid email format.")

        status, reasons = validate_password(password, username)
        if status == "REJECTED":
            return render_template("register.html", error="Password validation failed.", password_errors=reasons)

        if User.query.filter(
            (User.username == username) | (User.email == email)
        ).first():
            return render_template("register.html", error="User already exists.")

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        db.session.add(User(username=username, email=email, password=hashed_password))
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

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/chat", methods=["POST"])
def chat():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not client:
        return jsonify({"error": "GROQ_API_KEY not configured"}), 500

    data = request.get_json() or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "Message required"}), 400

    try:
        completion = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": message},
            ],
            timeout=30,
        )
        return jsonify({"message": completion.choices[0].message.content})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
