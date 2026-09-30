import os

from routes.contact_routes import contact_bp
from flask import Flask, send_from_directory
from flask_mail import Mail
from flask_cors import CORS
from dotenv import load_dotenv

from routes.scan_routes import scan_bp
from routes.email_routes import email_bp
from routes.sms_routes import sms_bp
from routes.ransomware_routes import ransomware_bp
from routes.ocr_routes import ocr_bp
from routes.auth_routes import auth_bp
from routes.file_routes import file_bp
from routes.contact_routes import contact_bp

from models import db


load_dotenv()


# Serve the existing FrontEnd directly from Flask
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(
    os.path.join(BASE_DIR, "..", "FrontEnd")
)


# ==========================================
# FLASK APPLICATION
# ==========================================

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path=""
)


# ==========================================
# SECRET KEY
# ==========================================

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    "development-secret-change-me"
)


# ==========================================
# EMAIL CONFIGURATION
# ==========================================

app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv(
    "MAIL_DEFAULT_SENDER",
    os.getenv("MAIL_USERNAME")
)

mail = Mail(app)


# ==========================================
# CORS
# ==========================================

CORS(
    app,
    supports_credentials=True,
    origins=[
        "http://127.0.0.1:5000",
        "http://localhost:5000",
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ]
)


# ==========================================
# DATABASE
# ==========================================

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///cyber_clean.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["MAX_CONTENT_LENGTH"] = (
    50 * 1024 * 1024
)

db.init_app(app)


# ==========================================
# SCAN BLUEPRINTS
# ==========================================

app.register_blueprint(
    scan_bp,
    url_prefix="/scan"
)

app.register_blueprint(
    email_bp,
    url_prefix="/scan"
)

app.register_blueprint(
    sms_bp,
    url_prefix="/scan"
)

app.register_blueprint(
    ransomware_bp,
    url_prefix="/scan"
)

app.register_blueprint(
    ocr_bp,
    url_prefix="/scan"
)


# ==========================================
# AUTHENTICATION BLUEPRINT
# ==========================================

app.register_blueprint(
    auth_bp,
    url_prefix="/auth"
)


# ==========================================
# FILE ANALYZER
# ==========================================

app.register_blueprint(
    file_bp,
    url_prefix="/scan"
)

app.register_blueprint(
    contact_bp
)

# ==========================================
# DATABASE INITIALIZATION
# ==========================================

with app.app_context():
    db.create_all()


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():
    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":
    app.run(
        debug=True
    )