from datetime import datetime

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Scan(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    scan_type = db.Column(
        db.String(50),
        nullable=False
    )

    input_content = db.Column(
        db.Text,
        nullable=True
    )

    url = db.Column(
        db.String(500),
        nullable=True
    )

    filename = db.Column(
        db.String(500),
        nullable=True
    )

    sha256 = db.Column(
        db.String(64),
        nullable=True
    )

    ocr_text = db.Column(
        db.Text,
        nullable=True
    )

    final_verdict = db.Column(
        db.String(50),
        nullable=True
    )

    internal_score = db.Column(
        db.Integer,
        nullable=True
    )

    confidence = db.Column(
        db.String(50),
        nullable=True
    )

    reasons = db.Column(
        db.Text,
        nullable=True
    )

    api_results = db.Column(
        db.Text,
        nullable=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )


class User(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(120),
        nullable=False
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
        index=True
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(50),
        nullable=False,
        default="user"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    is_verified = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    otp_hash = db.Column(
        db.String(255),
        nullable=True
    )

    otp_expires_at = db.Column(
        db.DateTime,
        nullable=True
    )