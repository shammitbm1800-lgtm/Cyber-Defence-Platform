from flask import request, jsonify, session, current_app
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from flask_mail import Message
from datetime import datetime, timedelta
import secrets

from models import db, User, Scan

def send_otp_email(user):
    otp = f"{secrets.randbelow(1000000):06d}"

    user.otp_hash = generate_password_hash(otp)
    user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)

    msg = Message(
        subject="Cyber Defence Platform - Email Verification",
        recipients=[user.email]
    )

    msg.body = f"""Hello {user.name},

Welcome to Cyber Defence Platform.

Your email verification OTP is:

{otp}

This OTP is valid for 10 minutes.

If you did not create this account, please ignore this email.

Regards,
Cyber Defence Platform
"""

    current_app.extensions["mail"].send(msg)

    return otp

def register_user():
    data = request.get_json(silent=True) or {}

    name = data.get(
        "name",
        ""
    ).strip()

    username = data.get(
        "username",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    if not name:
        return jsonify({
            "status": "error",
            "message": "Name is required"
        }), 400

    if not username:
        return jsonify({
            "status": "error",
            "message": "Username is required"
        }), 400

    if not email:
        return jsonify({
            "status": "error",
            "message": "Email is required"
        }), 400

    if not password:
        return jsonify({
            "status": "error",
            "message": "Password is required"
        }), 400

    if len(password) < 6:
        return jsonify({
            "status": "error",
            "message": "Password must contain at least 6 characters"
        }), 400

    existing_username = User.query.filter_by(
        username=username
    ).first()

    if existing_username:
        return jsonify({
            "status": "error",
            "message": "Username already exists"
        }), 409

    existing_email = User.query.filter_by(
        email=email
    ).first()

    if existing_email:
        return jsonify({
            "status": "error",
            "message": "An account with this email already exists"
        }), 409

    user = User(
        name=name,
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role="user",
        is_verified=False
    )

    db.session.add(user)

    try:
        send_otp_email(user)
        db.session.commit()

    except Exception as e:
        db.session.rollback()

        print("OTP email error:", e)

        return jsonify({
            "status": "error",
            "message": "Unable to send verification email. Please try again."
        }), 500

    return jsonify({
        "status": "success",
        "message": "Registration successful. Please verify your email.",
        "requires_verification": True,
        "email": user.email
    }), 201


def login_user():
    data = request.get_json(silent=True) or {}

    identifier = data.get(
        "identifier",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    if not identifier or not password:
        return jsonify({
            "status": "error",
            "message": "Username/email and password are required"
        }), 400

    user = User.query.filter(
        (User.username == identifier) |
        (User.email == identifier.lower())
    ).first()

    if not user:
        return jsonify({
            "status": "error",
            "message": "Invalid credentials"
        }), 401

    if not check_password_hash(
        user.password_hash,
        password
    ):
        return jsonify({
            "status": "error",
            "message": "Invalid credentials"
        }), 401

    if not user.is_verified:
        return jsonify({
            "status": "error",
            "message": "Please verify your email before logging in.",
            "requires_verification": True,
            "email": user.email
        }), 403

    session.clear()

    session["user_id"] = user.id
    session["user_name"] = user.name
    session["user_username"] = user.username
    session["user_email"] = user.email
    session["user_role"] = user.role

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    })

def verify_otp():
    data = request.get_json(silent=True) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()

    otp = data.get(
        "otp",
        ""
    ).strip()

    if not email or not otp:
        return jsonify({
            "status": "error",
            "message": "Email and OTP are required"
        }), 400

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:
        return jsonify({
            "status": "error",
            "message": "Account not found"
        }), 404

    if user.is_verified:
        return jsonify({
            "status": "success",
            "message": "Email is already verified"
        })

    if not user.otp_hash or not user.otp_expires_at:
        return jsonify({
            "status": "error",
            "message": "No active OTP. Please request a new one."
        }), 400

    if datetime.utcnow() > user.otp_expires_at:
        return jsonify({
            "status": "error",
            "message": "OTP has expired. Please request a new OTP."
        }), 400

    if not check_password_hash(
        user.otp_hash,
        otp
    ):
        return jsonify({
            "status": "error",
            "message": "Invalid OTP"
        }), 400

    user.is_verified = True
    user.otp_hash = None
    user.otp_expires_at = None

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Email verified successfully. You can now log in."
    })

def resend_otp():
    data = request.get_json(silent=True) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()

    if not email:
        return jsonify({
            "status": "error",
            "message": "Email is required"
        }), 400

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:
        return jsonify({
            "status": "error",
            "message": "Account not found"
        }), 404

    if user.is_verified:
        return jsonify({
            "status": "error",
            "message": "Email is already verified"
        }), 400

    try:
        send_otp_email(user)
        db.session.commit()

    except Exception as e:
        db.session.rollback()

        print("Resend OTP error:", e)

        return jsonify({
            "status": "error",
            "message": "Unable to send OTP. Please try again."
        }), 500

    return jsonify({
        "status": "success",
        "message": "A new OTP has been sent to your email."
    })

def logout_user():
    session.clear()

    return jsonify({
        "status": "success",
        "message": "Logout successful"
    })


def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "status": "error",
            "message": "Not authenticated"
        }), 401

    user = db.session.get(
        User,
        user_id
    )

    if not user:
        session.clear()

        return jsonify({
            "status": "error",
            "message": "User session is invalid"
        }), 401

    return jsonify({
        "status": "success",
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    })

def require_admin():
    user_id = session.get("user_id")

    if not user_id:
        return None, jsonify({
            "status": "error",
            "message": "Authentication required"
        }), 401

    user = db.session.get(
        User,
        user_id
    )

    if not user:
        session.clear()

        return None, jsonify({
            "status": "error",
            "message": "Invalid session"
        }), 401

    if user.role != "admin":
        return None, jsonify({
            "status": "error",
            "message": "Administrator access required"
        }), 403

    return user, None, None


def get_admin_users():
    admin, error_response, status_code = require_admin()

    if error_response:
        return error_response, status_code

    users = User.query.order_by(
        User.id.asc()
    ).all()

    return jsonify({
        "status": "success",
        "users": [
            {
                "id": user.id,
                "name": user.name,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "created_at": (
                    user.created_at.isoformat()
                    if user.created_at
                    else None
                )
            }
            for user in users
        ]
    })


def get_admin_stats():
    admin, error_response, status_code = require_admin()

    if error_response:
        return error_response, status_code

    total_users = User.query.count()
    total_scans = Scan.query.count()

    threat_count = Scan.query.filter(
        Scan.final_verdict.in_([
            "Dangerous",
            "dangerous",
            "Malicious",
            "malicious"
        ])
    ).count()

    return jsonify({
        "status": "success",
        "stats": {
            "total_users": total_users,
            "total_scans": total_scans,
            "threats_detected": threat_count
        }
    })


def delete_admin_user(user_id):
    admin, error_response, status_code = require_admin()

    if error_response:
        return error_response, status_code

    user = db.session.get(
        User,
        user_id
    )

    if not user:
        return jsonify({
            "status": "error",
            "message": "User not found"
        }), 404

    if user.role == "admin":
        return jsonify({
            "status": "error",
            "message": "Admin account cannot be deleted"
        }), 403

    db.session.delete(user)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "User deleted successfully"
    })