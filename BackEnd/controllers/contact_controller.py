from flask import Blueprint, request, jsonify, current_app
from flask_mail import Message


def send_contact_inquiry():
    data = request.get_json(silent=True) or {}

    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()
    email = data.get("email", "").strip()
    company = data.get("company", "").strip()
    message = data.get("message", "").strip()

    if not first_name:
        return jsonify({
            "status": "error",
            "message": "First name is required"
        }), 400

    if not last_name:
        return jsonify({
            "status": "error",
            "message": "Last name is required"
        }), 400

    if not email:
        return jsonify({
            "status": "error",
            "message": "Email address is required"
        }), 400

    if not message:
        return jsonify({
            "status": "error",
            "message": "Message is required"
        }), 400

    mail = current_app.extensions.get("mail")

    if mail is None:
        return jsonify({
            "status": "error",
            "message": "Email service is not configured"
        }), 500

    company_display = company if company else "Not provided"

    email_body = f"""
New Contact Inquiry
===================

Name:
{first_name} {last_name}

Work Email:
{email}

Company / Organization:
{company_display}

Message:
{message}

-------------------
Cyber Defence Platform
Contact Security Team
"""

    try:
        msg = Message(
            subject="Cyber Defence Platform - New Security Inquiry",
            recipients=[
                "cyberdefence.support@gmail.com"
            ],
            sender=current_app.config.get(
                "MAIL_DEFAULT_SENDER"
            ),
            reply_to=email,
            body=email_body
        )

        mail.send(msg)

        return jsonify({
            "status": "success",
            "message": "Your inquiry has been sent successfully"
        })

    except Exception as error:
        current_app.logger.error(
            "Contact inquiry email error: %s",
            error
        )

        return jsonify({
            "status": "error",
            "message": "Unable to send your inquiry. Please try again."
        }), 500