from flask import request, jsonify
import json

from services.email_service import analyze_email
from models import db, Scan


def scan_email():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()

    if not email:
        return jsonify({
            "status": "error",
            "message": "Email content is required"
        }), 400

    # Keep the current API-integrated email analysis
    result = analyze_email(email)

    # Store using the DB-clean schema
    new_scan = Scan(
        scan_type="email",
        input_content=email,
        final_verdict=result.get(
            "verdict",
            "unknown"
        ),
        internal_score=result.get(
            "score",
            0
        ),
        confidence=result.get(
            "confidence",
            "limited"
        ),
        reasons=json.dumps(
            result.get(
                "reasons",
                []
            )
        ),
        api_results=json.dumps({
            "api_results": result.get("api_results", []),
            "ml": result.get("ml")
        })
    )

    db.session.add(new_scan)
    db.session.commit()

    return jsonify({
        "status": "success",
        "result": result
    })