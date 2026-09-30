from flask import request, jsonify
import json

from services.sms_service import analyze_sms
from models import db, Scan


def scan_sms():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({
            "status": "error",
            "message": "SMS message is required"
        }), 400

    # Keep the current SMS API analysis
    result = analyze_sms(message)

    # Store using the DB-clean schema
    new_scan = Scan(
        scan_type="sms",
        input_content=message,
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