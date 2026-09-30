from flask import request, jsonify
import json
import os
import tempfile

from services.ransomware_service import analyze_ransomware
from models import db, Scan

MAX_RANSOMWARE_UPLOAD = 50 * 1024 * 1024

def scan_ransomware():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "File is required"}), 400

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return jsonify({"status": "error", "message": "No file selected"}), 400

    if request.content_length and request.content_length > MAX_RANSOMWARE_UPLOAD + 1024 * 1024:
        return jsonify({"status": "error", "message": "File upload is too large"}), 413

    fd, temp_path = tempfile.mkstemp(prefix="cdf_ransomware_", suffix=".bin")
    os.close(fd)

    try:
        uploaded_file.save(temp_path)
        result = analyze_ransomware(temp_path)

        new_scan = Scan(
            scan_type="ransomware",
            input_content=uploaded_file.filename,
            filename=uploaded_file.filename,
            sha256=result.get("sha256"),
            final_verdict=result.get("verdict", result.get("level", "Unknown")),
            internal_score=result.get("score", 0),
            confidence=result.get("confidence", "limited"),
            reasons=json.dumps(result.get("reasons", [])),
            api_results=json.dumps({
                "api_results": result.get("api_results", []),
                "ml": result.get("ml")
            }),
        )

        db.session.add(new_scan)
        db.session.commit()

        return jsonify({
            "status": "success",
            "result": result
        })
    except Exception as exc:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": "Ransomware analysis failed safely."
        }), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
