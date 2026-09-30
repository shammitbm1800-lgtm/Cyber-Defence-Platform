from flask import request, jsonify
import json

from services.url_api_aggregator import check_all_url_apis
from services.url_service import analyze_url, validate_url
from services.scoring_service import calculate_final_score
from models import db, Scan


def scan_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "No URL provided"
        }), 400

    # Step 1: Validate URL
    validation = validate_url(url)

    if not validation["valid"]:
        return jsonify({
            "status": "error",
            "message": validation["message"]
        }), 400

    # Use the normalized URL returned by validation
    url = validation["url"]

    # Step 2: Check all available URL APIs
    api_results = check_all_url_apis(url)

    # Step 3: Use API results first.
    # Local fallback is used only when APIs provide no useful result.
    results_for_scoring = analyze_url(url, api_results)

    # Step 4: Calculate final verdict
    final_result = calculate_final_score(results_for_scoring)

    # Step 5: Store scan using the DB-clean schema
    new_scan = Scan(
        scan_type="url",
        input_content=url,
        url=url,
        final_verdict=final_result.get(
            "verdict",
            "Unknown"
        ),
        internal_score=final_result.get(
            "internal_score",
            0
        ),
        confidence=final_result.get(
            "confidence",
            "limited"
        ),
        reasons=json.dumps(
            final_result.get(
                "reasons",
                []
            )
        ),
        api_results=json.dumps(
            results_for_scoring
        )
    )

    db.session.add(new_scan)
    db.session.commit()

    # Step 6: Return user-facing verdict plus the ML evidence.
    ml_result = next(
        (
            item.get("ml_result")
            for item in results_for_scoring
            if item.get("source") == "ml"
        ),
        None
    )

    return jsonify({
        "status": "success",
        "result": {
            "verdict": final_result["verdict"],
            "reasons": final_result["reasons"],
            "confidence": final_result["confidence"],
            "score": final_result.get("internal_score", 0),
            "ml": ml_result
        }
    })

def get_scan_history():
    scans = Scan.query.order_by(
        Scan.timestamp.desc()
    ).all()

    history = []

    for scan in scans:
        history.append({
            "id": scan.id,
            "scan_type": scan.scan_type,
            "input_content": scan.input_content,
            "url": scan.url,
            "filename": scan.filename,
            "sha256": scan.sha256,
            "ocr_text": scan.ocr_text,
            "final_verdict": scan.final_verdict,
            "internal_score": scan.internal_score,
            "confidence": scan.confidence,
            "reasons": scan.reasons,
            "api_results": scan.api_results,
            "timestamp": (
                scan.timestamp.isoformat()
                if scan.timestamp
                else None
            )
        })

    return jsonify({
        "status": "success",
        "history": history
    })

def clear_scan_history():
    Scan.query.delete()
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Scan history cleared successfully"
    })