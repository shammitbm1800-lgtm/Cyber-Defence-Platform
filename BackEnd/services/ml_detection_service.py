import json
from typing import Any

from ml.predictors import (
    predict_url,
    predict_email,
    predict_sms,
    predict_ransomware_file,
)

def _ml_reason(result: dict) -> str:
    model = result.get("model", "ML model")
    label = result.get("label", "unknown")
    score = result.get("score", 0)
    return f"{model}: {label} (risk score {score}/100)"

def apply_ml_to_url(url: str, existing_results: list[dict]) -> list[dict]:
    try:
        result = predict_url(url)
        normalized = "phishing" if result["label"] == "phishing" else (
            "suspicious" if result["label"] == "suspicious" else "safe"
        )
        existing_results = list(existing_results or [])
        existing_results.append({
            "api": "ML URL Classifier",
            "source": "ml",
            "verdict": normalized,
            "score": result["score"],
            "confidence": "model",
            "reasons": [_ml_reason(result)],
            "ml_result": result,
        })
        return existing_results
    except Exception as exc:
        return list(existing_results or []) + [{
            "api": "ML URL Classifier",
            "source": "ml",
            "verdict": "unknown",
            "score": 0,
            "confidence": "limited",
            "reasons": [f"ML model unavailable: {exc}"],
        }]

def enrich_text_result(result: dict, ml_result: dict, positive_verdict: str) -> dict:
    result = dict(result)
    result["ml"] = ml_result
    result["ml_model"] = ml_result.get("model")
    result["ml_score"] = ml_result.get("score", 0)
    result["score"] = max(int(result.get("score", 0) or 0), int(round(ml_result.get("score", 0) or 0)))
    result.setdefault("reasons", [])
    result["reasons"] = list(dict.fromkeys(result["reasons"] + [_ml_reason(ml_result)]))
    # High-confidence ML finding can provide a final ML-based verdict while existing API evidence remains.
    if ml_result.get("label") == positive_verdict:
        result["verdict"] = positive_verdict
        result["level"] = "High"
    elif ml_result.get("label") == "suspicious" and str(result.get("verdict", "")).lower() in ("safe", "unknown", ""):
        result["verdict"] = "suspicious"
        result["level"] = "Medium"
    return result

def apply_ml_to_email(email: str, result: dict) -> dict:
    try:
        return enrich_text_result(result, predict_email(email), "phishing")
    except Exception as exc:
        result = dict(result)
        result.setdefault("reasons", []).append(f"Email ML unavailable: {exc}")
        result["ml"] = {"label": "unavailable", "error": str(exc)}
        return result

def apply_ml_to_sms(message: str, result: dict) -> dict:
    try:
        ml_result = predict_sms(message)
        result = dict(result)
        result["ml"] = ml_result
        result["ml_model"] = ml_result.get("model")
        result["ml_score"] = ml_result.get("score", 0)
        result["score"] = max(int(result.get("score", 0) or 0), int(round(ml_result.get("score", 0) or 0)))
        result.setdefault("reasons", [])
        result["reasons"] = list(dict.fromkeys(result["reasons"] + [_ml_reason(ml_result)]))
        if ml_result.get("label") == "spam":
            result["verdict"] = "dangerous"
            result["level"] = "High"
        elif ml_result.get("label") == "suspicious" and str(result.get("verdict", "")).lower() in ("safe", "unknown", ""):
            result["verdict"] = "suspicious"
            result["level"] = "Medium"
        return result
    except Exception as exc:
        result = dict(result)
        result.setdefault("reasons", []).append(f"SMS ML unavailable: {exc}")
        result["ml"] = {"label": "unavailable", "error": str(exc)}
        return result

def apply_ml_to_ransomware(file_path: str, result: dict) -> dict:
    try:
        ml_result = predict_ransomware_file(file_path)
        result = dict(result)
        result["ml"] = ml_result
        result["ml_model"] = ml_result.get("model")
        result["ml_score"] = ml_result.get("score", 0)
        result.setdefault("reasons", [])
        result["reasons"] = list(dict.fromkeys(result["reasons"] + [_ml_reason(ml_result)]))
        if ml_result.get("label") == "ransomware":
            result["verdict"] = "malicious"
            result["level"] = "High"
            result["score"] = max(int(result.get("score", 0)), int(round(ml_result["score"])))
        elif ml_result.get("label") == "suspicious":
            result["level"] = "Medium" if result.get("level") not in ("High", "high") else result["level"]
            result["score"] = max(int(result.get("score", 0)), int(round(ml_result["score"])))
        return result
    except Exception as exc:
        result = dict(result)
        result.setdefault("reasons", []).append(f"Ransomware ML unavailable: {exc}")
        result["ml"] = {"label": "unavailable", "error": str(exc)}
        return result
