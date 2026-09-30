from services.hash_service import calculate_sha256
from services.ransomware_api_service import (
    check_virustotal,
    check_malwarebazaar,
    check_threatfox,
    check_hybrid_analysis,
    check_xexle,
)
from services.ml_detection_service import apply_ml_to_ransomware

def analyze_ransomware(file_path):
    file_hash = calculate_sha256(file_path)
    api_results = [
        check_virustotal(file_hash),
        check_malwarebazaar(file_hash),
        check_threatfox(file_hash),
        check_hybrid_analysis(file_hash),
        check_xexle(file_hash),
    ]

    malicious = sum(1 for result in api_results if result.get("verdict") == "malicious")
    suspicious = sum(1 for result in api_results if result.get("verdict") == "suspicious")
    safe = sum(1 for result in api_results if result.get("verdict") == "safe")
    unknown = sum(1 for result in api_results if result.get("verdict") == "unknown")

    if malicious > 0:
        level = "High"
        score = min(malicious * 25 + suspicious * 15, 100)
        verdict = "malicious"
    elif suspicious > 0:
        level = "Medium"
        score = min(suspicious * 15, 59)
        verdict = "suspicious"
    elif safe > 0:
        level = "Low"
        score = 0
        verdict = "safe"
    elif unknown == len(api_results):
        level = "Unknown"
        score = 0
        verdict = "unknown"
    else:
        level = "Unknown"
        score = 0
        verdict = "unknown"

    reasons = []
    for result in api_results:
        reasons.extend(result.get("reasons", []))

    result = {
        "score": score,
        "level": level,
        "verdict": verdict,
        "sha256": file_hash,
        "api_results": api_results,
        "reasons": list(dict.fromkeys(reasons)),
        "confidence": "normal" if any(r.get("verdict") != "unknown" for r in api_results) else "limited"
    }
    return apply_ml_to_ransomware(file_path, result)
