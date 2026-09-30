from services.sms_api_service import (
    check_oopspam,
    check_siftfy,
    check_nyckel,
    check_ipqualityscore
)
from services.sms_url_extractor import extract_urls
from services.url_api_aggregator import scan_url_with_apis
from services.url_service import analyze_url
from services.ml_detection_service import apply_ml_to_sms

def analyze_sms(message):
    api_results = [
        check_oopspam(message),
        check_siftfy(message),
        check_nyckel(message),
        check_ipqualityscore(message)
    ]

    extracted_urls = extract_urls(message)
    url_results = []
    for url in extracted_urls:
        url_api_results = scan_url_with_apis(url)
        analyzed_result = analyze_url(url, url_api_results)
        url_results.append({
            "url": url,
            "result": analyzed_result,
            "api_results": url_api_results
        })

    known_scores = [
        result.get("score", 0)
        for result in api_results
        if result.get("verdict") != "unknown"
    ]
    score = round(sum(known_scores) / len(known_scores)) if known_scores else 0

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    verdicts = [str(result.get("verdict", "unknown")).lower() for result in api_results]
    if "spam" in verdicts or "malicious" in verdicts:
        verdict = "dangerous"
    elif "suspicious" in verdicts:
        verdict = "suspicious"
    elif any(v in ("safe", "clean", "legitimate", "benign") for v in verdicts):
        verdict = "safe"
    elif known_scores:
        verdict = "suspicious" if score >= 30 else "safe"
    else:
        verdict = "unknown"

    reasons = []
    for result in api_results:
        api_name = result.get("api", "SMS API")
        reasons.extend(f"{api_name}: {reason}" for reason in result.get("reasons", []))

    for url_item in url_results:
        for result in url_item["api_results"]:
            api_name = result.get("api", "URL API")
            reasons.extend(
                f"{api_name} ({url_item['url']}): {reason}"
                for reason in result.get("reasons", [])
            )

    if not reasons:
        reasons.append("No specific API reasons were returned")

    result = {
        "score": score,
        "level": level,
        "verdict": verdict,
        "confidence": "normal" if known_scores else "limited",
        "reasons": list(dict.fromkeys(reasons)),
        "api_results": api_results,
        "extracted_urls": extracted_urls,
        "url_results": url_results
    }
    return apply_ml_to_sms(message, result)
