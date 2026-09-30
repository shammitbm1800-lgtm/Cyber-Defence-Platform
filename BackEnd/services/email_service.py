from services.email_api_service import analyze_email_with_apis
from services.ml_detection_service import apply_ml_to_email

def analyze_email(email):
    """API/content analysis plus the Phase 2 local ML classifier."""
    api_result = analyze_email_with_apis(email)
    api_score = api_result.get("score", 0)
    api_verdict = api_result.get("verdict", "unknown")
    reasons = list(api_result.get("reasons", []))

    suspicious_keywords = [
        "urgent", "verify", "password", "account", "click here",
        "winner", "prize", "bank", "login", "suspended",
        "confirm your identity", "security alert", "act now", "immediately"
    ]
    text = email.lower()
    keyword_findings = [
        f"Suspicious keyword detected: {keyword}"
        for keyword in suspicious_keywords if keyword in text
    ]

    urls_found = api_result.get("urls_found", [])
    if urls_found:
        keyword_findings.append(f"{len(urls_found)} URL(s) found in the email")

    keyword_count = len([
        finding for finding in keyword_findings
        if "Suspicious keyword detected:" in finding
    ])
    content_score = min(keyword_count * 10, 70)
    if urls_found:
        content_score = min(content_score + 10, 80)

    final_score = round((api_score * 0.6) + (content_score * 0.4))
    final_score = min(max(final_score, 0), 100)

    if api_verdict == "phishing":
        final_verdict = "phishing"
    elif final_score >= 20:
        final_verdict = "suspicious"
    else:
        final_verdict = "safe"

    level = "High" if final_verdict == "phishing" or final_score >= 60 else "Medium" if final_score >= 20 else "Low"
    reasons.extend(keyword_findings)
    reasons = list(dict.fromkeys(reasons))

    result = {
        "score": final_score,
        "level": level,
        "verdict": final_verdict,
        "confidence": "normal" if api_result.get("results") else "limited",
        "reasons": reasons,
        "api_results": api_result.get("results", []),
        "email_addresses_found": api_result.get("email_addresses_found", []),
        "urls_found": urls_found
    }
    return apply_ml_to_email(email, result)
