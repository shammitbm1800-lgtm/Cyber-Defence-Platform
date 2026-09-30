from urllib.parse import urlparse
import socket

from services.ml_detection_service import apply_ml_to_url


def validate_url(url):
    """
    Validate URL format and check whether the domain exists.
    """
    url = url.strip()
    if not url:
        return {"valid": False, "status": "invalid", "message": "No URL provided"}

    test_url = url
    if not test_url.startswith(("http://", "https://")):
        test_url = "https://" + test_url

    parsed = urlparse(test_url)
    if not parsed.netloc:
        return {"valid": False, "status": "invalid", "message": "Invalid URL format"}

    hostname = parsed.hostname
    if not hostname:
        return {"valid": False, "status": "invalid", "message": "Invalid URL format"}

    if "." not in hostname and not hostname.replace(".", "").isdigit():
        return {"valid": False, "status": "invalid", "message": "Invalid URL format"}

    try:
        socket.gethostbyname(hostname)
    except socket.gaierror:
        # Keep the existing behavior. ML inference itself does not require DNS,
        # but the legacy API-first scanner still does.
        return {"valid": False, "status": "not_found", "message": "URL not found"}

    return {"valid": True, "status": "valid", "url": test_url}


def local_fallback_analysis(url):
    findings = []
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return {
            "api": "Local Fallback", "source": "fallback", "confidence": "limited",
            "verdict": "unknown", "score": 0,
            "reasons": ["Invalid URL format"], "raw_result": {}
        }

    hostname = parsed.hostname or ""
    parts = hostname.split(".")

    if len(parts) == 4 and all(part.isdigit() for part in parts):
        findings.append({"reason": "IP address used instead of a domain", "score": 40})

    if len(hostname.split(".")) >= 5:
        findings.append({"reason": "Excessive number of subdomains", "score": 20})

    if len(url) > 100:
        findings.append({"reason": "Unusually long URL", "score": 20})

    suspicious_keywords = [
        "login", "verify", "account", "password", "secure", "update", "signin"
    ]
    lower_url = url.lower()
    for keyword in suspicious_keywords:
        if keyword in lower_url:
            findings.append({"reason": f"Suspicious keyword: {keyword}", "score": 10})

    total_score = min(sum(item["score"] for item in findings), 100)
    verdict = "dangerous" if total_score >= 60 else "suspicious" if total_score >= 30 else "safe"
    reasons = [item["reason"] for item in findings]
    if not reasons:
        reasons.append("No strong suspicious indicators found")

    return {
        "api": "Local Fallback", "source": "fallback", "confidence": "limited",
        "verdict": verdict, "score": total_score, "reasons": reasons,
        "raw_result": findings
    }


def analyze_url(url, api_results):
    """
    Preserve the existing API-first behavior and append the local ML model
    as additional evidence. The existing scoring_service can therefore use
    both API and ML evidence without removing the old path.
    """
    useful_results = []
    for result in api_results:
        verdict = str(result.get("verdict", "unknown")).lower()
        if verdict != "unknown":
            useful_results.append(result)

    base_results = useful_results if useful_results else [local_fallback_analysis(url)]
    return apply_ml_to_url(url, base_results)
