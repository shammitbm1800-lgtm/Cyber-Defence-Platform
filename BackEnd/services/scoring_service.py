def calculate_final_score(results):
    """
    Universal API-evidence scoring engine.

    Used by:
    - URL
    - Email
    - SMS
    - Ransomware

    User-facing verdicts:
    - Safe
    - Suspicious
    - Dangerous
    - Unknown
    """

    if not results:
        return {
            "verdict": "Unknown",
            "reasons": ["No API evidence available"],
            "internal_score": 0,
            "confidence": "limited"
        }

    verdict_map = {
        "safe": "safe",
        "clean": "safe",
        "legitimate": "safe",
        "benign": "safe",

        "suspicious": "suspicious",
        "questionable": "suspicious",

        "malicious": "dangerous",
        "phishing": "dangerous",
        "spam": "dangerous",
        "dangerous": "dangerous",
        "malware": "dangerous",

        "unknown": "unknown",
        "not_found": "unknown",
        "undetected": "unknown"
    }

    evidence = []
    reasons = []
    has_fallback = False

    for result in results:
        api_name = result.get("api", "Unknown API")

        if result.get("source") == "fallback":
            has_fallback = True

        raw_verdict = str(
            result.get("verdict", "unknown")
        ).strip().lower()

        normalized_verdict = verdict_map.get(
            raw_verdict,
            "unknown"
        )

        raw_score = result.get("score")

        try:
            api_score = float(raw_score)
            api_score = max(0, min(api_score, 100))
        except (TypeError, ValueError):
            api_score = None

        if api_score is None:
            if normalized_verdict == "safe":
                api_score = 0
            elif normalized_verdict == "suspicious":
                api_score = 50
            elif normalized_verdict == "dangerous":
                api_score = 100

        if normalized_verdict == "unknown":
            continue

        evidence.append({
            "api": api_name,
            "verdict": normalized_verdict,
            "score": api_score
        })

        for reason in result.get("reasons", []):
            reasons.append(
                f"{api_name}: {reason}"
            )

    if not evidence:
        return {
            "verdict": "Unknown",
            "reasons": [
                "No API provided a useful threat verdict"
            ],
            "internal_score": 0,
            "confidence": "limited"
        }

    dangerous_count = sum(
        1
        for item in evidence
        if item["verdict"] == "dangerous"
    )

    suspicious_count = sum(
        1
        for item in evidence
        if item["verdict"] == "suspicious"
    )

    safe_count = sum(
        1
        for item in evidence
        if item["verdict"] == "safe"
    )

    scored_results = [
        item
        for item in evidence
        if item["score"] is not None
    ]

    if scored_results:
        total_score = sum(
            item["score"]
            for item in scored_results
        )

        internal_score = round(
            total_score / len(scored_results)
        )
    else:
        internal_score = 0

    # Final platform verdict.
    #
    # A confirmed dangerous result must never be
    # overridden by safe results from other APIs.
    if dangerous_count >= 1:
        final_verdict = "Dangerous"

    elif suspicious_count >= 1:
        final_verdict = "Suspicious"

    elif safe_count >= 1:
        final_verdict = "Safe"

    else:
        final_verdict = "Unknown"

    confidence = "limited" if has_fallback else "normal"

    return {
        "verdict": final_verdict,
        "reasons": reasons,
        "internal_score": internal_score,
        "confidence": confidence
    }