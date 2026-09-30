import os
import re
import requests
from urllib.parse import quote
from dotenv import load_dotenv

load_dotenv()

TIMEOUT = 10


# ============================================================
# COMMON RESPONSE
# ============================================================

def _unknown(api, reason, raw_result=None):
    return {
        "api": api,
        "verdict": "unknown",
        "score": 0,
        "reasons": [reason],
        "raw_result": raw_result or {}
    }


# ============================================================
# EMAIL ADDRESS EXTRACTION
# ============================================================

def extract_email_addresses(text):
    """
    Extract email addresses from the supplied email content.
    """
    if not text:
        return []

    pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

    return list(dict.fromkeys(re.findall(pattern, text)))


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from email content.
    """
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(pattern, text)

    # Remove common punctuation accidentally captured
    cleaned = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


# ============================================================
# MAILROOK
# ============================================================

def check_mailrook(email_address):
    """
    Check an email address using MailRook.
    """

    api_key = os.getenv("MAILROOK_API_KEY")

    if not api_key:
        return _unknown(
            "MailRook",
            "MAILROOK_API_KEY is not configured"
        )

    try:
        encoded_email = quote(email_address, safe="")

        response = requests.get(
            f"https://api.mailrook.com/v1/validate/{encoded_email}",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json"
            },
            timeout=TIMEOUT
        )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "json" in content_type:
            raw = response.json()
        else:
            raw = {
                "response_text": response.text
            }

        if not response.ok:
            return _unknown(
                "MailRook",
                f"MailRook API returned HTTP {response.status_code}",
                raw
            )

        # Try common risk fields
        risk = raw.get("risk")

        try:
            risk = float(risk)
        except (TypeError, ValueError):
            risk = 0

        reasons = []

        # Handle common boolean indicators
        if raw.get("disposable") is True:
            reasons.append(
                "MailRook identified the email as disposable"
            )

        if raw.get("is_disposable") is True:
            reasons.append(
                "MailRook identified the email as disposable"
            )

        if raw.get("valid") is False:
            reasons.append(
                "MailRook reported the email address as invalid"
            )

        if raw.get("is_valid") is False:
            reasons.append(
                "MailRook reported the email address as invalid"
            )

        if raw.get("message"):
            reasons.append(str(raw["message"]))

        if not reasons:
            reasons.append(
                "MailRook completed the email reputation check"
            )

        if risk >= 70:
            verdict = "suspicious"
        elif risk >= 30:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "api": "MailRook",
            "verdict": verdict,
            "score": round(risk),
            "reasons": reasons,
            "raw_result": raw
        }

    except requests.Timeout:
        return _unknown(
            "MailRook",
            "MailRook API timed out"
        )

    except requests.RequestException as e:
        return _unknown(
            "MailRook",
            f"MailRook API error: {str(e)}"
        )

    except ValueError as e:
        return _unknown(
            "MailRook",
            f"Invalid MailRook response: {str(e)}"
        )


# ============================================================
# CHECK-MAIL
# ============================================================

def check_checkmail(email_address):
    """
    Check an email address using Check-Mail API.
    """

    api_key = os.getenv("CHECKMAIL_API_KEY")

    if not api_key:
        return _unknown(
            "Check-Mail",
            "CHECKMAIL_API_KEY is not configured"
        )

    try:
        response = requests.post(
            "https://api.check-mail.org/v2/",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json"
            },
            data={
                "email": email_address
            },
            timeout=TIMEOUT
        )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "json" in content_type:
            raw = response.json()
        else:
            raw = {
                "response_text": response.text
            }

        if not response.ok:
            return _unknown(
                "Check-Mail",
                f"Check-Mail API returned HTTP {response.status_code}",
                raw
            )

        try:
            risk = float(raw.get("risk", 0))
        except (TypeError, ValueError):
            risk = 0

        reasons = []

        if raw.get("is_disposable") is True:
            reasons.append(
                "Check-Mail identified a disposable email address"
            )

        if raw.get("is_email_forwarder") is True:
            reasons.append(
                "Check-Mail identified an email forwarding service"
            )

        if raw.get("block") is True:
            reasons.append(
                "Check-Mail recommends blocking this email address"
            )

        if raw.get("valid") is False:
            reasons.append(
                "Check-Mail reported the email address as invalid"
            )

        if raw.get("reason"):
            reasons.append(
                f"Check-Mail reason: {raw['reason']}"
            )

        if not reasons:
            reasons.append(
                "Check-Mail completed the email validation"
            )

        if risk >= 70:
            verdict = "suspicious"
        elif risk >= 30:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "api": "Check-Mail",
            "verdict": verdict,
            "score": round(risk),
            "reasons": reasons,
            "raw_result": raw
        }

    except requests.Timeout:
        return _unknown(
            "Check-Mail",
            "Check-Mail API timed out"
        )

    except requests.RequestException as e:
        return _unknown(
            "Check-Mail",
            f"Check-Mail API error: {str(e)}"
        )

    except ValueError as e:
        return _unknown(
            "Check-Mail",
            f"Invalid Check-Mail response: {str(e)}"
        )


# ============================================================
# PHISHSTATS
# ============================================================

def check_phishstats(url):
    """
    Check a URL against the PhishStats phishing database.
    """

    api_key = os.getenv("PHISHSTATS_API_KEY")

    if not api_key:
        return _unknown(
            "PhishStats",
            "PHISHSTATS_API_KEY is not configured"
        )

    try:
        headers = {
            "X-API-Key": api_key,
            "Accept": "application/json"
        }

        # PhishStats supports filtering using _where.
        params = {
            "_where": f"(url,eq,{url})",
            "_size": 10
        }

        response = requests.get(
            "https://api.phishstats.info/api/phishing",
            headers=headers,
            params=params,
            timeout=TIMEOUT
        )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "json" in content_type:
            raw = response.json()
        else:
            raw = {
                "response_text": response.text
            }

        if not response.ok:
            return _unknown(
                "PhishStats",
                f"PhishStats API returned HTTP {response.status_code}",
                raw
            )

        # PhishStats normally returns a list of records.
        if isinstance(raw, list):
            records = raw
        elif isinstance(raw, dict):
            records = raw.get("data", [])

            if not isinstance(records, list):
                records = []
        else:
            records = []

        if records:
            highest_score = 0

            for record in records:
                try:
                    record_score = float(
                        record.get("score", 0)
                    )
                    highest_score = max(
                        highest_score,
                        record_score
                    )
                except (TypeError, ValueError):
                    pass

            # PhishStats scores are phishing confidence
            # scores. A matching record itself is already
            # strong evidence.
            normalized_score = min(
                round(highest_score * 10),
                100
            )

            if normalized_score < 70:
                normalized_score = 85

            return {
                "api": "PhishStats",
                "verdict": "phishing",
                "score": normalized_score,
                "reasons": [
                    "URL found in the PhishStats phishing database"
                ],
                "raw_result": raw
            }

        return {
            "api": "PhishStats",
            "verdict": "safe",
            "score": 0,
            "reasons": [
                "URL was not found in the PhishStats phishing database"
            ],
            "raw_result": raw
        }

    except requests.Timeout:
        return _unknown(
            "PhishStats",
            "PhishStats API timed out"
        )

    except requests.RequestException as e:
        return _unknown(
            "PhishStats",
            f"PhishStats API error: {str(e)}"
        )

    except ValueError as e:
        return _unknown(
            "PhishStats",
            f"Invalid PhishStats response: {str(e)}"
        )


# ============================================================
# VIRUSTOTAL
# ============================================================

def check_virustotal_url(url):
    """
    Submit a URL to VirusTotal and retrieve its report.
    """

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return _unknown(
            "VirusTotal",
            "VIRUSTOTAL_API_KEY is not configured"
        )

    try:
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }

        # Submit URL for analysis
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={
                "url": url
            },
            timeout=TIMEOUT
        )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "json" in content_type:
            raw = response.json()
        else:
            raw = {
                "response_text": response.text
            }

        if not response.ok:
            return _unknown(
                "VirusTotal",
                f"VirusTotal API returned HTTP {response.status_code}",
                raw
            )

        analysis_id = (
            raw.get("data", {})
               .get("id")
        )

        if not analysis_id:
            return _unknown(
                "VirusTotal",
                "VirusTotal did not return an analysis ID",
                raw
            )

        # Retrieve analysis result
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=TIMEOUT
        )

        analysis_content_type = analysis_response.headers.get(
            "Content-Type", ""
        ).lower()

        if "json" in analysis_content_type:
            analysis_raw = analysis_response.json()
        else:
            analysis_raw = {
                "response_text": analysis_response.text
            }

        if not analysis_response.ok:
            return _unknown(
                "VirusTotal",
                f"VirusTotal analysis returned HTTP {analysis_response.status_code}",
                analysis_raw
            )

        attributes = (
            analysis_raw.get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "stats",
            {}
        )

        malicious = int(
            stats.get("malicious", 0) or 0
        )

        suspicious = int(
            stats.get("suspicious", 0) or 0
        )

        harmless = int(
            stats.get("harmless", 0) or 0
        )

        undetected = int(
            stats.get("undetected", 0) or 0
        )

        total_engines = (
            malicious
            + suspicious
            + harmless
            + undetected
        )

        if total_engines > 0:
            score = round(
                (
                    (malicious * 100)
                    + (suspicious * 50)
                )
                / total_engines
            )
        else:
            score = 0

        reasons = [
            f"VirusTotal malicious detections: {malicious}",
            f"VirusTotal suspicious detections: {suspicious}"
        ]

        if malicious > 0:
            verdict = "phishing"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "api": "VirusTotal",
            "verdict": verdict,
            "score": min(score, 100),
            "reasons": reasons,
            "raw_result": analysis_raw
        }

    except requests.Timeout:
        return _unknown(
            "VirusTotal",
            "VirusTotal API timed out"
        )

    except requests.RequestException as e:
        return _unknown(
            "VirusTotal",
            f"VirusTotal API error: {str(e)}"
        )

    except ValueError as e:
        return _unknown(
            "VirusTotal",
            f"Invalid VirusTotal response: {str(e)}"
        )


# ============================================================
# MAIN EMAIL API ANALYZER
# ============================================================

def analyze_email_with_apis(email):
    """
    Run the available security APIs against an email.

    The email body itself is not blindly sent to every API.
    Email addresses are checked with email-reputation APIs,
    while URLs are checked with phishing/threat-intelligence APIs.
    """

    results = []

    # --------------------------------------------------------
    # Extract email addresses
    # --------------------------------------------------------

    email_addresses = extract_email_addresses(email)

    # --------------------------------------------------------
    # Extract URLs
    # --------------------------------------------------------

    urls = extract_urls(email)

    # --------------------------------------------------------
    # Check email addresses
    # --------------------------------------------------------

    for address in email_addresses:

        results.append(
            check_mailrook(address)
        )

        results.append(
            check_checkmail(address)
        )

    # --------------------------------------------------------
    # Check URLs
    # --------------------------------------------------------

    for url in urls:

        results.append(
            check_phishstats(url)
        )

        results.append(
            check_virustotal_url(url)
        )

    # --------------------------------------------------------
    # If no API checks were possible
    # --------------------------------------------------------

    if not results:
        return {
            "status": "no_api_checks",
            "results": [],
            "score": 0,
            "verdict": "unknown",
            "reasons": [
                "No email addresses or URLs were found in the input"
            ]
        }

    # --------------------------------------------------------
    # Aggregate results
    # --------------------------------------------------------

    valid_results = [
        result
        for result in results
        if result.get("verdict") != "unknown"
    ]

    if valid_results:
        average_score = round(
            sum(
                result.get("score", 0)
                for result in valid_results
            )
            / len(valid_results)
        )
    else:
        average_score = 0

    # Strong phishing signals get priority.
    if any(
        result.get("verdict") == "phishing"
        for result in valid_results
    ):
        final_verdict = "phishing"

    elif any(
        result.get("verdict") == "suspicious"
        for result in valid_results
    ):
        final_verdict = "suspicious"

    elif valid_results:
        final_verdict = "safe"

    else:
        final_verdict = "unknown"

    reasons = []

    for result in results:
        api_name = result.get("api", "API")

        for reason in result.get("reasons", []):
            reasons.append(
                f"{api_name}: {reason}"
            )

    return {
        "status": "completed",
        "results": results,
        "score": min(average_score, 100),
        "verdict": final_verdict,
        "reasons": reasons,
        "email_addresses_found": email_addresses,
        "urls_found": urls
    }