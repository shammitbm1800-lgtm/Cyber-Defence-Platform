import os
import time
import requests

from dotenv import load_dotenv


load_dotenv()


# ============================================================
# URLScan API
# ============================================================

def check_urlscan(url):
    api_key = os.getenv("URLSCAN_API_KEY")

    if not api_key:
        return {
            "api": "URLScan",
            "verdict": "unknown",
            "score": 0,
            "reasons": ["URLScan API key is missing"],
            "raw_result": {}
        }

    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }

    try:
        # ----------------------------------------------------
        # Step 1: Submit URL to URLScan
        # ----------------------------------------------------
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={
                "url": url,
                "visibility": "private"
            },
            timeout=20
        )

        response.raise_for_status()

        submission = response.json()
        scan_uuid = submission.get("uuid")

        if not scan_uuid:
            return {
                "api": "URLScan",
                "verdict": "unknown",
                "score": 0,
                "reasons": [
                    "URLScan submission succeeded but no scan UUID was returned"
                ],
                "raw_result": submission
            }

        # ----------------------------------------------------
        # Step 2: Wait before checking result
        # ----------------------------------------------------
        time.sleep(10)

        result_url = (
            f"https://urlscan.io/api/v1/result/{scan_uuid}/"
        )

        result = None

        # Try up to 5 times
        for _ in range(5):

            result_response = requests.get(
                result_url,
                headers={
                    "API-Key": api_key
                },
                timeout=20
            )

            # Scan completed
            if result_response.status_code == 200:
                result = result_response.json()
                break

            # Scan is still processing
            if result_response.status_code == 404:
                time.sleep(5)
                continue

            result_response.raise_for_status()

        # ----------------------------------------------------
        # Scan not ready yet
        # ----------------------------------------------------
        if result is None:
            return {
                "api": "URLScan",
                "verdict": "unknown",
                "score": 0,
                "reasons": [
                    "URLScan scan submitted but result is not ready yet"
                ],
                "raw_result": submission
            }

        # ----------------------------------------------------
        # Step 3: Read URLScan verdict
        # ----------------------------------------------------
        verdicts = result.get("verdicts", {})

        urlscan_verdict = verdicts.get("urlscan", {})

        raw_score = urlscan_verdict.get("score", 0)

        try:
            raw_score = int(raw_score)
        except (ValueError, TypeError):
            raw_score = 0

        # URLScan score is approximately -100 to +100.
        # Convert it to our required 0-100 format.
        score = int((raw_score + 100) / 2)

        score = max(0, min(score, 100))

        malicious = bool(
            urlscan_verdict.get("malicious", False)
        )

        categories = urlscan_verdict.get(
            "categories",
            []
        )

        reasons = []

        if malicious:
            reasons.append(
                "URLScan classified the URL as malicious"
            )

        if categories:
            reasons.append(
                "Categories: "
                + ", ".join(map(str, categories))
            )

        if not reasons:

            if raw_score < 0:
                reasons.append(
                    "URLScan score indicates legitimate activity"
                )
            else:
                reasons.append(
                    "URLScan returned no malicious indicators"
                )

        # ----------------------------------------------------
        # Normalize verdict
        # ----------------------------------------------------
        if malicious:
            verdict = "malicious"

        elif raw_score > 0:
            verdict = "suspicious"

        else:
            verdict = "safe"

        return {
            "api": "URLScan",
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "raw_result": result
        }

    except requests.exceptions.RequestException as e:

        return {
            "api": "URLScan",
            "verdict": "unknown",
            "score": 0,
            "reasons": [
                f"URLScan API error: {str(e)}"
            ],
            "raw_result": {}
        }


# ============================================================
# URLhaus API
# ============================================================

def check_urlhaus(url):
    api_key = os.getenv("URLHAUS_AUTH_KEY")

    if not api_key:
        return {
            "api": "URLhaus",
            "verdict": "unknown",
            "score": 0,
            "reasons": ["URLhaus API key is missing"],
            "raw_result": {}
        }

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers={
                "Auth-Key": api_key
            },
            data={
                "url": url
            },
            timeout=20
        )

        response.raise_for_status()

        result = response.json()

        query_status = result.get(
            "query_status"
        )

        # URL found in URLhaus
        if query_status == "ok":

            return {
                "api": "URLhaus",
                "verdict": "malicious",
                "score": 100,
                "reasons": [
                    "URL found in URLhaus malware database"
                ],
                "raw_result": result
            }

        # URL not found
        if query_status == "no_results":

            return {
                "api": "URLhaus",
                "verdict": "unknown",
                "score": 0,
                "reasons": [
                    "URL not found in URLhaus database"
                ],
                "raw_result": result
            }

        return {
            "api": "URLhaus",
            "verdict": "unknown",
            "score": 0,
            "reasons": [
                "URLhaus returned an unexpected response"
            ],
            "raw_result": result
        }

    except requests.exceptions.RequestException as e:

        return {
            "api": "URLhaus",
            "verdict": "unknown",
            "score": 0,
            "reasons": [
                f"URLhaus API error: {str(e)}"
            ],
            "raw_result": {}
        }


# ============================================================
# PrivacyTestLab API
# ============================================================

def check_privacytestlab(url):
    api_key = os.getenv(
        "PRIVACYTESTLAB_API_KEY"
    )

    if not api_key:
        return {
            "api": "PrivacyTestLab",
            "verdict": "unknown",
            "score": 0,
            "reasons": [
                "PrivacyTestLab API key is missing"
            ],
            "raw_result": {}
        }

    try:
        response = requests.get(
            "https://privacytestlab.com/api/v1/phishing-check",
            headers={
                "X-Api-Key": api_key
            },
            params={
                "url": url
            },
            timeout=40
        )

        response.raise_for_status()

        result = response.json()

        data = result.get(
            "data",
            {}
        )

        signals = data.get(
            "signals",
            {}
        )

        reasons = []

        suspicious_count = 0
        malicious_count = 0

        # ----------------------------------------------------
        # Inspect returned signals
        # ----------------------------------------------------
        for signal_name, signal_data in signals.items():

            if not isinstance(signal_data, dict):
                continue

            status = str(
                signal_data.get(
                    "status",
                    ""
                )
            ).lower()

            if status in (
                "malicious",
                "phishing",
                "blocked",
                "dangerous"
            ):
                malicious_count += 1

                reasons.append(
                    f"{signal_name}: {status}"
                )

            elif status in (
                "suspicious",
                "warning",
                "unknown"
            ):
                suspicious_count += 1

                reasons.append(
                    f"{signal_name}: {status}"
                )

        # ----------------------------------------------------
        # Determine verdict
        # ----------------------------------------------------
        if malicious_count > 0:

            verdict = "malicious"
            score = 100

        elif suspicious_count > 0:

            verdict = "suspicious"
            score = 60

        else:

            verdict = "safe"
            score = 0

        if not reasons:

            if verdict == "safe":
                reasons.append(
                    "PrivacyTestLab did not report malicious indicators"
                )
            else:
                reasons.append(
                    "PrivacyTestLab returned no additional signals"
                )

        return {
            "api": "PrivacyTestLab",
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "raw_result": result
        }

    except requests.exceptions.RequestException as e:

        return {
            "api": "PrivacyTestLab",
            "verdict": "unknown",
            "score": 0,
            "reasons": [
                f"PrivacyTestLab API error: {str(e)}"
            ],
            "raw_result": {}
        }


# ============================================================
# PhishStats API
# ============================================================

def check_phishstats(url):
    api_key = os.getenv(
        "PHISHSTATS_API_KEY"
    )

    headers = {
        "Accept": "application/json"
    }

    # API key is optional for read-only access,
    # but using a registered key gives a higher quota.
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        response = requests.get(
            "https://api.phishstats.info/api/phishing",
            headers=headers,
            params={
                "_where": f"(url,eq,{url})",
                "_size": 10
            },
            timeout=20
        )

        response.raise_for_status()

        result = response.json()

        # PhishStats normally returns a list
        if isinstance(result, list):

            records = result

        elif isinstance(result, dict):

            records = result.get(
                "data",
                result.get(
                    "results",
                    []
                )
            )

        else:

            records = []

        # ----------------------------------------------------
        # URL found in phishing database
        # ----------------------------------------------------
        if records:

            first_record = records[0]

            raw_score = first_record.get(
                "score",
                0
            )

            try:
                raw_score = float(raw_score)
            except (ValueError, TypeError):
                raw_score = 0

            # PhishStats score is generally 0-10.
            score = int(
                (raw_score / 10) * 100
            )

            score = max(
                0,
                min(score, 100)
            )

            return {
                "api": "PhishStats",
                "verdict": "malicious",
                "score": score,
                "reasons": [
                    "URL found in PhishStats phishing database"
                ],
                "raw_result": result
            }

        # ----------------------------------------------------
        # URL not found
        # ----------------------------------------------------
        return {
            "api": "PhishStats",
            "verdict": "unknown",
            "score": 0,
            "reasons": [
                "URL not found in PhishStats phishing database"
            ],
            "raw_result": result
        }

    except requests.exceptions.RequestException as e:

        return {
            "api": "PhishStats",
            "verdict": "unknown",
            "score": 0,
            "reasons": [
                f"PhishStats API error: {str(e)}"
            ],
            "raw_result": {}
        }