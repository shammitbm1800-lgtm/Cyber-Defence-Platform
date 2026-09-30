import os
import requests
from dotenv import load_dotenv

load_dotenv()

TIMEOUT = 10


def check_oopspam(message):
    try:
        response = requests.post(
            "https://api.oopspam.com/v1/spamdetection",
            headers={
                "X-Api-Key": os.getenv("OOPSPAM_API_KEY"),
                "Content-Type": "application/json"
            },
            json={
                "content": message,
                "checkForLength": True,
                "blockTempEmail": False
            },
            timeout=TIMEOUT
        )

        raw = response.json()

        if not response.ok:
            return {
                "api": "OOPSpam",
                "verdict": "unknown",
                "score": 0,
                "reasons": [raw.get("message", "API request failed")],
                "raw_result": raw
            }

        score = raw.get("Score", 0)
        details = raw.get("Details", {})
        spam_status = str(details.get("isContentSpam", "")).lower()

        if spam_status == "spam":
            verdict = "spam"
        elif score >= 3:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "api": "OOPSpam",
            "verdict": verdict,
            "score": round(min(float(score) / 6 * 100, 100)),
            "reasons": [f"OOPSpam score: {score}/6"],
            "raw_result": raw
        }

    except requests.RequestException as e:
        return {
            "api": "OOPSpam",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }


def check_siftfy(message):
    try:
        response = requests.post(
            "https://api.siftfy.io/v1/predict",
            headers={
                "X-API-Key": os.getenv("SIFTFY_API_KEY"),
                "Content-Type": "application/json"
            },
            json={"text": message},
            timeout=TIMEOUT
        )

        raw = response.json()

        if not response.ok:
            return {
                "api": "Siftfy",
                "verdict": "unknown",
                "score": 0,
                "reasons": [raw.get("message", "API request failed")],
                "raw_result": raw
            }

        probability = float(raw.get("spam_probability", 0))

        if probability >= 0.85:
            verdict = "spam"
        elif probability >= 0.50:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "api": "Siftfy",
            "verdict": verdict,
            "score": round(probability * 100),
            "reasons": [f"Spam probability: {probability:.2f}"],
            "raw_result": raw
        }

    except (requests.RequestException, ValueError) as e:
        return {
            "api": "Siftfy",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }


def check_nyckel(message):
    try:
        # We will add your Nyckel function ID here after confirming
        # the exact spam classifier you are using.
        return {
            "api": "Nyckel",
            "verdict": "unknown",
            "score": 0,
            "reasons": ["Nyckel function ID not configured yet"],
            "raw_result": {}
        }

    except Exception as e:
        return {
            "api": "Nyckel",
            "verdict": "unknown",
            "score": 0,
            "reasons": [str(e)],
            "raw_result": {}
        }


def check_ipqualityscore(message):
    # IPQS currently has no usable credits on your account.
    return {
        "api": "IPQualityScore",
        "verdict": "unknown",
        "score": 0,
        "reasons": ["IPQS currently has no usable credits"],
        "raw_result": {}
    }