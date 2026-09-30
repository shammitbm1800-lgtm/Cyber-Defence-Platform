import os
import requests
from dotenv import load_dotenv

load_dotenv()

TIMEOUT = 10


def check_virustotal(file_hash):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={
                "x-apikey": api_key
            },
            timeout=TIMEOUT
        )

        raw = response.json()

        if response.status_code == 404:
            return {
                "api": "VirusTotal",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["Hash not found"],
                "raw_result": raw
            }

        if not response.ok:
            return {
                "api": "VirusTotal",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["API request failed"],
                "raw_result": raw
            }

        stats = raw["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "safe"

        score = round(((malicious + suspicious) / total) * 100) if total else 0

        return {
            "api": "VirusTotal",
            "verdict": verdict,
            "score": score,
            "reasons": [
                f"Malicious engines: {malicious}",
                f"Suspicious engines: {suspicious}",
                f"Total engines: {total}"
            ],
            "raw_result": raw
        }

    except requests.RequestException as e:
        return {
            "api": "VirusTotal",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }


def check_malwarebazaar(file_hash):
    api_key = os.getenv("ABUSECH_AUTH_KEY")

    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={
                "Auth-Key": api_key
            },
            data={
                "query": "get_info",
                "hash": file_hash
            },
            timeout=TIMEOUT
        )

        raw = response.json()
        status = raw.get("query_status")

        if status == "hash_not_found":
            return {
                "api": "MalwareBazaar",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["Hash not found"],
                "raw_result": raw
            }

        if status != "ok":
            return {
                "api": "MalwareBazaar",
                "verdict": "unknown",
                "score": 0,
                "reasons": [f"Query status: {status}"],
                "raw_result": raw
            }

        return {
            "api": "MalwareBazaar",
            "verdict": "malicious",
            "score": 100,
            "reasons": ["Hash found in MalwareBazaar"],
            "raw_result": raw
        }

    except requests.RequestException as e:
        return {
            "api": "MalwareBazaar",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }


def check_hybrid_analysis(file_hash):
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY")

    try:
        response = requests.get(
            "https://hybrid-analysis.com/api/v2/search/hash",
            headers={
                "api-key": api_key,
                "User-Agent": "Falcon Sandbox"
            },
            params={
                "hash": file_hash
            },
            timeout=TIMEOUT
        )

        raw = response.json()

        if response.status_code == 404 or not raw:
            return {
                "api": "Hybrid Analysis",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["Hash not found"],
                "raw_result": raw
            }

        if not response.ok:
            return {
                "api": "Hybrid Analysis",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["API request failed"],
                "raw_result": raw
            }

        results = raw if isinstance(raw, list) else [raw]

        verdict = "safe"
        score = 0
        reasons = []

        for item in results:
            verdict_value = str(
                item.get("verdict", item.get("status", ""))
            ).lower()

            if "malicious" in verdict_value:
                verdict = "malicious"
                score = 100
                reasons.append("Malicious verdict found")
                break

            if "suspicious" in verdict_value:
                verdict = "suspicious"
                score = max(score, 60)
                reasons.append("Suspicious verdict found")

        return {
            "api": "Hybrid Analysis",
            "verdict": verdict,
            "score": score,
            "reasons": reasons or ["Hash found with no malicious verdict"],
            "raw_result": raw
        }

    except requests.RequestException as e:
        return {
            "api": "Hybrid Analysis",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }


def check_threatfox(file_hash):
    api_key = os.getenv("ABUSECH_AUTH_KEY")

    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={
                "Auth-Key": api_key
            },
            json={
                "query": "search_hash",
                "hash": file_hash
            },
            timeout=TIMEOUT
        )

        raw = response.json()
        status = raw.get("query_status")

        if status == "no_result":
            return {
                "api": "ThreatFox",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["Hash not found"],
                "raw_result": raw
            }

        if status != "ok":
            return {
                "api": "ThreatFox",
                "verdict": "unknown",
                "score": 0,
                "reasons": [f"Query status: {status}"],
                "raw_result": raw
            }

        data = raw.get("data", [])

        return {
            "api": "ThreatFox",
            "verdict": "malicious",
            "score": 100,
            "reasons": [
                f"ThreatFox matched {len(data)} IOC(s)"
            ],
            "raw_result": raw
        }

    except requests.RequestException as e:
        return {
            "api": "ThreatFox",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }


def check_sophos(file_hash):
    return {
        "api": "Sophos Intelix",
        "verdict": "unknown",
        "score": 0,
        "reasons": [],
        "raw_result": {}
    }


def check_xexle(file_hash):
    try:
        response = requests.get(
            "https://hashcheck.xexle.com/api/check",
            params={
                "hashes": file_hash,
                "include_missing": 1
            },
            timeout=TIMEOUT
        )

        raw = response.json()

        if not response.ok or raw.get("status") is not True:
            return {
                "api": "Xexle HashCheck",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["API request failed"],
                "raw_result": raw
            }

        result = raw.get("data", {}).get(file_hash.lower(), 0)

        if result in [1, 2]:
            verdict = "malicious"
            score = 100
            reason = "Hash found in Xexle HashCheck"
        elif result == 3:
            verdict = "suspicious"
            score = 60
            reason = "Hash found as user-submitted record"
        else:
            verdict = "unknown"
            score = 0
            reason = "Hash not found"

        return {
            "api": "Xexle HashCheck",
            "verdict": verdict,
            "score": score,
            "reasons": [reason],
            "raw_result": raw
        }

    except requests.RequestException as e:
        return {
            "api": "Xexle HashCheck",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }


def check_dfir(file_hash):
    api_key = os.getenv("DFIR_API_KEY")

    try:
        response = requests.post(
            "https://api.dfir-lab.ch/v1/enrichment/lookup",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "indicators": [file_hash]
            },
            timeout=TIMEOUT
        )

        raw = response.json()

        if not response.ok:
            return {
                "api": "DFIR Platform",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["API request failed"],
                "raw_result": raw
            }

        results = raw.get("data", {}).get("results", [])

        if not results:
            return {
                "api": "DFIR Platform",
                "verdict": "unknown",
                "score": 0,
                "reasons": ["Hash not found"],
                "raw_result": raw
            }

        result = results[0]

        return {
            "api": "DFIR Platform",
            "verdict": "malicious" if result.get("malicious") else "unknown",
            "score": 100 if result.get("malicious") else 0,
            "reasons": ["Malicious IOC match"] if result.get("malicious") else ["No malicious match"],
            "raw_result": raw
        }

    except requests.RequestException as e:
        return {
            "api": "DFIR Platform",
            "verdict": "unknown",
            "score": 0,
            "reasons": [f"API error: {str(e)}"],
            "raw_result": {}
        }