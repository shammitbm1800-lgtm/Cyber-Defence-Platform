import hashlib
import os
import math
from collections import Counter
from pathlib import Path

from ml.predictors import predict_malicious_file, predict_nonpe_file
from services.nonpe_file_analysis import analyze_pdf, analyze_elf, detect_file_kind

MAX_FILE_SIZE = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".com",
    ".pdf", ".elf",
}


def calculate_sha256(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_filename(filename: str) -> str:
    name = Path(filename or "uploaded_file").name.replace("\x00", "")
    cleaned = "".join(ch if ch.isalnum() or ch in "._- " else "_" for ch in name)
    return cleaned[:180] or "uploaded_file"


def _build_assessment(verdict: str, malicious_probability: float, suspicious_points: list[str], model_name: str):
    probability_pct = malicious_probability * 100
    points: list[str] = []
    if verdict == "Dangerous":
        points.append(f"The local {model_name} assigned a {probability_pct:.2f}% malicious probability, placing the file in the malicious range.")
        points.extend(suspicious_points)
        if not suspicious_points:
            points.append("Static inspection did not add a high-signal indicator; the ML result is the primary evidence.")
        recommendation = "Do not open or execute this file. Keep it isolated and investigate it through a trusted security workflow."
        status_key = "dangerous"
    elif verdict == "Suspicious":
        points.append(f"The local {model_name} assigned a {probability_pct:.2f}% malicious probability, which falls in the review range.")
        points.extend(suspicious_points)
        if not suspicious_points:
            points.append("No additional high-signal static indicator was recorded, so this result should be reviewed rather than treated as confirmed malware.")
        recommendation = "Treat the file with caution. Do not execute it until it has been verified through a trusted security process."
        status_key = "suspicious"
    else:
        points.append(f"The local {model_name} assigned a {probability_pct:.2f}% malicious probability, below the suspicious threshold used by this analyzer.")
        if suspicious_points:
            points.append("Static inspection found contextual characteristics shown below; a low ML probability does not guarantee safety.")
            points.extend(suspicious_points)
            recommendation = "The ML result is in the safe range, but review the static observations before opening an unfamiliar file."
        else:
            points.append("No high-signal suspicious static characteristic was detected by the implemented checks.")
            recommendation = "The file appears safe based on the available static evidence and local ML model, but this is not a guarantee of safety."
        status_key = "safe"
    return points, recommendation, status_key


def _analyze_pe(file_path: str):
    ml_result, static_info = predict_malicious_file(file_path)
    suspicious_points: list[str] = []
    suspicious_imports = int(static_info.get("suspicious_imports", 0) or 0)
    suspicious_sections = list(static_info.get("suspicious_section_names", []) or [])
    max_entropy = max((float(section.get("entropy", 0) or 0) for section in static_info.get("sections", [])), default=0.0)
    if suspicious_imports:
        suspicious_points.append(f"Static PE analysis found {suspicious_imports} suspicious imported function(s).")
    if suspicious_sections:
        suspicious_points.append(f"Unusual/suspicious PE section name(s) were found: {', '.join(suspicious_sections[:8])}.")
    if max_entropy >= 7.2:
        suspicious_points.append(f"The highest PE section entropy was {max_entropy:.2f}; high entropy can be consistent with packed or compressed content, but is not proof of malware.")
    verdict = ml_result["label"]
    final_verdict = "Dangerous" if verdict == "malicious" else "Suspicious" if verdict == "suspicious" else "Safe"
    probability = float(ml_result["probabilities"]["malicious"])
    why, recommendation, status_key = _build_assessment(final_verdict, probability, suspicious_points, ml_result["model"])
    return final_verdict, status_key, ml_result, static_info, suspicious_points, why, recommendation, "PE32+" if static_info.get("pe32plus") else "PE32"


def _analyze_nonpe(file_path: str, kind: str):
    static_info = analyze_pdf(file_path) if kind == "pdf" else analyze_elf(file_path)
    ml_result = predict_nonpe_file(file_path, kind)
    suspicious_points = list(static_info.get("suspicious_points", []))
    verdict = ml_result["label"]
    final_verdict = "Dangerous" if verdict == "malicious" else "Suspicious" if verdict == "suspicious" else "Safe"
    probability = float(ml_result["probabilities"]["malicious"])
    why, recommendation, status_key = _build_assessment(final_verdict, probability, suspicious_points, ml_result["model"])
    return final_verdict, status_key, ml_result, static_info, suspicious_points, why, recommendation, ("PDF" if kind == "pdf" else static_info.get("class", "ELF"))


def _generic_analysis(file_path: str):
    data = Path(file_path).read_bytes()
    entropy = 0.0
    if data:
        counts = Counter(data)
        total = float(len(data))
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return {
        "entropy": round(entropy, 4),
        "note": "This file type is outside the currently trained PDF, ELF, and PE ML models. Only hash/basic static inspection was performed.",
        "suspicious_points": [],
    }


def analyze_uploaded_file(file_path: str, original_name: str) -> dict:
    size = os.path.getsize(file_path)
    if size == 0:
        raise ValueError("The uploaded file is empty.")
    if size > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 50 MB analysis limit.")

    sha256 = calculate_sha256(file_path)
    kind = detect_file_kind(file_path, original_name)

    if kind == "pe":
        final_verdict, status_key, ml_result, static_info, suspicious_points, why, recommendation, file_type = _analyze_pe(file_path)
        model_available = True
    elif kind in ("pdf", "elf"):
        final_verdict, status_key, ml_result, static_info, suspicious_points, why, recommendation, file_type = _analyze_nonpe(file_path, kind)
        model_available = True
    else:
        static_info = _generic_analysis(file_path)
        suspicious_points = static_info.get("suspicious_points", [])
        final_verdict = "Unknown"
        status_key = "unknown"
        ml_result = {
            "model": "No trained model for this file type",
            "label": "unavailable",
            "score": 0,
            "probabilities": {},
        }
        why = ["SHA-256 was calculated and the file was inspected without executing it.", static_info["note"]]
        recommendation = "Do not execute an unfamiliar file. For ML classification, use a supported PE, PDF, or ELF sample."
        file_type = Path(original_name or "").suffix.lower().lstrip(".").upper() or "Unknown"
        model_available = False

    score = int(round(float(ml_result.get("score", 0) or 0)))
    reasons = [
        f"ML model: {ml_result.get('model', 'Unavailable')}",
        f"ML classification: {ml_result.get('label', 'unavailable')}",
    ]
    if ml_result.get("probabilities"):
        reasons.append(f"Malicious probability: {float(ml_result['probabilities'].get('malicious', 0)):.2%}")
    reasons.extend(suspicious_points)

    return {
        "filename": original_name,
        "safe_filename": safe_filename(original_name),
        "size": size,
        "sha256": sha256,
        "file_type": file_type,
        "file_kind": kind,
        "verdict": final_verdict,
        "status_key": status_key,
        "score": score,
        "confidence": "model probability" if model_available else "static only",
        "reasons": reasons,
        "assessment": {
            "why": why,
            "recommendation": recommendation,
            "limitations": [
                "Static analysis does not execute the uploaded file.",
                "A Safe result is not a guarantee that a file is harmless.",
                "The ML probability is evidence from the trained model, not a definitive malware verdict.",
            ],
        },
        "ml": ml_result,
        "static_analysis": static_info,
    }
