import math
import numpy as np
import pandas as pd

from .model_registry import get_model
from .url_features import URL_FEATURES, extract_url_features
from .ransomware_features import extract_header_bytes
from .pe_features import PE_FEATURES, parse_pe_features

def _risk_label(prob_malicious: float, positive_name: str, threshold: float = 0.5):
    if prob_malicious >= 0.85:
        verdict = "malicious"
    elif prob_malicious >= threshold:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return verdict, positive_name

def predict_url(url: str) -> dict:
    model = get_model("url")
    features = extract_url_features(url)
    X = pd.DataFrame([[features[name] for name in URL_FEATURES]], columns=URL_FEATURES)
    proba = model.predict_proba(X)[0]
    # Dataset label 0 = phishing, 1 = legitimate.
    phishing_probability = float(proba[0])
    legitimate_probability = float(proba[1])
    verdict = "phishing" if phishing_probability >= 0.85 else (
        "suspicious" if phishing_probability >= 0.5 else "safe"
    )
    return {
        "model": "RandomForest URL Classifier",
        "label": verdict,
        "score": round(phishing_probability * 100, 2),
        "probability": round(phishing_probability, 6),
        "probabilities": {
            "phishing": round(phishing_probability, 6),
            "legitimate": round(legitimate_probability, 6),
        },
        "features": features,
    }

def _predict_text(name: str, text: str, positive_name: str, model_label: str) -> dict:
    model = get_model(name)
    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    positive_probability = float(probabilities[classes.index(1)])
    negative_probability = float(probabilities[classes.index(0)])
    label = positive_name if positive_probability >= 0.85 else (
        "suspicious" if positive_probability >= 0.5 else "safe"
    )
    negative_name = "legitimate" if positive_name == "phishing" else "ham"
    return {
        "model": model_label,
        "label": label,
        "score": round(positive_probability * 100, 2),
        "probability": round(positive_probability, 6),
        "probabilities": {
            positive_name: round(positive_probability, 6),
            negative_name: round(negative_probability, 6),
        },
    }

def predict_email(text: str) -> dict:
    return _predict_text("email", text, "phishing", "TF-IDF + Logistic Regression Email Classifier")

def predict_sms(text: str) -> dict:
    return _predict_text("sms", text, "spam", "TF-IDF + Logistic Regression SMS Classifier")

def predict_ransomware_file(file_path: str) -> dict:
    model = get_model("ransomware")
    features = extract_header_bytes(file_path, 1024)
    X = pd.DataFrame([features], columns=[str(i) for i in range(1024)])
    proba = model.predict_proba(X)[0]
    ransomware_probability = float(proba[list(model.classes_).index(1)])
    goodware_probability = float(proba[list(model.classes_).index(0)])
    label = "ransomware" if ransomware_probability >= 0.85 else (
        "suspicious" if ransomware_probability >= 0.5 else "safe"
    )
    return {
        "model": "RandomForest 1024-byte PE Header Ransomware Classifier",
        "label": label,
        "score": round(ransomware_probability * 100, 2),
        "probability": round(ransomware_probability, 6),
        "probabilities": {
            "ransomware": round(ransomware_probability, 6),
            "goodware": round(goodware_probability, 6),
        },
    }

def predict_malicious_file(file_path: str) -> tuple[dict, dict]:
    model = get_model("malicious_file")
    features, info = parse_pe_features(file_path)
    X = pd.DataFrame([[features[name] for name in PE_FEATURES]], columns=PE_FEATURES)
    proba = model.predict_proba(X)[0]
    malicious_probability = float(proba[list(model.classes_).index(1)])
    benign_probability = float(proba[list(model.classes_).index(0)])
    label = "malicious" if malicious_probability >= 0.85 else (
        "suspicious" if malicious_probability >= 0.5 else "benign"
    )
    return {
        "model": "RandomForest Static PE Malware Classifier",
        "label": label,
        "score": round(malicious_probability * 100, 2),
        "probability": round(malicious_probability, 6),
        "probabilities": {
            "malicious": round(malicious_probability, 6),
            "benign": round(benign_probability, 6),
        },
    }, info


def predict_nonpe_file(file_path: str, file_kind: str) -> dict:
    """Predict PDF/ELF using the locally trained EMBER2024-compatible model."""
    from .nonpe_features import extract_nonpe_features

    kind = str(file_kind).lower()
    if kind not in ("pdf", "elf"):
        raise ValueError(f"Unsupported non-PE ML type: {file_kind}")

    model = get_model(kind)
    vector, _ = extract_nonpe_features(file_path)
    proba = model.predict_proba([vector])[0]
    classes = list(model.classes_)
    malicious_probability = float(proba[classes.index(1)])
    benign_probability = float(proba[classes.index(0)])
    label = "malicious" if malicious_probability >= 0.85 else (
        "suspicious" if malicious_probability >= 0.50 else "benign"
    )
    return {
        "model": f"RandomForest {kind.upper()} Malware Classifier",
        "label": label,
        "score": round(malicious_probability * 100, 2),
        "probability": round(malicious_probability, 6),
        "probabilities": {
            "malicious": round(malicious_probability, 6),
            "benign": round(benign_probability, 6),
        },
        "file_kind": kind.upper(),
        "feature_count": int(getattr(model, "n_features_in_", 0)),
    }
