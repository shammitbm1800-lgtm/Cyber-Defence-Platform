from functools import lru_cache
from pathlib import Path
import joblib

MODEL_DIR = Path(__file__).resolve().parent / "models"

_MODEL_FILES = {
    "url": "url_model.joblib",
    "email": "email_model.joblib",
    "sms": "sms_model.joblib",
    "ransomware": "ransomware_model.joblib",
    "malicious_file": "malicious_file_model.joblib",
    "pdf": "pdf_model.joblib",
    "elf": "elf_model.joblib",
}

@lru_cache(maxsize=None)
def get_model(name: str):
    if name not in _MODEL_FILES:
        raise KeyError(f"Unknown ML model: {name}")
    path = MODEL_DIR / _MODEL_FILES[name]
    if not path.exists():
        raise FileNotFoundError(f"ML model not found: {path}")
    return joblib.load(path)

def model_status() -> dict:
    status = {}
    for name, filename in _MODEL_FILES.items():
        path = MODEL_DIR / filename
        status[name] = {"available": path.exists(), "file": filename}
    return status
