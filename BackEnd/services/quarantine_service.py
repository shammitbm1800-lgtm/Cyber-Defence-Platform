import os
import uuid
from pathlib import Path

def quarantine_file(source_path: str, quarantine_root: str, original_name: str) -> dict:
    root = Path(quarantine_root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    clean_name = Path(original_name or "uploaded_file").name
    clean_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in clean_name)[:120]
    destination = root / f"{uuid.uuid4().hex}_{clean_name}"

    source = Path(source_path).resolve()
    if root in source.parents:
        raise ValueError("Source file is already inside quarantine.")

    os.replace(str(source), str(destination))
    return {
        "quarantined": True,
        "path": str(destination),
        "display_name": clean_name,
    }
