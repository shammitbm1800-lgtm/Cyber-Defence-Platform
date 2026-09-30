import os

def extract_header_bytes(file_path: str, size: int = 1024) -> list[float]:
    """Return the first 1024 bytes as numeric features, padded with zeros."""
    with open(file_path, "rb") as handle:
        data = handle.read(size)
    if not data:
        raise ValueError("File is empty.")
    if data[:2] != b"MZ":
        raise ValueError("The ransomware ML model is trained on Windows PE files; MZ header not found.")
    data = data.ljust(size, b"\x00")
    return [float(value) for value in data]
