"""Static EMBER2024-compatible feature extraction for PDF/ELF/non-PE files.

This intentionally uses the feature families present in the supplied EMBER2024
JSONL datasets: general file information, byte histogram, byte/entropy
histogram, and string statistics/IOC counts. No uploaded file is executed.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

import numpy as np

# The supplied EMBER2024 records contain this string-feature vocabulary.  The
# project trains with the complete vocabulary observed in the supplied train
# sets, keeping the order stable for live inference.
STRING_REGEXES = {
    "url": re.compile(r"\b(?:http|https|ftp):\/\/[a-zA-Z0-9-._~:?#[\]@!$&'()*+,;=]+"),
    "ipv4_addr": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "ipv6_addr": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\b"),
    "mac_addr": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b"),
    # Kept identical to the EMBER2024 feature definition supplied in the data.
    "email_addr": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b"),
    "btc_wallet": re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"),
    "file_path": re.compile(r"\bC:/"),
    "dos_msg": re.compile(r"!This program "),
    "registry_key": re.compile(r"\b(?:KHEY_|KHLM|HKCU)"),
    "/dev/": re.compile(r"/dev/"),
    "/proc/": re.compile(r"/proc/"),
    "/bin/": re.compile(r"/bin/"),
    "/usr/": re.compile(r"/usr/"),
    "/tmp/": re.compile(r"/tmp/"),
    "/URI": re.compile(r"/URI"),
    "/FlateDecode": re.compile(r"/FlateDecode"),
    "/EmbeddedFile": re.compile(r"/EmbeddedFile"),
    "html": re.compile(r"html", re.IGNORECASE),
    "javascript": re.compile(r"javascript", re.IGNORECASE),
    "<script": re.compile(r"<script", re.IGNORECASE),
    ".click(": re.compile(r".click", re.IGNORECASE),
    "onlick": re.compile(r"onclick", re.IGNORECASE),
    "powershell": re.compile(r"powershell", re.IGNORECASE),
    "Invoke-Expression": re.compile(r"Invoke-Expression"),
    "Invoke-Command": re.compile(r"Invoke-Command"),
    "Start-process": re.compile(r"Start-process"),
    "get": re.compile(r"GET /", re.IGNORECASE),
    "post": re.compile(r"POST /", re.IGNORECASE),
    "http": re.compile(r"HTTP/", re.IGNORECASE),
    "http://": re.compile(r"http://", re.IGNORECASE),
    "https://": re.compile(r"https://", re.IGNORECASE),
    "ftp": re.compile(r"ftp:", re.IGNORECASE),
    "useragent": re.compile(r"User-Agent", re.IGNORECASE),
    "cookie": re.compile(r"cookie", re.IGNORECASE),
    "internet": re.compile(r"internet", re.IGNORECASE),
    "download": re.compile(r"download", re.IGNORECASE),
    "connect": re.compile(r"connect", re.IGNORECASE),
    "base64": re.compile(r"base64", re.IGNORECASE),
    "base64string": re.compile(r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    "crypt": re.compile(r"crypt"),
    "encode": re.compile(r"encode", re.IGNORECASE),
    "decode": re.compile(r"decode", re.IGNORECASE),
    "cache": re.compile(r"cache", re.IGNORECASE),
    "certificate": re.compile(r"certificate", re.IGNORECASE),
    "clipboard": re.compile(r"clipboard", re.IGNORECASE),
    "command": re.compile(r"command", re.IGNORECASE),
    "create": re.compile(r"create", re.IGNORECASE),
    "debug": re.compile(r"debug", re.IGNORECASE),
    "delete": re.compile(r"delete", re.IGNORECASE),
    "desktop": re.compile(r"desktop", re.IGNORECASE),
    "directory": re.compile(r"directory", re.IGNORECASE),
    "disk": re.compile(r"disk", re.IGNORECASE),
    "environment": re.compile(r"environment", re.IGNORECASE),
    "enum": re.compile(r"enum", re.IGNORECASE),
    "exit": re.compile(r"exit", re.IGNORECASE),
    "file": re.compile(r"file", re.IGNORECASE),
    "hostname": re.compile(r"hostname", re.IGNORECASE),
    "install": re.compile(r"install", re.IGNORECASE),
    "hidden": re.compile(r"hidden", re.IGNORECASE),
    "keyboard": re.compile(r"keyboard", re.IGNORECASE),
    "memory": re.compile(r"memory", re.IGNORECASE),
    "module": re.compile(r"module", re.IGNORECASE),
    "mutex": re.compile(r"mutex", re.IGNORECASE),
    "password": re.compile(r"password", re.IGNORECASE),
    "privilege": re.compile(r"privilege", re.IGNORECASE),
    "process": re.compile(r"process", re.IGNORECASE),
    "remote": re.compile(r"remote", re.IGNORECASE),
    "resource": re.compile(r"resource", re.IGNORECASE),
    "security": re.compile(r"security", re.IGNORECASE),
    "service": re.compile(r"service", re.IGNORECASE),
    "shell": re.compile(r"shell", re.IGNORECASE),
    "snapshot": re.compile(r"snapshot", re.IGNORECASE),
    "system": re.compile(r"system", re.IGNORECASE),
    "thread": re.compile(r"thread", re.IGNORECASE),
    "token": re.compile(r"token", re.IGNORECASE),
    "wallet": re.compile(r"wallet", re.IGNORECASE),
    "window": re.compile(r"window", re.IGNORECASE),
}
STRING_FEATURE_NAMES = sorted(STRING_REGEXES)
FEATURE_NAMES = (
    ["size", "entropy", "is_pe", "start_byte_0", "start_byte_1", "start_byte_2", "start_byte_3"]
    + [f"histogram_{i}" for i in range(256)]
    + [f"byteentropy_{i}" for i in range(256)]
    + ["numstrings", "avlength", "printables"]
    + [f"printabledist_{i}" for i in range(96)]
    + ["string_entropy"]
    + [f"string_count_{name}" for name in STRING_FEATURE_NAMES]
)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def _byte_entropy_histogram(data: bytes, step: int = 1024, window: int = 2048) -> np.ndarray:
    output = np.zeros((16, 16), dtype=np.float32)
    a = np.frombuffer(data, dtype=np.uint8)
    if a.size == 0:
        return output.flatten()

    def block_counts(block: np.ndarray):
        c = np.bincount(block >> 4, minlength=16).astype(np.float32)
        p = c / float(window)
        wh = np.where(c > 0)[0]
        h = float(np.sum(-p[wh] * np.log2(p[wh])) * 2.0)
        hbin = int(h * 2.0)
        if hbin >= 16:
            hbin = 15
        return hbin, c

    if a.size < window:
        hbin, c = block_counts(a)
        output[hbin, :] += c
    else:
        # Avoid materialising all overlapping windows.
        for start in range(0, a.size - window + 1, step):
            hbin, c = block_counts(a[start:start + window])
            output[hbin, :] += c
    total = float(output.sum())
    if total > 0:
        output /= total
    return output.flatten()


def _string_features(data: bytes) -> tuple[np.ndarray, dict]:
    allstrings = re.findall(rb"[\x20-\x7f]{5,}", data)
    if allstrings:
        lengths = [len(s) for s in allstrings]
        avlength = float(sum(lengths) / len(lengths))
        joined = b"".join(allstrings)
        shifted = np.frombuffer(joined, dtype=np.uint8).astype(np.int16) - 0x20
        shifted = shifted[(shifted >= 0) & (shifted < 96)]
        printable = np.bincount(shifted, minlength=96).astype(np.float32)
        printables = int(printable.sum())
        if printables:
            p = printable[printable > 0] / printables
            string_entropy = float(-np.sum(p * np.log2(p)))
        else:
            string_entropy = 0.0
    else:
        avlength = 0.0
        printable = np.zeros(96, dtype=np.float32)
        printables = 0
        string_entropy = 0.0

    divisor = float(printables) if printables else 1.0
    normalized_printable = printable / divisor
    decoded = [s.decode("ascii", errors="ignore") for s in allstrings]
    counts = {}
    for name, regex in STRING_REGEXES.items():
        count = 0
        for text in decoded:
            if regex.search(text):
                count += 1
        counts[name] = count

    vec = np.concatenate([
        np.asarray([len(allstrings), avlength, printables], dtype=np.float32),
        normalized_printable.astype(np.float32),
        np.asarray([string_entropy], dtype=np.float32),
        np.asarray([counts[name] for name in STRING_FEATURE_NAMES], dtype=np.float32),
    ])
    return vec, {
        "numstrings": len(allstrings),
        "avlength": avlength,
        "printables": printables,
        "entropy": string_entropy,
        "string_counts": counts,
    }


def extract_nonpe_features_from_bytes(data: bytes) -> tuple[np.ndarray, dict]:
    if not data:
        raise ValueError("File is empty.")
    arr = np.frombuffer(data, dtype=np.uint8)
    hist = np.bincount(arr, minlength=256).astype(np.float32)
    hist /= float(hist.sum())
    byteentropy = _byte_entropy_histogram(data)
    strings, string_info = _string_features(data)
    general = np.asarray([
        len(data),
        _entropy(data),
        0.0,
        *[int(b) for b in data[:4]] + [0] * max(0, 4 - len(data)),
    ], dtype=np.float32)
    vector = np.concatenate([general, hist, byteentropy, strings]).astype(np.float32)
    if len(vector) != len(FEATURE_NAMES):
        raise RuntimeError(f"Feature dimension mismatch: {len(vector)} != {len(FEATURE_NAMES)}")
    return vector, {"general": general.tolist(), "strings": string_info}


def extract_nonpe_features(file_path: str) -> tuple[np.ndarray, dict]:
    path = Path(file_path)
    data = path.read_bytes()
    return extract_nonpe_features_from_bytes(data)
