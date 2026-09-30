from __future__ import annotations

import math
import re
import struct
from pathlib import Path
from collections import Counter


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect_file_kind(file_path: str, original_name: str = "") -> str:
    data = Path(file_path).read_bytes()[:4096]
    lower = str(original_name or "").lower()
    if data.startswith(b"%PDF-") or lower.endswith(".pdf"):
        return "pdf"
    if data.startswith(b"\x7fELF") or lower in {".elf"} or lower.endswith(".elf"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    return "unknown"


def analyze_pdf(file_path: str) -> dict:
    data = Path(file_path).read_bytes()
    text = data.decode("latin-1", errors="ignore")
    markers = {
        "JavaScript": len(re.findall(r"/JavaScript\b|/JS\b", text, re.I)),
        "OpenAction": len(re.findall(r"/OpenAction\b", text, re.I)),
        "AdditionalActions": len(re.findall(r"/AA\b", text, re.I)),
        "Launch": len(re.findall(r"/Launch\b", text, re.I)),
        "EmbeddedFile": len(re.findall(r"/EmbeddedFile\b", text, re.I)),
        "RichMedia": len(re.findall(r"/RichMedia\b", text, re.I)),
        "URI": len(re.findall(r"/URI\b", text, re.I)),
        "AcroForm": len(re.findall(r"/AcroForm\b", text, re.I)),
        "XFA": len(re.findall(r"/XFA\b", text, re.I)),
        "ObjStm": len(re.findall(r"/ObjStm\b", text, re.I)),
    }
    suspicious = []
    if markers["JavaScript"]:
        suspicious.append(f"PDF contains {markers['JavaScript']} JavaScript/JS marker(s).")
    if markers["OpenAction"] or markers["AdditionalActions"]:
        suspicious.append("PDF contains automatic-action entries that can trigger content when opened.")
    if markers["Launch"]:
        suspicious.append(f"PDF contains {markers['Launch']} Launch action marker(s).")
    if markers["EmbeddedFile"]:
        suspicious.append(f"PDF contains {markers['EmbeddedFile']} embedded-file marker(s).")
    if markers["RichMedia"]:
        suspicious.append(f"PDF contains {markers['RichMedia']} RichMedia marker(s).")
    if markers["URI"]:
        suspicious.append(f"PDF contains {markers['URI']} URI marker(s); this is not inherently malicious but is relevant context.")
    return {
        "format_valid": data.startswith(b"%PDF-"),
        "entropy": round(_entropy(data), 4),
        "object_count": len(re.findall(rb"(?m)^\s*\d+\s+\d+\s+obj\b", data)),
        "stream_count": data.count(b"stream"),
        "xref_count": data.count(b"xref"),
        "trailer_count": data.count(b"trailer"),
        "markers": markers,
        "suspicious_points": suspicious,
    }


def analyze_elf(file_path: str) -> dict:
    data = Path(file_path).read_bytes()
    if len(data) < 16 or not data.startswith(b"\x7fELF"):
        return {"format_valid": False, "suspicious_points": []}
    elf_class = 64 if data[4] == 2 else 32 if data[4] == 1 else 0
    endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
    prefix = "<" if endian == "little" else ">"
    e_type = struct.unpack_from(prefix + "H", data, 16)[0] if len(data) >= 18 else 0
    e_machine = struct.unpack_from(prefix + "H", data, 18)[0] if len(data) >= 20 else 0
    e_phoff = struct.unpack_from(prefix + ("Q" if elf_class == 64 else "I"), data, 32 if elf_class == 64 else 28)[0] if len(data) >= (40 if elf_class == 64 else 32) else 0
    e_phentsize_off = 54 if elf_class == 64 else 42
    e_phnum_off = 56 if elf_class == 64 else 44
    e_phentsize = struct.unpack_from(prefix + "H", data, e_phentsize_off)[0] if len(data) >= e_phentsize_off + 2 else 0
    e_phnum = struct.unpack_from(prefix + "H", data, e_phnum_off)[0] if len(data) >= e_phnum_off + 2 else 0
    e_shentsize_off = 58 if elf_class == 64 else 46
    e_shnum_off = 60 if elf_class == 64 else 48
    e_shstrndx_off = 62 if elf_class == 64 else 50
    e_shentsize = struct.unpack_from(prefix + "H", data, e_shentsize_off)[0] if len(data) >= e_shentsize_off + 2 else 0
    e_shnum = struct.unpack_from(prefix + "H", data, e_shnum_off)[0] if len(data) >= e_shnum_off + 2 else 0
    e_shstrndx = struct.unpack_from(prefix + "H", data, e_shstrndx_off)[0] if len(data) >= e_shstrndx_off + 2 else 0
    suspicious = []
    decoded = data.decode("latin-1", errors="ignore")
    patterns = {
        "ptrace": r"ptrace",
        "LD_PRELOAD": r"LD_PRELOAD",
        "/proc/self/mem": r"/proc/self/mem",
        "/dev/shm": r"/dev/shm",
        "wget": r"\bwget\b",
        "curl": r"\bcurl\b",
        "chmod": r"\bchmod\b",
        "nc": r"\bnc\b",
        "bash": r"\bbash\b",
    }
    marker_counts = {k: len(re.findall(v, decoded, re.I)) for k, v in patterns.items()}
    for key, count in marker_counts.items():
        if count:
            suspicious.append(f"ELF contains {count} occurrence(s) of the suspicious string '{key}'.")
    if e_type == 3:
        file_type = "shared object / PIE"
    elif e_type == 2:
        file_type = "executable"
    elif e_type == 1:
        file_type = "relocatable object"
    else:
        file_type = f"ELF type {e_type}"
    return {
        "format_valid": True,
        "class": f"ELF{elf_class}" if elf_class else "Unknown",
        "endianness": endian,
        "machine": e_machine,
        "object_type": file_type,
        "program_headers": e_phnum,
        "program_header_size": e_phentsize,
        "section_headers": e_shnum,
        "section_header_size": e_shentsize,
        "section_string_table_index": e_shstrndx,
        "program_header_offset": e_phoff,
        "entropy": round(_entropy(data), 4),
        "marker_counts": marker_counts,
        "suspicious_points": suspicious,
    }
