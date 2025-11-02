import os
import math
import re
from typing import Dict, List, Tuple

import numpy as np
import pefile


PRINTABLE_RE = re.compile(rb"[ -~]{4,}")

SUSPICIOUS_IMPORTS = {
    b"WriteProcessMemory",
    b"ReadProcessMemory",
    b"VirtualAlloc",
    b"VirtualAllocEx",
    b"VirtualProtect",
    b"CreateRemoteThread",
    b"OpenProcess",
    b"WinExec",
    b"ShellExecuteA",
    b"LoadLibraryA",
    b"GetProcAddress",
}

METASPLOIT_KEYWORDS = [
    b"meterpreter",
    b"metasploit",
    b"msf",
]

VEIL_KEYWORDS = [
    b"veil",
    b"ava",
]

SUSPICIOUS_KEYWORDS = [
    b"keylogger",
    b"ransom",
    b"inject",
    b"persistence",
    b"mimikatz",
    b"powershell",
    b"cmd.exe",
]


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    histogram = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)
    probs = histogram / max(1.0, float(len(data)))
    nz = probs[probs > 0]
    return float(-np.sum(nz * np.log2(nz)))


def byte_histogram_16bins(data: bytes) -> List[float]:
    if not data:
        return [0.0] * 16
    arr = np.frombuffer(data, dtype=np.uint8)
    bins = np.linspace(0, 256, 17)
    hist, _ = np.histogram(arr, bins=bins)
    hist = hist.astype(np.float64) / float(len(arr))
    return hist.tolist()


def extract_strings(data: bytes) -> List[bytes]:
    return PRINTABLE_RE.findall(data)[:20000]


def section_by_name(pe: pefile.PE, name: bytes) -> bytes:
    for s in pe.sections:
        raw_name = s.Name.rstrip(b"\x00")
        if raw_name.lower() == name.lower():
            try:
                return s.get_data()
            except Exception:
                return b""
    return b""


def list_imports(pe: pefile.PE) -> List[bytes]:
    imports: List[bytes] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                imports.append(imp.name)
    return imports


def count_keywords(strings: List[bytes], keywords: List[bytes]) -> int:
    total = 0
    for k in keywords:
        k_lower = k.lower()
        total += sum(1 for s in strings if k_lower in s.lower())
    return total


def has_suspicious_sections(pe: pefile.PE) -> bool:
    expected = {b".text", b".rdata", b".data", b".rsrc", b".idata", b".edata", b".tls", b".reloc"}
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").lower()
        if name and name not in {x.lower() for x in expected} and not name.startswith(b"."):
            return True
        # Very high entropy sections also suspicious
        try:
            data = s.get_data()
            if compute_entropy(data) > 7.5 and len(data) > 1024:
                return True
        except Exception:
            continue
    return False


def extract_features_from_exe(exe_path: str) -> Dict[str, float]:
    with open(exe_path, "rb") as f:
        file_bytes = f.read()

    features: Dict[str, float] = {}
    features["is_pe"] = 0

    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        features["is_pe"] = 1
    except Exception:
        # Not a PE file; still compute generic features
        pe = None  # type: ignore

    # Overall entropy and scaled
    entropy = compute_entropy(file_bytes)
    features["entropy"] = entropy
    features["entropy_scaled"] = entropy / 8.0 if entropy else 0.0

    # ASCII strings
    strings = extract_strings(file_bytes)
    features["ascii_matches_count"] = float(len(strings))
    features["ascii_strings"] = 1.0 if len(strings) > 0 else 0.0

    # Section entropies
    text_bytes = b""
    rdata_bytes = b""
    data_bytes = b""
    if pe is not None:
        text_bytes = section_by_name(pe, b".text")
        rdata_bytes = section_by_name(pe, b".rdata")
        data_bytes = section_by_name(pe, b".data")

    text_entropy = compute_entropy(text_bytes)
    rdata_entropy = compute_entropy(rdata_bytes)
    data_entropy = compute_entropy(data_bytes)
    features["text_entropy"] = text_entropy
    features["rdata_entropy"] = rdata_entropy
    features["data_entropy"] = data_entropy
    features["text_entropy_scaled"] = text_entropy / 8.0 if text_entropy else 0.0
    features["rdata_entropy_scaled"] = rdata_entropy / 8.0 if rdata_entropy else 0.0
    features["data_entropy_scaled"] = data_entropy / 8.0 if data_entropy else 0.0

    # Sections count
    num_sections = len(pe.sections) if pe is not None else 0
    features["num_sections"] = float(num_sections)

    # Imports
    imports = list_imports(pe) if pe is not None else []
    imports_lower = {imp.lower() for imp in imports}
    features["import_count"] = float(len(imports))
    features["imp_WriteProcessMemory"] = 1.0 if b"writeprocessmemory" in imports_lower else 0.0
    features["imp_WinExec"] = 1.0 if b"winexec" in imports_lower else 0.0
    features["imp_VirtualAlloc"] = 1.0 if b"virtualalloc" in imports_lower else 0.0
    features["imp_CreateRemoteThread"] = 1.0 if b"createremotethread" in imports_lower else 0.0
    features["imp_LoadLibraryA"] = 1.0 if b"loadlibrarya" in imports_lower else 0.0

    # Suspicious imports flag
    features["suspicious_imports"] = 1.0 if any(imp.lower() in imports_lower for imp in SUSPICIOUS_IMPORTS) else 0.0

    # PE timestamp
    try:
        features["pe_timestamp"] = float(pe.FILE_HEADER.TimeDateStamp) if pe is not None else 0.0
    except Exception:
        features["pe_timestamp"] = 0.0

    # Byte histogram 16-bin (normalized)
    hist16 = byte_histogram_16bins(file_bytes)
    for i, v in enumerate(hist16):
        features[f"byte_hist_{i}"] = float(v)

    # Heuristic indicators via strings
    metasploit_kw_count = count_keywords(strings, METASPLOIT_KEYWORDS)
    veil_kw_count = count_keywords(strings, VEIL_KEYWORDS)
    suspicious_kw_count = count_keywords(strings, SUSPICIOUS_KEYWORDS)
    features["metasploit_kw_count"] = float(metasploit_kw_count)
    features["veil_kw_count"] = float(veil_kw_count)
    features["suspicious_kw_count"] = float(suspicious_kw_count)

    features["metasploit_indicator"] = 1.0 if metasploit_kw_count > 0 else 0.0
    features["veil_indicator"] = 1.0 if veil_kw_count > 0 else 0.0

    # Suspicious sections heuristic
    features["suspicious_sections"] = 1.0 if (pe is not None and has_suspicious_sections(pe)) else 0.0

    # Fields we won't use for prediction (text) left blank; predictor will drop
    features["ascii_list"] = ""
    features["imports_list"] = ""
    features["yara_matches"] = 0.0

    return features


