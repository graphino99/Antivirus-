#!/usr/bin/env python3
"""
analyzer_metasploit_detector.py

Single-file static malware analyzer focused on detecting Metasploit/Meterpreter payloads.
This patched version accepts either a single file or a directory (recursively),
writing per-file JSON reports to `reports/` and a `reports/summary.json`.

Requirements:
    pip install yara-python pefile python-magic==0.4.27 requests tqdm

Usage:
    python3 analyzer_metasploit_detector.py /path/to/scan_dir_or_file

Safety:
    This script performs *static* analysis only. Do NOT execute samples.
"""

import os
import sys
import json
import hashlib
import math
import yara
import pefile
import traceback
from tqdm import tqdm
from typing import Dict, List, Any

# ---------- Configuration ----------

REPORT_DIR = "reports"
RULE_NAME = "metasploit_rules"

# Thresholds / scoring weights (tune as needed)
WEIGHTS = {
    "yara_match": 50,
    "keyword": 25,
    "high_entropy": 10,
    "suspicious_imports": 20,
    "suspicious_sections": 15,
    "packer_strings": 20
}
ENTROPY_HIGH = 7.5  # bytes entropy considered high (possible packing/encryption)
SECTION_COUNT_SUSPICIOUS = 10

# ---------- Embedded YARA rules (focused on Metasploit/Meterpreter artifacts) ----------
YARA_SOURCE = r"""
rule MSF_Meterpreter_Strings
{
    meta:
        author = "Abhinav (defensive)"
        description = "Detect Meterpreter / Metasploit strings"
        confidence = 80
    strings:
        $meter1 = "meterpreter" nocase
        $meter2 = "Meterpreter" ascii
        $msf = "msf" wide ascii
        $reverse_http = "reverse_http" nocase
        $reverse_https = "reverse_https" nocase
        $reverse_tcp = "reverse_tcp" nocase
        $bind_tcp = "bind_tcp" nocase
        $stager = "stager" nocase
        $staged = "staged" nocase
        $shikata = "shikata_ga_nai" nocase
        $enc_xor = "x86/shikata" nocase
        $reflect = "ReflectiveLoader" ascii
        $payload = "Payload" ascii
        $mettle = "mettle" nocase
        $vnc_inject = "vncinject" nocase
    condition:
        any of ($meter*) or any of ($reverse_*) or $shikata or $reflect or $mettle or $msf or $bind_tcp or $stager or $staged or $enc_xor or $payload or $vnc_inject
}

rule MSF_Packer_And_Encoder_Names
{
    meta:
        description = "Common msf encoder or packer names in strings"
    strings:
        $enc1 = "alpha_mixed" nocase
        $enc2 = "x86/shikata" nocase
        $enc3 = "x86/jmp_call_additive" nocase
        $enc4 = "x64/xor" nocase
        $enc5 = "shikata" nocase
    condition:
        any of them
}

rule MSF_HTTP_STAGER_PATTERN
{
    meta:
        description = "Simple HTTP stager patterns (strings used by staged HTTP payloads)"
    strings:
        $http1 = "HTTP/1.1" ascii
        $http2 = "User-Agent: " ascii
        $http3 = "Connection: Keep-Alive" ascii
        $http4 = "Content-Length:" ascii
    condition:
        2 of ($http*)
}

rule Suspicious_DLL_Imports_For_RATs
{
    meta:
        description = "Detect imports commonly used by remote access Trojan/stagers"
    strings:
        $winsock = "ws2_32.dll" nocase
        $wininet = "wininet.dll" nocase
        $urlmon = "urlmon.dll" nocase
        $advapi = "advapi32.dll" nocase
        $kernel32 = "kernel32.dll" nocase
        $loadlib = "LoadLibraryA" ascii
        $getproc = "GetProcAddress" ascii
    condition:
        any of ($winsock, $wininet, $urlmon, $advapi, $kernel32) and any of ($loadlib, $getproc)
}
"""

# ---------- Utility functions ----------

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def file_entropy(path: str) -> float:
    with open(path, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for c in freq:
        if c == 0:
            continue
        p = c/length
        entropy -= p * math.log2(p)
    return entropy

def is_pe(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            mz = f.read(2)
        return mz == b'MZ'
    except Exception:
        return False

# ---------- Static analysis functions ----------
def analyze_pe(path: str) -> Dict[str, Any]:
    """Extract PE metadata: imports, exports, sections, section entropies."""
    result = {}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll = entry.dll.decode(errors='ignore') if isinstance(entry.dll, bytes) else str(entry.dll)
                except Exception:
                    dll = str(entry.dll)
                funcs = []
                for imp in entry.imports:
                    try:
                        fn = imp.name.decode(errors='ignore') if imp.name else f"ord_{imp.ordinal}"
                    except Exception:
                        fn = str(imp)
                    funcs.append(fn)
                imports.append({'dll': dll.lower(), 'functions': funcs})
        result['imports'] = imports

        # Sections
        secs = []
        for s in pe.sections:
            name = s.Name.decode(errors='ignore').rstrip('\\x00')
            try:
                ent = s.get_entropy()
            except Exception:
                ent = None
            secs.append({
                'name': name,
                'virt_size': s.Misc_VirtualSize,
                'raw_size': s.SizeOfRawData,
                'entropy': ent
            })
        result['sections'] = secs
        result['number_of_sections'] = len(secs)

        # Export table presence
        try:
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append(e.name.decode(errors='ignore') if e.name else str(e.ordinal))
            result['exports'] = exports
        except Exception:
            result['exports'] = []

    except Exception as e:
        result['pe_error'] = str(e)
    return result

def extract_ascii_strings(path: str, min_len: int = 4) -> List[str]:
    """Extract printable ASCII strings from file (simple implementation)."""
    strings = []
    with open(path, 'rb') as f:
        data = f.read()
    current = []
    for b in data:
        if 32 <= b <= 126:  # printable range
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                s = ''.join(current)
                strings.append(s)
            current = []
    # tail
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings

# ---------- Detection heuristics & scoring ----------
def score_indicators(yara_matches: List[str], strings: List[str], pe_meta: Dict[str, Any], entropy: float) -> Dict[str, Any]:
    """Compute a detection score and reasoning for Metasploit-like payloads."""
    score = 0
    reasons = []

    # YARA matches
    if yara_matches:
        score += WEIGHTS.get("yara_match", 50)
        reasons.append(f"YARA rules matched: {', '.join(yara_matches)}")

    # Keyword string heuristics (direct Meterpreter/MSF markers)
    key_indicators = ['meterpreter', 'mettle', 'msf', 'reverse_http', 'reverse_https', 'reverse_tcp', 'bind_tcp', 'shikata_ga_nai', 'ReflectiveLoader', 'stager', 'staged']
    found_keys = []
    lower_strings = [s.lower() for s in strings]
    for k in key_indicators:
        if k.lower() in ' '.join(lower_strings):
            found_keys.append(k)
    if found_keys:
        score += WEIGHTS.get("keyword", 25)
        reasons.append(f"Found suspicious keywords in strings: {', '.join(found_keys)}")

    # High entropy -> possible packing/enc/obfuscation
    if entropy and entropy >= ENTROPY_HIGH:
        score += WEIGHTS.get("high_entropy", 10)
        reasons.append(f"High file entropy: {entropy:.2f}")

    # Suspicious imports commonly used by MSF payloads / stagers (networking and dynamic loading)
    suspicious_imports = set()
    if pe_meta:
        for imp in pe_meta.get('imports', []):
            dll = imp.get('dll', '').lower()
            funcs = [f.lower() for f in imp.get('functions', [])]
            # network DLLs and dynamic load APIs
            if any(x in dll for x in ['ws2_32', 'wininet', 'winhttp', 'urlmon', 'winsock']):
                suspicious_imports.add(dll)
            if any(f in funcs for f in ['loadlibrarya', 'getprocaddress', 'virtualalloc', 'virtualprotect', 'createprocessa', 'createservicea']):
                suspicious_imports.add('dynamic_api_usage')
    if suspicious_imports:
        score += WEIGHTS.get("suspicious_imports", 20)
        reasons.append(f"Suspicious imports / APIs: {', '.join(sorted(suspicious_imports))}")

    # Suspicious section names / count (many packers add many sections or weird names)
    suspicious_sections = []
    if pe_meta:
        for s in pe_meta.get('sections', []):
            name = s.get('name', '').lower()
            if name in ['.rsrc', '.text', '.data', '.rdata']:
                continue
            # uncommon names used by packers/cryppers
            if name.startswith('.as') or name.startswith('.upd') or name.startswith('.adata') or name.startswith('.enc') or name.startswith('.xx'):
                suspicious_sections.append(name)
            # extremely short or non-ascii names
            if any(not (32 <= ord(ch) <= 126) for ch in name) or name == '':
                suspicious_sections.append(name)
        if pe_meta.get('number_of_sections', 0) >= SECTION_COUNT_SUSPICIOUS:
            suspicious_sections.append(f"high_section_count_{pe_meta.get('number_of_sections')}")

    if suspicious_sections:
        score += WEIGHTS.get("suspicious_sections", 15)
        reasons.append(f"Suspicious/packed sections: {', '.join(suspicious_sections)}")

    # Packer/encoder strings
    packer_indicators = ['shikata', 'alpha_mixed', 'xor', 'upx', 'aspack', 'pez', 'mpress']
    found_packers = [p for p in packer_indicators if any(p in s.lower() for s in strings)]
    if found_packers:
        score += WEIGHTS.get("packer_strings", 20)
        reasons.append(f"Found packer/encoder strings: {', '.join(found_packers)}")

    # clamp score to 0-100
    score = max(0, min(100, score))
    return {"score": score, "reasons": reasons}

# ---------- Main orchestration ----------
def compile_yara():
    try:
        rules = yara.compile(source=YARA_SOURCE)
        return rules
    except Exception as e:
        print("ERROR compiling YARA:", e)
        print(traceback.format_exc())
        sys.exit(1)

def analyze_file(path: str, rules) -> Dict[str, Any]:
    result = {"path": path}
    try:
        result["sha256"] = sha256_of_file(path)
    except Exception as e:
        result["error"] = f"Failed to hash file: {e}"
        return result

    # determine file type and entropy
    try:
        entropy = file_entropy(path)
        result["entropy"] = entropy
    except Exception as e:
        result["entropy_error"] = str(e)
        entropy = None

    # run yara
    yara_matches = []
    try:
        matches = rules.match(path)
        yara_matches = [m.rule for m in matches] if matches else []
        result["yara_matches"] = yara_matches
    except Exception as e:
        result["yara_error"] = str(e)

    # extract readable strings (for keyword heuristics)
    try:
        strings = extract_ascii_strings(path, min_len=4)
        # keep only unique small sample to reduce memory
        result["sample_strings"] = strings[:200]
    except Exception as e:
        strings = []
        result["strings_error"] = str(e)

    # If PE, parse imports & sections
    pe_meta = None
    if is_pe(path):
        try:
            pe_meta = analyze_pe(path)
            result["pe"] = pe_meta
            result["is_pe"] = True
        except Exception as e:
            result["pe_error"] = str(e)
            result["is_pe"] = True
    else:
        result["is_pe"] = False

    # scoring
    scoreinfo = score_indicators(yara_matches, strings, pe_meta, entropy)
    result["detection_score"] = scoreinfo["score"]
    result["detection_reasons"] = scoreinfo["reasons"]

    # final verdict shorthand
    if scoreinfo["score"] >= 70:
        verdict = "highly_likely_metasploit"
    elif scoreinfo["score"] >= 40:
        verdict = "possible_metasploit"
    else:
        verdict = "unlikely_metasploit"
    result["verdict"] = verdict

    return result

def scan_path(path: str):
    """
    Accepts either a directory or a single file.
    If 'path' is a file, analyze just that file.
    If 'path' is a directory, analyze all files recursively under it.
    """
    if not os.path.exists(path):
        raise RuntimeError(f"{path} does not exist")

    os.makedirs(REPORT_DIR, exist_ok=True)
    rules = compile_yara()
    summary = []

    # If it's a file, analyze just that file
    if os.path.isfile(path):
        print(f"Scanning single file: {path}")
        try:
            report = analyze_file(path, rules)
            sha = report.get("sha256", hashlib.sha256(path.encode()).hexdigest())
            outpath = os.path.join(REPORT_DIR, f"{sha}.json")
            with open(outpath, "w") as fh:
                json.dump(report, fh, indent=2)
            summary.append({
                "path": path,
                "sha256": report.get("sha256"),
                "verdict": report.get("verdict"),
                "score": report.get("detection_score"),
                "yara_matches": report.get("yara_matches", []),
                "entropy": report.get("entropy")
            })
        except Exception as e:
            print(f"Error analyzing {path}: {e}")
    else:
        # It's a directory: recurse as before
        for root, _, files in os.walk(path):
            for fn in tqdm(files, desc="Scanning files"):
                full = os.path.join(root, fn)
                try:
                    report = analyze_file(full, rules)
                    sha = report.get("sha256", hashlib.sha256(full.encode()).hexdigest())
                    outpath = os.path.join(REPORT_DIR, f"{sha}.json")
                    with open(outpath, "w") as fh:
                        json.dump(report, fh, indent=2)
                    summary.append({
                        "path": full,
                        "sha256": report.get("sha256"),
                        "verdict": report.get("verdict"),
                        "score": report.get("detection_score"),
                        "yara_matches": report.get("yara_matches", []),
                        "entropy": report.get("entropy")
                    })
                except Exception as e:
                    print(f"Error analyzing {full}: {e}")

    # write summary
    with open(os.path.join(REPORT_DIR, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"Scan complete. Reports in {REPORT_DIR}")

# ---------- Main entry ----------
if __name__ == "__main__":
    # Accept single path or multiple paths as CLI args
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer_metasploit_detector.py /path/to/file_or_directory [optional: additional paths...]")
        sys.exit(1)
    # Skip the first argument if it's '-f' (added by Colab)
    paths = sys.argv[1:]
    if paths and paths[0] == '-f':
        paths = paths[1:]
    if not paths:
        print("Usage: python3 analyzer_metasploit_detector.py /path/to/file_or_directory [optional: additional paths...]")
        sys.exit(1)
    for p in paths:
        scan_path(p)
