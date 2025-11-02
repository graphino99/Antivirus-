import json
import hashlib
import os
from datetime import datetime
from typing import Dict, Any, Optional
import uuid

def generate_stix_id(prefix: str) -> str:
    """Generate a STIX-compliant ID."""
    return f"{prefix}--{uuid.uuid4()}"

def create_stix_bundle(static_result: Dict[str, Any], ml_result: Dict[str, Any], exe_path: Optional[str] = None, gemini_summary: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert malware analysis results to STIX 2.1 format.
    Returns a STIX Bundle with Indicator, Observable (File), and Report objects.
    """
    bundle_id = generate_stix_id("bundle")
    created_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    
    # File hash and name
    file_name = os.path.basename(exe_path) if exe_path else "unknown.exe"
    file_hash = ""
    file_size = 0
    if exe_path and os.path.exists(exe_path):
        with open(exe_path, "rb") as f:
            file_bytes = f.read()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            file_size = len(file_bytes)
    
    # Create File Observable
    file_observable_id = generate_stix_id("file")
    file_observable = {
        "type": "file",
        "id": file_observable_id,
        "name": file_name,
        "hashes": {
            "SHA-256": file_hash
        } if file_hash else {},
        "size": file_size,
        "extensions": {
            "windows-pebinary-ext": {
                "pe_type": "exe" if static_result.get("is_pe", 0) else "unknown"
            }
        }
    }
    
    # Create Indicator
    indicator_id = generate_stix_id("indicator")
    pattern_type = "stix"
    
    # Build pattern based on results
    pattern_parts = []
    if static_result.get("suspicious_imports", False):
        pattern_parts.append("[file:name = '{}']".format(file_name))
    if ml_result.get("malicious_probability", 0) > 0.7:
        pattern_parts.append("[file:hashes.'SHA-256' = '{}']".format(file_hash[:16]))
    
    pattern = " AND ".join(pattern_parts) if pattern_parts else "[file:name = '{}']".format(file_name)
    
    # Determine labels based on results
    labels = []
    if ml_result.get("label") == "malicious" or ml_result.get("malicious_probability", 0) > 0.7:
        labels = ["malicious-activity"]
    elif ml_result.get("malicious_probability", 0) > 0.5:
        labels = ["anomalous-activity"]
    else:
        labels = ["benign"]
    
    indicator = {
        "type": "indicator",
        "id": indicator_id,
        "spec_version": "2.1",
        "created": created_time,
        "modified": created_time,
        "name": f"Malware Indicator for {file_name}",
        "description": f"Generated from static analysis and ML classification. ML Probability: {ml_result.get('malicious_probability', 0):.4f}",
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": created_time,
        "labels": labels,
        "confidence": int(ml_result.get("malicious_probability", 0) * 100),
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "execution"
            }
        ]
    }
    
    # Create Report
    report_id = generate_stix_id("report")
    
    # Build report description with analysis results
    report_desc = f"Malware Analysis Report for {file_name}\n\n"
    report_desc += f"Static Analysis Results:\n"
    report_desc += f"- Is PE File: {static_result.get('is_pe', False)}\n"
    report_desc += f"- Entropy: {static_result.get('entropy', 0):.2f}\n"
    report_desc += f"- Suspicious Imports: {static_result.get('suspicious_imports', False)}\n"
    report_desc += f"- Suspicious Sections: {static_result.get('suspicious_sections', False)}\n"
    report_desc += f"- Metasploit Indicators: {static_result.get('metasploit_indicator', False)}\n"
    report_desc += f"- Veil Indicators: {static_result.get('veil_indicator', False)}\n"
    report_desc += f"\nML Classification Results:\n"
    report_desc += f"- Malicious Probability: {ml_result.get('malicious_probability', 0):.4f}\n"
    report_desc += f"- Prediction: {ml_result.get('label', 'unknown')}\n"
    
    if gemini_summary:
        report_desc += f"\nAI Analysis Summary:\n{gemini_summary}"
    
    report = {
        "type": "report",
        "id": report_id,
        "spec_version": "2.1",
        "created": created_time,
        "modified": created_time,
        "name": f"Malware Analysis Report: {file_name}",
        "description": report_desc,
        "published": created_time,
        "report_types": ["threat-report"],
        "object_refs": [file_observable_id, indicator_id],
        "labels": labels
    }
    
    # Create Relationship
    relationship_id = generate_stix_id("relationship")
    relationship = {
        "type": "relationship",
        "id": relationship_id,
        "spec_version": "2.1",
        "created": created_time,
        "modified": created_time,
        "relationship_type": "indicates",
        "source_ref": indicator_id,
        "target_ref": file_observable_id
    }
    
    # Create Bundle
    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": [
            file_observable,
            indicator,
            report,
            relationship
        ]
    }
    
    return bundle

def stix_to_json(stix_bundle: Dict[str, Any], pretty: bool = True) -> str:
    """Convert STIX bundle to JSON string."""
    if pretty:
        return json.dumps(stix_bundle, indent=2)
    return json.dumps(stix_bundle)

