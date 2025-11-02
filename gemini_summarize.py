import google.generativeai as genai
import hashlib
import json
import os
from typing import Dict, Any, Optional

# Helper: get short file fingerprint for privacy

def file_fingerprint(path: str) -> str:
    h = hashlib.sha256()
    try:
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                h.update(f.read(4096))  # Only file head for context
            return h.hexdigest()[:16]  # Short hash
    except Exception:
        pass
    return "n/a"


def gemini_summary(static_result: Dict[str, Any], ml_result: Dict[str, Any], exe_path: Optional[str] = None, api_key: Optional[str] = None) -> str:
    """Generate AI summary using Gemini API with better error handling."""
    if not api_key:
        api_key = os.environ.get("GEMINI_API_KEY")
    
    if not api_key:
        raise ValueError("Gemini API key is required. Provide via api_key parameter or GEMINI_API_KEY environment variable.")
    
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")  # Use newer model
        
        # Short fingerprint prevents sending raw user data.
        file_meta = ""
        if exe_path and os.path.exists(exe_path):
            fp = file_fingerprint(exe_path)
            file_meta = f"File fingerprint (first 16 chars): {fp}\nFilename: {os.path.basename(exe_path)}"
        else:
            file_meta = "File: N/A"
        
        prompt = f'''You are an expert cybersecurity threat analyst. Analyze and summarize the following malware detection results from both static analysis and machine learning classification.

Provide a clear, concise security assessment report covering:
1. Overall verdict (High/Medium/Low risk or Benign)
2. Key risk indicators found
3. Specific suspicious behaviors or attributes
4. Recommended next steps for security teams

Static Analyzer Results:
{json.dumps(static_result, indent=2)}

Machine Learning Classification:
{json.dumps(ml_result, indent=2)}

File Information:
{file_meta}

Format your response as a clear security assessment report suitable for a security analyst.'''
        
        response = model.generate_content(prompt)
        
        # Handle different response types
        if hasattr(response, 'text'):
            return response.text.strip()
        elif hasattr(response, 'candidates') and response.candidates:
            if hasattr(response.candidates[0], 'content'):
                return str(response.candidates[0].content).strip()
        return str(response).strip()
        
    except Exception as e:
        raise Exception(f"Gemini API error: {str(e)}. Please check your API key and network connection.")
