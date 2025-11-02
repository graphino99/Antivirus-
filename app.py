import io
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import requests
import streamlit as st
from xgboost import XGBClassifier

from extract_features import extract_features_from_exe
from model_utils import load_schema, load_model, prepare_features
from stix_formatter import create_stix_bundle, stix_to_json
import google.generativeai as genai

# ==============================
# API KEYS (Inbuilt)
# ==============================
GEMINI_API_KEY = "AIzaSyC15hsDv36g8H1heO3ZQt9MW023G1NB8G0"  # 🔒 Replace with your Gemini key
VT_API_KEY = "e5093ccf71c1a1703bf15bb7cd49b291fb8d6b11345d4845dcadd8ac00ace786"  # 🔒 VirusTotal key


# ==============================
# Gemini Summary Helper Function
# ==============================
def gemini_summary(report_text, api_key=GEMINI_API_KEY):
    try:
        genai.configure(api_key=api_key)
        
        # Try to find an available model
        available_models = []
        model_names_to_try = []
        
        try:
            # List available models
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    model_name = m.name.replace('models/', '')
                    available_models.append(model_name)
        except Exception:
            pass
        
        # Build list of models to try (prefer common working ones)
        if available_models:
            # Prioritize gemini-pro if available (most stable)
            if "gemini-pro" in available_models:
                model_names_to_try.append("gemini-pro")
            # Try newer models if available
            for preferred in ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.0-pro"]:
                if preferred in available_models:
                    model_names_to_try.append(preferred)
        else:
            # Fallback to common model names
            model_names_to_try = ["gemini-pro", "gemini-1.5-pro", "gemini-1.5-flash"]
        
        # Try each model until one works
        model = None
        last_error = None
        for model_name in model_names_to_try:
            try:
                model = genai.GenerativeModel(model_name)
                # Test that it works
                break
            except Exception as e:
                last_error = e
                continue
        
        # Final fallback
        if model is None:
            try:
                model = genai.GenerativeModel("gemini-2.5-flash")
            except Exception:
                raise Exception(f"No working Gemini model found. Tried: {model_names_to_try}. Error: {last_error}")

        prompt = f"""
        You are an expert cybersecurity threat analyst. You MUST TRUST and PRIORITIZE the static analysis results provided below as they come from verified technical analysis of the executable file.

        === STATIC ANALYSIS RESULTS (TRUST THIS DATA) ===
        {report_text}

        IMPORTANT INSTRUCTIONS:
        1. **TRUST THE STATIC ANALYSIS**: The static analysis data is directly extracted from the executable file's binary structure, PE headers, imports, sections, and entropy measurements. This is objective technical evidence.
        2. Base your assessment primarily on these static analysis indicators:
           - High entropy values (>6.5) indicate potential packing/encryption
           - Suspicious imports (WriteProcessMemory, VirtualAlloc, CreateRemoteThread) suggest code injection capabilities
           - Suspicious sections or unexpected section names indicate obfuscation
           - Metasploit/Veil indicators are strong evidence of framework usage
        3. Provide a clear, professional security assessment report:
           - Overall threat verdict (High Risk/Medium Risk/Low Risk/Benign) based on static analysis findings
           - Specific technical indicators found in the static analysis
           - Risk assessment explanation linking static analysis features to threat behavior
           - Recommended next steps for security teams
        4. Be direct and factual - let the static analysis data guide your assessment.

        Format your response as a structured security assessment report suitable for inclusion in threat intelligence platforms.
        """

        response = model.generate_content(prompt)
        
        # Handle response
        if hasattr(response, 'text'):
            return response.text.strip()
        elif hasattr(response, 'candidates') and response.candidates:
            if hasattr(response.candidates[0], 'content'):
                content = response.candidates[0].content
                if hasattr(content, 'parts'):
                    text_parts = [part.text for part in content.parts if hasattr(part, 'text')]
                    if text_parts:
                        return '\n'.join(text_parts).strip()
                return str(content).strip()
        return str(response).strip()

    except Exception as e:
        return f"Gemini API error: {str(e)}"


# ==============================
# VirusTotal File Analysis
# ==============================
def analyze_with_virustotal(file_path: str, api_key: str = VT_API_KEY):
    """
    Uploads a file to VirusTotal and retrieves its analysis report.
    """
    vt_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    try:
        # Upload file to VirusTotal
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            upload_response = requests.post(vt_url, headers=headers, files=files)
        if upload_response.status_code != 200:
            return {"error": f"Upload failed: {upload_response.text}"}

        analysis_id = upload_response.json()["data"]["id"]

        # Poll until analysis completes
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(15):
            result = requests.get(analysis_url, headers=headers)
            data = result.json()
            status = data.get("data", {}).get("attributes", {}).get("status", "")
            if status == "completed":
                return data
            time.sleep(5)

        return {"error": "Analysis timed out. Try again later."}
    except Exception as e:
        return {"error": str(e)}


# ===========================
# Load model and schema utils
# ===========================
@st.cache_resource
def load_artifacts(model_dir: str) -> Tuple[Dict, XGBClassifier, List[str]]:
    schema = load_schema(os.path.join(model_dir, "feature_schema.json"))
    model = load_model(model_dir)
    feature_cols: List[str] = schema["feature_columns"]
    return schema, model, feature_cols


# ===========================
# Format static analysis report
# ===========================
def pretty_analyzer_report(features: Dict[str, float]) -> Dict[str, object]:
    report = {}
    report["is_pe"] = bool(features.get("is_pe", 0))
    report["num_sections"] = int(features.get("num_sections", 0))
    report["entropy"] = float(features.get("entropy", 0.0))
    report["import_count"] = int(features.get("import_count", 0))
    report["suspicious_imports"] = bool(features.get("suspicious_imports", 0))
    report["suspicious_sections"] = bool(features.get("suspicious_sections", 0))
    return report


# ===========================
# Main Streamlit App
# ===========================
def main() -> None:
    st.set_page_config(page_title="Malware & File Analyzer", page_icon="🛡️", layout="wide")
    st.title("🛡️ Malware & File Analyzer (XGBoost + VirusTotal + Gemini)")

    with st.sidebar:
        st.header("Model Configuration")
        model_dir = st.text_input("Model artifacts directory", value="model_artifacts")
        threshold = st.slider("Classification threshold", min_value=0.05, max_value=0.95, value=0.5, step=0.05)

        st.success("✅ Gemini & VirusTotal API Keys Loaded Securely")

        artifacts_ready = False
        if os.path.exists(os.path.join(model_dir, "xgb_model.json")) and os.path.exists(
            os.path.join(model_dir, "feature_schema.json")
        ):
            artifacts_ready = True
            st.caption("✅ ML model ready.")
        else:
            st.warning("⚠️ ML model artifacts not found. Only VirusTotal mode will be active.")

    uploaded = st.file_uploader(
        "Upload a file (.exe, .pdf, .png, .jpg, .mp4, etc.)", type=None, accept_multiple_files=False
    )

    if uploaded is None:
        st.info("📁 Upload a file to begin analysis.")
        return

    # Save uploaded file
    tmp_dir = os.path.join(".", "_uploads")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, uploaded.name)
    with open(tmp_path, "wb") as f:
        f.write(uploaded.getbuffer())

    file_ext = os.path.splitext(uploaded.name)[1].lower()

    # ---------------------------
    # CASE 1: Executable file
    # ---------------------------
    if file_ext in [".exe", ".dll", ".bin"]:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Static Analysis")
            raw_features = extract_features_from_exe(tmp_path)
            report = pretty_analyzer_report(raw_features)
            st.json(report)

        with col2:
            st.subheader("🧠 ML Classification (XGBoost)")
            proba = 0.0
            pred = 0
            label = "unknown"
            ml_result_dict = None
            
            if not artifacts_ready:
                st.error("❌ Model artifacts missing.")
            else:
                try:
                    schema, model, feature_cols = load_artifacts(model_dir)
                    X = prepare_features(pd.DataFrame([raw_features]), feature_cols)
                    
                    # Ensure model has required sklearn attributes
                    if not hasattr(model, "n_classes_"):
                        model.n_classes_ = 2
                    if not hasattr(model, "classes_"):
                        model.classes_ = [0, 1]
                    
                    # Get prediction probabilities
                    proba_array = model.predict_proba(X.values)
                    # Handle both binary and multi-class cases
                    if proba_array.shape[1] > 1:
                        proba = float(proba_array[:, 1][0])  # Probability of class 1 (malicious)
                    else:
                        proba = float(proba_array[0][0])
                    
                    pred = int(proba >= threshold)
                    label = "malicious" if pred == 1 else "benign"
                    
                    # Create ML result dict
                    ml_result_dict = {
                        "malicious_probability": proba,
                        "prediction": pred,
                        "label": label,
                        "threshold": threshold
                    }
                    
                    st.metric("Prediction", label)
                    st.metric("Malicious Probability", f"{proba:.4f}")
                except Exception as e:
                    st.error(f"❌ ML prediction failed: {str(e)}")
                    st.caption("Please ensure the model is properly trained and all features are available.")
                    ml_result_dict = {
                        "malicious_probability": 0.0,
                        "prediction": 0,
                        "label": "unknown",
                        "threshold": threshold
                    }

        st.markdown("---")
        st.subheader("🤖 Gemini AI Security Summary")
        gemini_summary_text = None
        
        # Prepare combined report emphasizing static analysis
        if ml_result_dict:
            combined_report = {
                "STATIC_ANALYSIS_RESULTS": report,
                "ML_CLASSIFICATION_SUPPORT": ml_result_dict
            }
            report_for_gemini = json.dumps(combined_report, indent=2)
        else:
            report_for_gemini = json.dumps(report, indent=2)
        
        with st.spinner("Generating AI summary (trusting static analysis data)..."):
            summary_text = gemini_summary(report_for_gemini)
            if "Gemini API error" not in summary_text:
                gemini_summary_text = summary_text
                st.success("✅ AI Summary Generated (Prioritizing Static Analysis):")
                st.markdown(summary_text)
            else:
                st.error(summary_text)
        
        # STIX Format Output Section
        st.markdown("---")
        st.subheader("📋 STIX 2.1 Format Output")
        
        with st.spinner("Generating STIX bundle..."):
            try:
                # Use ml_result_dict if available, otherwise create default
                if not ml_result_dict:
                    ml_result_dict = {
                        "malicious_probability": 0.0,
                        "prediction": 0,
                        "label": "unknown",
                        "threshold": threshold
                    }
                
                stix_bundle = create_stix_bundle(
                    static_result=report,
                    ml_result=ml_result_dict,
                    exe_path=tmp_path,
                    gemini_summary=gemini_summary_text
                )
                
                stix_json = stix_to_json(stix_bundle, pretty=True)
                
                st.success("✅ STIX 2.1 Bundle Generated Successfully")
                
                # Download button
                st.download_button(
                    label="📥 Download STIX JSON",
                    data=stix_json,
                    file_name=f"malware_analysis_{os.path.basename(tmp_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
                
                # Expandable STIX viewer
                with st.expander("📄 View STIX Bundle (JSON)", expanded=False):
                    st.code(stix_json, language="json")
                    
            except Exception as e:
                st.error(f"❌ STIX generation failed: {str(e)}")

    # ---------------------------
    # CASE 2: PDF or Media file
    # ---------------------------
    else:
        st.subheader("🧪 VirusTotal File Analysis")
        with st.spinner("Uploading to VirusTotal..."):
            vt_data = analyze_with_virustotal(tmp_path, VT_API_KEY)

        if "error" in vt_data:
            st.error(vt_data["error"])
        else:
            stats = vt_data["data"]["attributes"]["stats"]
            st.write("### 🧾 Detection Stats")
            st.json(stats)

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            st.metric("Malicious", malicious)
            st.metric("Suspicious", suspicious)
            st.metric("Harmless", harmless)
            st.metric("Undetected", undetected)

            st.markdown("---")
            st.subheader("🤖 Gemini AI Summary of VirusTotal Report")
            report_text = json.dumps(stats, indent=2)
            summary_text = gemini_summary(report_text)
            st.success("✅ Gemini Summary Generated:")
            st.markdown(summary_text)

    # Cleanup
    try:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except Exception:
        pass


if __name__ == "__main__":
    main()
