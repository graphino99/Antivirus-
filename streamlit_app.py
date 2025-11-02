#!/usr/bin/env python3
"""
Streamlit Frontend for Metasploit/Meterpreter Detection Tool

A web-based interface for the static malware analyzer focused on detecting 
Metasploit/Meterpreter payloads.

Usage:
    streamlit run streamlit_app.py
"""

import streamlit as st
import os
import sys
import json
import hashlib
import math
import yara
import pefile
import traceback
from typing import Dict, List, Any
import tempfile
from datetime import datetime

# Import our analyzer functions
from analyzer_metasploit_detector import (
    sha256_of_file, file_entropy, is_pe, analyze_pe, extract_ascii_strings,
    score_indicators, compile_yara, analyze_file, YARA_SOURCE, WEIGHTS,
    ENTROPY_HIGH, SECTION_COUNT_SUSPICIOUS
)

# Page configuration
st.set_page_config(
    page_title="Metasploit Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .warning-card {
        background-color: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ffc107;
    }
    .danger-card {
        background-color: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #dc3545;
    }
    .success-card {
        background-color: #d4edda;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #28a745;
    }
    .code-block {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #dee2e6;
        font-family: 'Courier New', monospace;
    }
</style>
""", unsafe_allow_html=True)

def get_verdict_color(verdict: str) -> str:
    """Get color class based on verdict"""
    if "highly_likely" in verdict:
        return "danger-card"
    elif "possible" in verdict:
        return "warning-card"
    else:
        return "success-card"

def display_file_info(file_info: Dict[str, Any]):
    """Display basic file information"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("File Size", f"{file_info.get('file_size', 0):,} bytes")
    
    with col2:
        st.metric("SHA256", file_info.get('sha256', 'N/A')[:16] + "...")
    
    with col3:
        entropy = file_info.get('entropy', 0)
        st.metric("Entropy", f"{entropy:.2f}")
    
    with col4:
        is_pe = file_info.get('is_pe', False)
        st.metric("PE File", "Yes" if is_pe else "No")

def display_detection_results(results: Dict[str, Any]):
    """Display detection results with visual indicators"""
    verdict = results.get('verdict', 'unknown')
    score = results.get('detection_score', 0)
    reasons = results.get('detection_reasons', [])
    
    # Main verdict display
    st.markdown(f"### 🎯 Detection Results")
    
    # Verdict card
    color_class = get_verdict_color(verdict)
    verdict_text = verdict.replace('_', ' ').title()
    
    st.markdown(f"""
    <div class="{color_class}">
        <h3>Verdict: {verdict_text}</h3>
        <h2>Score: {score}/100</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Progress bar for score
    st.progress(score / 100)
    
    # Detection reasons
    if reasons:
        st.markdown("#### 🔍 Detection Reasons:")
        for i, reason in enumerate(reasons, 1):
            st.markdown(f"{i}. {reason}")
    
    # YARA matches
    yara_matches = results.get('yara_matches', [])
    if yara_matches:
        st.markdown("#### 🚨 YARA Rule Matches:")
        for match in yara_matches:
            st.markdown(f"- `{match}`")

def display_pe_analysis(pe_data: Dict[str, Any]):
    """Display PE file analysis results"""
    if not pe_data:
        return
    
    st.markdown("#### 📋 PE File Analysis")
    
    # Sections
    sections = pe_data.get('sections', [])
    if sections:
        st.markdown("**Sections:**")
        section_data = []
        for section in sections:
            section_data.append({
                "Name": section.get('name', 'N/A'),
                "Virtual Size": f"{section.get('virt_size', 0):,}",
                "Raw Size": f"{section.get('raw_size', 0):,}",
                "Entropy": f"{section.get('entropy', 0):.2f}" if section.get('entropy') else "N/A"
            })
        st.dataframe(section_data, use_container_width=True)
    
    # Imports
    imports = pe_data.get('imports', [])
    if imports:
        st.markdown("**Imports:**")
        import_data = []
        for imp in imports[:20]:  # Limit to first 20 imports
            dll = imp.get('dll', 'N/A')
            functions = imp.get('functions', [])
            import_data.append({
                "DLL": dll,
                "Functions": f"{len(functions)} functions",
                "Sample Functions": ", ".join(functions[:5]) if functions else "None"
            })
        st.dataframe(import_data, use_container_width=True)
        
        if len(imports) > 20:
            st.info(f"Showing first 20 of {len(imports)} imports")

def display_strings_analysis(strings: List[str]):
    """Display string analysis results"""
    if not strings:
        return
    
    st.markdown("#### 📝 String Analysis")
    
    # Suspicious keywords
    suspicious_keywords = [
        'meterpreter', 'mettle', 'msf', 'reverse_http', 'reverse_https', 
        'reverse_tcp', 'bind_tcp', 'shikata_ga_nai', 'ReflectiveLoader', 
        'stager', 'staged', 'shikata', 'alpha_mixed', 'xor', 'upx'
    ]
    
    found_suspicious = []
    for string in strings:
        for keyword in suspicious_keywords:
            if keyword.lower() in string.lower():
                found_suspicious.append(string)
                break
    
    if found_suspicious:
        st.markdown("**Suspicious Strings Found:**")
        for string in found_suspicious[:10]:  # Limit to first 10
            st.code(string)
        if len(found_suspicious) > 10:
            st.info(f"Showing first 10 of {len(found_suspicious)} suspicious strings")
    else:
        st.success("No suspicious strings detected")

def main():
    """Main Streamlit application"""
    
    # Header
    st.markdown('<h1 class="main-header">🛡️ Metasploit/Meterpreter Detector</h1>', unsafe_allow_html=True)
    
    st.markdown("""
    This tool performs static analysis on executable files to detect Metasploit/Meterpreter payloads.
    Upload an executable file below to begin analysis.
    """)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### ⚙️ Configuration")
        
        # Display current weights
        st.markdown("**Detection Weights:**")
        for key, value in WEIGHTS.items():
            st.text(f"{key}: {value}")
        
        st.markdown("**Thresholds:**")
        st.text(f"High Entropy: {ENTROPY_HIGH}")
        st.text(f"Suspicious Sections: {SECTION_COUNT_SUSPICIOUS}")
        
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.markdown("""
        This tool analyzes files for:
        - YARA rule matches
        - Suspicious keywords
        - High entropy (packing)
        - Suspicious imports
        - PE section analysis
        - String analysis
        """)
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose an executable file to analyze",
        type=['exe', 'dll', 'sys', 'scr', 'com', 'bat', 'cmd'],
        help="Supported formats: .exe, .dll, .sys, .scr, .com, .bat, .cmd"
    )
    
    if uploaded_file is not None:
        # Display file info
        st.markdown("### 📁 File Information")
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            temp_path = tmp_file.name
        
        try:
            # Get file info
            file_size = os.path.getsize(temp_path)
            file_info = {
                'file_size': file_size,
                'sha256': sha256_of_file(temp_path),
                'entropy': file_entropy(temp_path),
                'is_pe': is_pe(temp_path)
            }
            
            display_file_info(file_info)
            
            # Analysis button
            if st.button("🔍 Analyze File", type="primary"):
                with st.spinner("Analyzing file... This may take a few moments."):
                    try:
                        # Compile YARA rules
                        rules = compile_yara()
                        
                        # Analyze file
                        results = analyze_file(temp_path, rules)
                        
                        # Display results
                        st.markdown("---")
                        display_detection_results(results)
                        
                        # PE Analysis
                        if results.get('is_pe') and results.get('pe'):
                            st.markdown("---")
                            display_pe_analysis(results['pe'])
                        
                        # String Analysis
                        if results.get('sample_strings'):
                            st.markdown("---")
                            display_strings_analysis(results['sample_strings'])
                        
                        # Raw JSON output (expandable)
                        with st.expander("📄 Raw Analysis Data"):
                            st.json(results)
                        
                        # Download results
                        json_str = json.dumps(results, indent=2)
                        st.download_button(
                            label="📥 Download Analysis Report",
                            data=json_str,
                            file_name=f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                        
                    except yara.Error as e:
                        st.error(f"YARA compilation error: {str(e)}")
                        st.warning("Please ensure YARA is properly installed and accessible.")
                    except pefile.PEFormatError as e:
                        st.error(f"PE file format error: {str(e)}")
                        st.info("The file may be corrupted or not a valid PE file.")
                    except PermissionError as e:
                        st.error(f"Permission error: {str(e)}")
                        st.warning("Please ensure the file is not locked by another process.")
                    except FileNotFoundError as e:
                        st.error(f"File not found: {str(e)}")
                    except Exception as e:
                        st.error(f"Unexpected error during analysis: {str(e)}")
                        with st.expander("Error Details"):
                            st.code(traceback.format_exc())
                        
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>⚠️ <strong>Safety Notice:</strong> This tool performs static analysis only. Do NOT execute suspicious files.</p>
        <p>Built with Streamlit | Metasploit Detector v1.0</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
