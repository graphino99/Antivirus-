# 🛡️ Metasploit/Meterpreter Detector

A comprehensive static malware analysis tool designed to detect Metasploit/Meterpreter payloads in executable files. This project includes both a command-line interface and a modern web-based Streamlit frontend.

## 🚀 Features

### Core Detection Capabilities
- **YARA Rule Matching**: Detects Metasploit-specific strings and patterns
- **PE File Analysis**: Extracts imports, exports, sections, and metadata
- **Entropy Analysis**: Identifies potentially packed/encrypted files
- **String Analysis**: Extracts and analyzes ASCII strings for suspicious keywords
- **Scoring System**: Combines multiple indicators to generate a detection score (0-100)

### Detection Patterns
- Meterpreter payloads
- Reverse shell connections (HTTP/HTTPS/TCP)
- Shikata Ga Nai encoding
- Reflective DLL loading
- Suspicious API imports
- Packer/encoder signatures
- High entropy sections

## 📁 Project Structure

```
ABHI_CAP/
├── analyzer_metasploit_detector.py    # Core analysis engine
├── streamlit_app.py                   # Web frontend
├── requirements.txt                   # Python dependencies
├── README.md                         # This file
├── test.py                          # Original notebook code
└── Untitled51.ipynb                 # Jupyter notebook
```

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step 1: Clone or Download
```bash
# If using git
git clone <repository-url>
cd ABHI_CAP

# Or simply download the files to a directory
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Verify Installation
```bash
python analyzer_metasploit_detector.py --help
```

## 🖥️ Usage

### Web Interface (Recommended)

1. **Start the Streamlit app**:
   ```bash
   streamlit run streamlit_app.py
   ```

2. **Open your browser** and navigate to `http://localhost:8501`

3. **Upload an executable file** using the file uploader

4. **Click "Analyze File"** to start the analysis

5. **View results** including:
   - Detection verdict and score
   - YARA rule matches
   - PE file analysis
   - String analysis
   - Downloadable JSON report

### Command Line Interface

#### Analyze a single file:
```bash
python analyzer_metasploit_detector.py /path/to/suspicious_file.exe
```

#### Analyze a directory recursively:
```bash
python analyzer_metasploit_detector.py /path/to/samples/
```

#### Analyze multiple files/directories:
```bash
python analyzer_metasploit_detector.py file1.exe /path/to/dir1 file2.exe
```

### Output
- Individual JSON reports for each file in `reports/` directory
- Summary report in `reports/summary.json`
- Detection verdicts: `highly_likely_metasploit`, `possible_metasploit`, or `unlikely_metasploit`

## 📊 Detection Scoring

The tool uses a weighted scoring system:

| Indicator | Weight | Description |
|-----------|--------|-------------|
| YARA Match | 50 | Direct YARA rule matches |
| Keywords | 25 | Suspicious string patterns |
| High Entropy | 10 | Packed/encrypted content |
| Suspicious Imports | 20 | Malicious API usage |
| Suspicious Sections | 15 | Unusual PE sections |
| Packer Strings | 20 | Known packer signatures |

### Score Interpretation
- **0-39**: Unlikely Metasploit
- **40-69**: Possible Metasploit
- **70-100**: Highly Likely Metasploit

## 🔧 Configuration

### Adjusting Detection Sensitivity
Edit the `WEIGHTS` dictionary in `analyzer_metasploit_detector.py`:

```python
WEIGHTS = {
    "yara_match": 50,        # Increase for stricter YARA matching
    "keyword": 25,           # Adjust keyword sensitivity
    "high_entropy": 10,      # Entropy threshold weight
    "suspicious_imports": 20, # API import sensitivity
    "suspicious_sections": 15, # PE section analysis
    "packer_strings": 20     # Packer detection weight
}
```

### Entropy Threshold
```python
ENTROPY_HIGH = 7.5  # Adjust for entropy sensitivity
```

## 🚨 Safety Notice

⚠️ **IMPORTANT**: This tool performs **static analysis only**. 

- **DO NOT** execute suspicious files
- **DO NOT** run in production environments without proper isolation
- Always use in a secure, isolated environment
- Consider using virtual machines for analysis

## 🐛 Troubleshooting

### Common Issues

1. **YARA compilation error**:
   ```bash
   # Install YARA system library first
   # Ubuntu/Debian:
   sudo apt-get install yara
   
   # Windows: Download from https://github.com/VirusTotal/yara/releases
   ```

2. **PE file analysis errors**:
   - Ensure the file is a valid PE executable
   - Check file permissions
   - Verify file is not corrupted

3. **Streamlit not starting**:
   ```bash
   # Check if port 8501 is available
   # Or specify a different port:
   streamlit run streamlit_app.py --server.port 8502
   ```

### Dependencies Issues

If you encounter issues with `python-magic` on Windows:
```bash
pip install python-magic-bin
```

## 📈 Performance

- **File Size Limit**: Recommended < 100MB for web interface
- **Analysis Time**: 1-10 seconds per file depending on size
- **Memory Usage**: ~50-200MB depending on file complexity

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational and defensive security purposes only.

## ⚠️ Disclaimer

This tool is designed for legitimate security research and malware analysis. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## 🔗 Related Tools

- [YARA](https://github.com/VirusTotal/yara) - Pattern matching engine
- [pefile](https://github.com/erocarrera/pefile) - PE file analysis
- [Streamlit](https://streamlit.io/) - Web application framework

---

**Built with ❤️ for the security community**
