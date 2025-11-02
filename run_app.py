#!/usr/bin/env python3
"""
Startup script for Metasploit Detector Streamlit App

This script checks dependencies and starts the Streamlit application.
"""

import subprocess
import sys
import os

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = [
        'streamlit', 'yara', 'pefile', 'magic', 'requests', 'tqdm'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'yara':
                import yara
            elif package == 'magic':
                import magic
            else:
                __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n📦 Install missing packages with:")
        print("   pip install -r requirements.txt")
        return False
    
    print("✅ All required packages are installed")
    return True

def main():
    """Main startup function"""
    print("🛡️ Metasploit Detector - Starting Application")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists('analyzer_metasploit_detector.py'):
        print("❌ Error: analyzer_metasploit_detector.py not found")
        print("   Please run this script from the project directory")
        sys.exit(1)
    
    if not os.path.exists('streamlit_app.py'):
        print("❌ Error: streamlit_app.py not found")
        print("   Please run this script from the project directory")
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    print("\n🚀 Starting Streamlit application...")
    print("   The app will open in your default browser")
    print("   Press Ctrl+C to stop the application")
    print("=" * 50)
    
    try:
        # Start Streamlit
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run', 'streamlit_app.py',
            '--server.headless', 'false',
            '--server.runOnSave', 'true'
        ])
    except KeyboardInterrupt:
        print("\n\n👋 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
