#!/usr/bin/env python3
"""
Hashcat Integration Script for Password Security Project
This script automates the extraction and cracking workflow
"""

import os
import subprocess
import sys
from pathlib import Path

def check_hashcat():
    """Check if hashcat is installed"""
    hashcat_paths = [
        Path("hashcat-6.2.6/hashcat.exe"),
        Path("C:/Program Files/hashcat/hashcat.exe"),
        Path("C:/Program Files (x86)/hashcat/hashcat.exe"),
    ]
    
    for path in hashcat_paths:
        if path.exists():
            return str(path)
    
    return None

def extract_hashes():
    """Extract hashes from vulnerable database"""
    print("\n" + "="*70)
    print("STEP 1: Extract Hashes from Database")
    print("="*70)
    
    try:
        result = subprocess.run(
            [sys.executable, "exploits/extract_hashes.py"],
            capture_output=False
        )
        if result.returncode == 0:
            print("✓ Hashes extracted successfully!")
            return True
        else:
            print("✗ Failed to extract hashes")
            return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def run_python_brute_force():
    """Run Python-based brute force (no external dependencies)"""
    print("\n" + "="*70)
    print("STEP 2: Run Python Brute Force Attack")
    print("="*70)
    
    try:
        result = subprocess.run(
            [sys.executable, "exploits/brute_force.py"],
            capture_output=False
        )
        return result.returncode == 0
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def run_hashcat(wordlist="rockyou.txt"):
    """Run hashcat attack"""
    print("\n" + "="*70)
    print("STEP 2: Run Hashcat Attack")
    print("="*70)
    
    hashcat_path = check_hashcat()
    
    if not hashcat_path:
        print("✗ Hashcat not found!")
        print("\nTo install Hashcat:")
        print("1. Download from: https://hashcat.net/hashcat/")
        print("2. Extract to: hashcat-6.2.6/")
        print("3. Or use: choco install hashcat")
        print("\nFalling back to Python brute force...")
        return run_python_brute_force()
    
    # Check if hashes file exists
    if not Path("exploits/hashes.txt").exists():
        print("✗ Hashes file not found! Run extract first.")
        return False
    
    # Check if wordlist exists
    if not Path(wordlist).exists():
        print(f"✗ Wordlist {wordlist} not found!")
        print("\nTo download rockyou.txt:")
        print("wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
        print("\nUsing Python brute force instead...")
        return run_python_brute_force()
    
    # Run hashcat
    cmd = [
        hashcat_path,
        "-m", "0",          # MD5
        "-a", "0",          # Wordlist mode
        "-o", "exploits/cracked_hashes.txt",
        "exploits/hashes.txt",
        wordlist
    ]
    
    try:
        print(f"\nCommand: {' '.join(cmd)}\n")
        result = subprocess.run(cmd, capture_output=False)
        return result.returncode == 0
    except Exception as e:
        print(f"✗ Error running hashcat: {e}")
        return False

def main():
    """Main workflow"""
    print("\n" + "="*70)
    print("PASSWORD SECURITY PROJECT - ATTACK WORKFLOW")
    print("="*70)
    
    # Step 1: Extract hashes
    if not extract_hashes():
        sys.exit(1)
    
    # Step 2: Run attack
    print("\n" + "="*70)
    print("SELECT ATTACK METHOD")
    print("="*70)
    print("1. Python Brute Force (no dependencies needed)")
    print("2. Hashcat (faster, requires installation)")
    
    choice = input("\nSelect (1 or 2) [default=1]: ").strip() or "1"
    
    if choice == "2":
        success = run_hashcat()
    else:
        success = run_python_brute_force()
    
    # Summary
    print("\n" + "="*70)
    if success:
        print("ATTACK COMPLETED SUCCESSFULLY!")
        print("="*70)
        print("\nResults location:")
        if choice == "2":
            print("- Hashcat: exploits/cracked_hashes.txt")
        else:
            print("- Python: exploits/cracked_passwords.txt")
    else:
        print("ATTACK FAILED!")
        print("="*70)
        sys.exit(1)

if __name__ == "__main__":
    main()
