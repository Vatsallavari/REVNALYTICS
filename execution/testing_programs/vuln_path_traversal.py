#!/usr/bin/env python3
"""
Vulnerable Program: Path Traversal / Directory Traversal
CVE Pattern: CWE-22 (Path Traversal)
Similar to: CVE-2021-41773 (Apache), CVE-2019-11043 (PHP-FPM)

Vulnerability: User-controlled file paths allow reading/writing
arbitrary files outside intended directory.
"""

import os
import sys

# Simulated web application root
WEB_ROOT = "/tmp/webapp"
UPLOAD_DIR = "/tmp/webapp/uploads"

def setup_environment():
    """Create test environment"""
    os.makedirs(WEB_ROOT, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    # Create some test files
    with open(os.path.join(WEB_ROOT, "index.html"), "w") as f:
        f.write("<html><body>Welcome!</body></html>")
    
    with open(os.path.join(WEB_ROOT, "config.php"), "w") as f:
        f.write("<?php $db_password = 'secret123'; ?>")
    
    with open(os.path.join(UPLOAD_DIR, "user_file.txt"), "w") as f:
        f.write("User uploaded content")


# VULNERABLE: No path validation
def read_file_vulnerable(filename):
    """
    VULNERABLE FILE READ
    Exploit: filename = "../../../etc/passwd"
             filename = "....//....//....//etc/passwd"
             filename = "/etc/passwd"
    """
    # VULNERABLE: Direct path concatenation without validation
    filepath = os.path.join(WEB_ROOT, filename)
    
    print(f"[DEBUG] Attempting to read: {filepath}")
    
    try:
        with open(filepath, "r") as f:
            content = f.read()
            print(f"[+] File contents:\n{content}")
            return content
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return None


# VULNERABLE: Insufficient path validation
def read_file_weak_validation(filename):
    """
    VULNERABLE - Weak blacklist validation
    Exploit: filename = "..././..././etc/passwd"
             filename = "..%2f..%2f..%2fetc/passwd" (URL encoded)
             filename = "....//....//etc/passwd"
    """
    # Weak attempt at filtering (can be bypassed)
    if "../" in filename:
        print("[-] Path traversal detected!")
        return None
    
    # VULNERABLE: Only checks for "../" but not other variants
    filepath = os.path.join(WEB_ROOT, filename)
    
    print(f"[DEBUG] Attempting to read: {filepath}")
    
    try:
        with open(filepath, "r") as f:
            return f.read()
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


# VULNERABLE: File upload with traversal
def upload_file_vulnerable(filename, content):
    """
    VULNERABLE FILE UPLOAD
    Exploit: filename = "../../../tmp/malicious.sh"
             filename = "../../cron.d/backdoor"
    """
    # VULNERABLE: No validation on filename
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    print(f"[DEBUG] Uploading to: {filepath}")
    
    try:
        # Create parent directories if traversal path used
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, "w") as f:
            f.write(content)
        print(f"[+] File uploaded successfully: {filepath}")
        return True
    except Exception as e:
        print(f"[-] Upload failed: {e}")
        return False


# VULNERABLE: File deletion with traversal
def delete_file_vulnerable(filename):
    """
    VULNERABLE FILE DELETE
    Exploit: filename = "../../../important_file"
    """
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    print(f"[DEBUG] Deleting: {filepath}")
    
    try:
        os.remove(filepath)
        print(f"[+] File deleted: {filepath}")
        return True
    except Exception as e:
        print(f"[-] Delete failed: {e}")
        return False


# VULNERABLE: Include/template injection
def render_template_vulnerable(template_name):
    """
    VULNERABLE TEMPLATE INCLUDE
    Exploit: template_name = "../../../etc/passwd"
    """
    template_dir = os.path.join(WEB_ROOT, "templates")
    os.makedirs(template_dir, exist_ok=True)
    
    # VULNERABLE: Path traversal in template include
    template_path = os.path.join(template_dir, template_name)
    
    print(f"[DEBUG] Rendering template: {template_path}")
    
    try:
        with open(template_path, "r") as f:
            return f.read()
    except Exception as e:
        print(f"[-] Template error: {e}")
        return None


# VULNERABLE: Zip extraction (Zip Slip)
def extract_zip_vulnerable(zip_content, entry_name):
    """
    VULNERABLE ZIP EXTRACTION (Zip Slip)
    A malicious zip file with entries like:
    "../../../../../../tmp/malicious.sh"
    can write files outside extraction directory
    """
    extract_dir = "/tmp/extracted"
    
    # VULNERABLE: No validation on entry name
    output_path = os.path.join(extract_dir, entry_name)
    
    print(f"[DEBUG] Extracting to: {output_path}")
    
    # In real scenario, this would extract file content
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(zip_content)
    
    print(f"[+] Extracted: {output_path}")


def main():
    setup_environment()
    
    print("=" * 50)
    print("Path Traversal Vulnerability Demo")
    print("=" * 50)
    
    if len(sys.argv) < 3:
        print(f"\nUsage: {sys.argv[0]} <action> <path>")
        print("\nActions:")
        print("  read <filename>           - Vulnerable file read")
        print("  weak <filename>           - Weak validation bypass")
        print("  upload <filename> <data>  - Vulnerable upload")
        print("  delete <filename>         - Vulnerable delete")
        print("  template <name>           - Vulnerable template")
        print("\nExploit Examples:")
        print(f"  {sys.argv[0]} read '../../../etc/passwd'")
        print(f"  {sys.argv[0]} weak '....//....//....//etc/passwd'")
        print(f"  {sys.argv[0]} upload '../../../tmp/evil.sh' '#!/bin/bash\\nid'")
        return
    
    action = sys.argv[1]
    path = sys.argv[2]
    
    if action == "read":
        read_file_vulnerable(path)
    elif action == "weak":
        content = read_file_weak_validation(path)
        if content:
            print(f"[+] Content:\n{content}")
    elif action == "upload" and len(sys.argv) >= 4:
        upload_file_vulnerable(path, sys.argv[3])
    elif action == "delete":
        delete_file_vulnerable(path)
    elif action == "template":
        render_template_vulnerable(path)
    else:
        print("Invalid action or missing parameters")


if __name__ == "__main__":
    main()

