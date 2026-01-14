#!/usr/bin/env python3
"""
Vulnerable Program: Hardcoded Credentials & Sensitive Data Exposure
CVE Pattern: CWE-798 (Hardcoded Credentials), CWE-200 (Information Exposure)
Similar to: CVE-2019-10149 (Exim), CVE-2021-43798 (Grafana)

Vulnerability: Sensitive credentials hardcoded in source code,
exposing them to anyone with access to the binary/source.
"""

import hashlib
import base64
import os
import sys

# ============================================
# VULNERABLE: Hardcoded credentials
# ============================================

# VULNERABLE: Plain text passwords
DATABASE_HOST = "prod-db.internal.company.com"
DATABASE_USER = "admin"
DATABASE_PASSWORD = "SuperSecretP@ssw0rd123!"  # CWE-798
DATABASE_NAME = "production_data"

# VULNERABLE: API keys in source
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # CWE-798
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # CWE-798
STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"  # CWE-798
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # CWE-798

# VULNERABLE: Encryption keys in source
AES_ENCRYPTION_KEY = "ThisIsA32ByteKeyForAES256Encry!"  # CWE-321
JWT_SECRET = "my-super-secret-jwt-signing-key-12345"  # CWE-798
ADMIN_API_KEY = "admin-api-key-do-not-share-12345"  # CWE-798

# VULNERABLE: SSH/Private keys embedded
SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHD
TYW7hdI4yZ448MN8OvZrHpXvaKVc/qJrAoONqoOK/TQ5Hh7ZElLMlJb8rNczrHlC
R9wIu9vZE3V8RHD/mHPmQqCEF0wnUnstnhkpHosEtGFoC9HhqYgKQKPCW5lS6HhS
o5Jp+Hj9hFhKoqijaoMPQ5rVAqkRNqN1EvxW5pLklNlP3Mj0gYSYJd6aZ6EXAMPLE
-----END RSA PRIVATE KEY-----"""

# VULNERABLE: Backdoor credentials
BACKDOOR_USERNAME = "maintenance_admin"
BACKDOOR_PASSWORD = "M@int3n@nc3!"

# ============================================
# VULNERABLE: Weak cryptography
# ============================================

def hash_password_weak(password):
    """
    VULNERABLE: Using MD5 for password hashing
    CVE Pattern: CWE-328 (Reversible One-Way Hash)
    """
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_unsalted(password):
    """
    VULNERABLE: SHA256 without salt
    CVE Pattern: CWE-916 (Use of Password Hash Without Salt)
    """
    # VULNERABLE: No salt makes rainbow table attacks possible
    return hashlib.sha256(password.encode()).hexdigest()


# VULNERABLE: Predictable encryption
def encrypt_data_weak(data):
    """
    VULNERABLE: Base64 is not encryption
    CVE Pattern: CWE-327 (Use of Broken Crypto Algorithm)
    """
    # VULNERABLE: Base64 is encoding, not encryption
    return base64.b64encode(data.encode()).decode()


def decrypt_data_weak(encoded):
    """VULNERABLE: Base64 decoding masquerading as decryption"""
    return base64.b64decode(encoded).decode()


# ============================================
# VULNERABLE: Authentication bypass
# ============================================

def authenticate_user(username, password):
    """
    VULNERABLE: Multiple authentication issues
    """
    # VULNERABLE: Backdoor account check
    if username == BACKDOOR_USERNAME and password == BACKDOOR_PASSWORD:
        print("[!] Backdoor access granted!")
        return True
    
    # VULNERABLE: Hardcoded admin credentials
    if username == "admin" and password == "admin123":
        print("[!] Default admin credentials used!")
        return True
    
    # VULNERABLE: Debug mode bypass
    if os.environ.get("DEBUG_AUTH") == "1":
        print("[!] Debug authentication bypass!")
        return True
    
    # VULNERABLE: Compare against hardcoded hash (still bad)
    stored_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 of "password"
    if hash_password_weak(password) == stored_hash:
        return True
    
    return False


def check_api_key(provided_key):
    """
    VULNERABLE: API key comparison issues
    """
    # VULNERABLE: Hardcoded API key comparison
    if provided_key == ADMIN_API_KEY:
        return True
    
    # VULNERABLE: Timing attack possible with == comparison
    # Should use constant-time comparison
    return provided_key == "user-api-key-12345"


# ============================================
# VULNERABLE: Information disclosure
# ============================================

def get_debug_info():
    """
    VULNERABLE: Exposes sensitive configuration
    CVE Pattern: CWE-200 (Information Exposure)
    """
    # VULNERABLE: Returns sensitive data
    return {
        "database_host": DATABASE_HOST,
        "database_user": DATABASE_USER,
        "database_password": DATABASE_PASSWORD,
        "aws_key": AWS_ACCESS_KEY,
        "encryption_key": AES_ENCRYPTION_KEY,
        "internal_ips": ["10.0.0.5", "10.0.0.6", "192.168.1.100"],
        "version": "2.3.1-internal",
    }


def handle_error(error):
    """
    VULNERABLE: Verbose error messages
    CVE Pattern: CWE-209 (Error Information Leak)
    """
    # VULNERABLE: Exposes stack trace and internal info
    return f"""
    Error occurred: {error}
    Database: {DATABASE_HOST}
    User: {DATABASE_USER}
    Query: SELECT * FROM users WHERE password = '{DATABASE_PASSWORD}'
    Internal Path: /var/www/internal/app
    """


def main():
    print("=" * 50)
    print("Hardcoded Credentials & Secrets Demo")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print(f"\nUsage: {sys.argv[0]} <action>")
        print("\nActions:")
        print("  show        - Display hardcoded secrets")
        print("  auth <u> <p> - Test authentication")
        print("  hash <pwd>  - Hash password (weak)")
        print("  debug       - Show debug info leak")
        print("\nExploit Examples:")
        print(f"  {sys.argv[0]} show")
        print(f"  {sys.argv[0]} auth maintenance_admin 'M@int3n@nc3!'")
        print(f"  {sys.argv[0]} auth admin admin123")
        return
    
    action = sys.argv[1]
    
    if action == "show":
        print("\n[!] EXPOSED SECRETS:")
        print(f"  Database Password: {DATABASE_PASSWORD}")
        print(f"  AWS Access Key: {AWS_ACCESS_KEY}")
        print(f"  AWS Secret Key: {AWS_SECRET_KEY}")
        print(f"  Stripe Key: {STRIPE_SECRET_KEY}")
        print(f"  JWT Secret: {JWT_SECRET}")
        print(f"  Backdoor: {BACKDOOR_USERNAME}:{BACKDOOR_PASSWORD}")
        
    elif action == "auth" and len(sys.argv) >= 4:
        result = authenticate_user(sys.argv[2], sys.argv[3])
        print(f"Authentication result: {'SUCCESS' if result else 'FAILED'}")
        
    elif action == "hash" and len(sys.argv) >= 3:
        password = sys.argv[2]
        print(f"MD5 (weak): {hash_password_weak(password)}")
        print(f"SHA256 (unsalted): {hash_password_unsalted(password)}")
        print(f"Base64 (not encryption!): {encrypt_data_weak(password)}")
        
    elif action == "debug":
        print("\n[!] DEBUG INFO LEAK:")
        for key, value in get_debug_info().items():
            print(f"  {key}: {value}")
    else:
        print("Invalid action")


if __name__ == "__main__":
    main()

