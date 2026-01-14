#!/usr/bin/env python3
"""
Vulnerable Program: Command Injection / OS Command Injection
CVE Pattern: CWE-78 (OS Command Injection)
Similar to: CVE-2021-44228 (Log4Shell), CVE-2014-6271 (Shellshock)

Vulnerability: User input passed to shell commands without sanitization
allows arbitrary command execution on the system.
"""

import os
import sys
import subprocess

# VULNERABLE: os.system with user input
def ping_host_vulnerable(hostname):
    """
    VULNERABLE PING FUNCTION
    Exploit: hostname = "8.8.8.8; cat /etc/passwd"
             hostname = "8.8.8.8 && whoami"
             hostname = "$(whoami)"
    """
    # VULNERABLE: Direct string concatenation to shell command
    command = "ping -c 1 " + hostname
    print(f"[DEBUG] Executing: {command}")
    os.system(command)


# VULNERABLE: subprocess with shell=True
def dns_lookup_vulnerable(domain):
    """
    VULNERABLE DNS LOOKUP
    Exploit: domain = "google.com; id; cat /etc/shadow"
             domain = "`id`"
    """
    # VULNERABLE: shell=True with user input
    command = f"nslookup {domain}"
    print(f"[DEBUG] Executing: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(f"Errors: {result.stderr}")


# VULNERABLE: Backtick/command substitution in f-string
def check_file_vulnerable(filename):
    """
    VULNERABLE FILE CHECK
    Exploit: filename = "test.txt; rm -rf /tmp/*"
             filename = "$(cat /etc/passwd)"
    """
    # VULNERABLE: User input in shell command
    command = f"ls -la {filename} 2>/dev/null && file {filename}"
    print(f"[DEBUG] Executing: {command}")
    os.system(command)


# VULNERABLE: eval() with user input (code injection)
def calculate_vulnerable(expression):
    """
    VULNERABLE CALCULATOR
    Exploit: expression = "__import__('os').system('id')"
             expression = "open('/etc/passwd').read()"
    """
    # VULNERABLE: eval with user input
    print(f"[DEBUG] Evaluating: {expression}")
    try:
        result = eval(expression)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")


# VULNERABLE: exec() with user input
def run_code_vulnerable(code):
    """
    VULNERABLE CODE RUNNER
    Exploit: code = "import os; os.system('whoami')"
    """
    # VULNERABLE: exec with user input
    print(f"[DEBUG] Executing code: {code}")
    exec(code)


# VULNERABLE: Popen with shell interpolation
def grep_logs_vulnerable(pattern, logfile="/var/log/syslog"):
    """
    VULNERABLE LOG SEARCH
    Exploit: pattern = "error; cat /etc/passwd #"
    """
    # VULNERABLE: Pattern not escaped
    command = f"grep '{pattern}' {logfile}"
    print(f"[DEBUG] Executing: {command}")
    os.popen(command).read()


def main():
    print("=" * 50)
    print("Command Injection Vulnerability Demo")
    print("=" * 50)
    
    if len(sys.argv) < 3:
        print(f"\nUsage: {sys.argv[0]} <action> <param>")
        print("\nActions:")
        print("  ping <hostname>      - Vulnerable ping")
        print("  dns <domain>         - Vulnerable DNS lookup")
        print("  file <filename>      - Vulnerable file check")
        print("  calc <expression>    - Vulnerable calculator (eval)")
        print("  exec <code>          - Vulnerable code exec")
        print("\nExploit Examples:")
        print("  ./vuln_command_injection.py ping '8.8.8.8; id'")
        print("  ./vuln_command_injection.py calc '__import__(\"os\").system(\"id\")'")
        print("  ./vuln_command_injection.py dns 'google.com && cat /etc/passwd'")
        return
    
    action = sys.argv[1]
    param = sys.argv[2]
    
    if action == "ping":
        ping_host_vulnerable(param)
    elif action == "dns":
        dns_lookup_vulnerable(param)
    elif action == "file":
        check_file_vulnerable(param)
    elif action == "calc":
        calculate_vulnerable(param)
    elif action == "exec":
        run_code_vulnerable(param)
    else:
        print(f"Unknown action: {action}")


if __name__ == "__main__":
    main()

