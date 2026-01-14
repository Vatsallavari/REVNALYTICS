#!/usr/bin/env python3
"""
Multi-Vulnerability Program: Combined Injection Attacks
CVE Patterns: CWE-89 + CWE-78 + CWE-22 + CWE-94

Combines:
- SQL Injection
- Command Injection
- Path Traversal
- Code Injection (eval/exec)

Multiple injection vectors in authentication and file management system.
"""

import sqlite3
import os
import sys
import subprocess

DB_FILE = "/tmp/multi_vuln.db"
UPLOAD_DIR = "/tmp/uploads"
LOG_DIR = "/tmp/logs"

def init_system():
    """Initialize database and directories"""
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT,
            email TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            owner TEXT,
            filename TEXT,
            path TEXT
        )
    ''')
    try:
        cursor.execute("INSERT INTO users VALUES (1, 'admin', 'supersecret', 'admin', 'admin@test.com')")
        cursor.execute("INSERT INTO users VALUES (2, 'user1', 'password', 'user', 'user@test.com')")
    except:
        pass
    conn.commit()
    conn.close()


class VulnerableAuthSystem:
    """Authentication system with SQL injection"""
    
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
    
    # ===== VULNERABILITY 1: SQL Injection (CWE-89) =====
    def login(self, username, password):
        """
        VULN: SQL injection in login
        Exploit: username = "' OR '1'='1' --"
        """
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"[SQL] {query}")
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchone()
    
    # ===== VULNERABILITY 2: SQL + Command Injection Chain =====
    def get_user_files(self, username):
        """
        VULN 1: SQL injection to get file paths
        VULN 2: Command injection when listing files
        """
        # SQL Injection
        query = f"SELECT path FROM files WHERE owner='{username}'"
        print(f"[SQL] {query}")
        cursor = self.conn.cursor()
        cursor.execute(query)
        files = cursor.fetchall()
        
        # Command injection - uses SQL results in shell
        for (path,) in files:
            # VULN: Path from DB used in shell command
            cmd = f"ls -la {path}"
            print(f"[CMD] {cmd}")
            os.system(cmd)


class VulnerableFileManager:
    """File manager with path traversal and command injection"""
    
    # ===== VULNERABILITY 3: Path Traversal (CWE-22) =====
    def read_file(self, filename):
        """
        VULN: Path traversal
        Exploit: filename = "../../../etc/passwd"
        """
        filepath = os.path.join(UPLOAD_DIR, filename)
        print(f"[PATH] Reading: {filepath}")
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error: {e}"
    
    # ===== VULNERABILITY 4: Path Traversal + Command Injection =====
    def process_file(self, filename, operation):
        """
        VULN 1: Path traversal in filename
        VULN 2: Command injection in operation
        Exploit: operation = "cat; id; #"
        """
        filepath = os.path.join(UPLOAD_DIR, filename)
        # VULN: Both path and operation are user-controlled
        cmd = f"{operation} {filepath}"
        print(f"[CMD] {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr
    
    # ===== VULNERABILITY 5: Command Injection in Logging =====
    def log_access(self, username, action):
        """
        VULN: Command injection via log filename
        Exploit: username = "test; cat /etc/passwd > /tmp/pwned #"
        """
        log_file = os.path.join(LOG_DIR, f"{username}.log")
        # VULN: username in shell command
        cmd = f"echo '{action}' >> {log_file}"
        print(f"[CMD] {cmd}")
        os.system(cmd)


class VulnerableTemplateEngine:
    """Template engine with code injection"""
    
    # ===== VULNERABILITY 6: Code Injection via eval (CWE-94) =====
    def render_template(self, template, context):
        """
        VULN: eval() on user template expressions
        Exploit: template = "Hello {{__import__('os').system('id')}}"
        """
        import re
        
        def replace_expr(match):
            expr = match.group(1)
            print(f"[EVAL] Evaluating: {expr}")
            # VULN: eval on user-controlled expression
            try:
                return str(eval(expr, {"context": context}))
            except:
                return match.group(0)
        
        # Find {{expression}} and evaluate
        result = re.sub(r'\{\{(.+?)\}\}', replace_expr, template)
        return result
    
    # ===== VULNERABILITY 7: exec() for dynamic code =====
    def run_plugin(self, plugin_code):
        """
        VULN: exec() on user-provided code
        Exploit: plugin_code = "import os; os.system('id')"
        """
        print(f"[EXEC] Running plugin code...")
        # VULN: Direct code execution
        exec(plugin_code)


class VulnerableSearchEngine:
    """Search with combined SQL injection and path traversal"""
    
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
    
    # ===== VULNERABILITY 8: SQL Injection + Path Traversal Chain =====
    def search_and_read(self, search_term, base_path):
        """
        VULN 1: SQL injection in search
        VULN 2: Path traversal when reading results
        """
        # SQL Injection
        query = f"SELECT filename FROM files WHERE filename LIKE '%{search_term}%'"
        print(f"[SQL] {query}")
        cursor = self.conn.cursor()
        cursor.execute(query)
        
        results = []
        for (filename,) in cursor.fetchall():
            # Path traversal - base_path is user controlled
            filepath = os.path.join(base_path, filename)
            print(f"[PATH] Reading: {filepath}")
            try:
                with open(filepath, 'r') as f:
                    results.append(f.read())
            except:
                pass
        return results


def attack_chain_demo(username, filename, template):
    """
    Demonstrates chained attack using multiple vulnerabilities
    """
    print("\n" + "="*50)
    print("ATTACK CHAIN DEMONSTRATION")
    print("="*50)
    
    # Step 1: SQL injection to bypass auth
    auth = VulnerableAuthSystem()
    user = auth.login(username, "anything")
    print(f"\n[1] Auth result: {user}")
    
    # Step 2: Path traversal to read sensitive files
    fm = VulnerableFileManager()
    content = fm.read_file(filename)
    print(f"\n[2] File content:\n{content[:200]}...")
    
    # Step 3: Template injection for code execution
    te = VulnerableTemplateEngine()
    result = te.render_template(template, {"user": user})
    print(f"\n[3] Template result: {result}")


def main():
    init_system()
    
    print("="*50)
    print("Multi-Injection Vulnerability Demo")
    print("="*50)
    
    if len(sys.argv) < 2:
        print(f"\nUsage: {sys.argv[0]} <mode> [args...]")
        print("\nModes:")
        print("  sqli <username> <password>       - SQL injection login")
        print("  path <filename>                  - Path traversal read")
        print("  cmdi <filename> <operation>      - Command injection")
        print("  eval <template>                  - Code injection via eval")
        print("  exec <code>                      - Code injection via exec")
        print("  chain <user> <file> <template>   - Combined attack chain")
        print("\nExploit Examples:")
        print(f"  {sys.argv[0]} sqli \"' OR '1'='1' --\" x")
        print(f"  {sys.argv[0]} path '../../../etc/passwd'")
        print(f"  {sys.argv[0]} cmdi 'test' 'cat /etc/passwd #'")
        print(f"  {sys.argv[0]} eval '{{{{__import__(\"os\").popen(\"id\").read()}}}}'")
        return
    
    mode = sys.argv[1]
    
    if mode == "sqli" and len(sys.argv) >= 4:
        auth = VulnerableAuthSystem()
        result = auth.login(sys.argv[2], sys.argv[3])
        print(f"Login result: {result}")
        
    elif mode == "path" and len(sys.argv) >= 3:
        fm = VulnerableFileManager()
        content = fm.read_file(sys.argv[2])
        print(f"Content:\n{content}")
        
    elif mode == "cmdi" and len(sys.argv) >= 4:
        fm = VulnerableFileManager()
        result = fm.process_file(sys.argv[2], sys.argv[3])
        print(f"Result:\n{result}")
        
    elif mode == "eval" and len(sys.argv) >= 3:
        te = VulnerableTemplateEngine()
        result = te.render_template(sys.argv[2], {})
        print(f"Result: {result}")
        
    elif mode == "exec" and len(sys.argv) >= 3:
        te = VulnerableTemplateEngine()
        te.run_plugin(sys.argv[2])
        
    elif mode == "chain" and len(sys.argv) >= 5:
        attack_chain_demo(sys.argv[2], sys.argv[3], sys.argv[4])


if __name__ == "__main__":
    main()

