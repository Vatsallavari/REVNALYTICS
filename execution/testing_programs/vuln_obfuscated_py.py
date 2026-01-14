#!/usr/bin/env python3
"""
Obfuscated Vulnerability Program (Python)
Contains hidden vulnerabilities using obfuscation techniques:
- Dynamic imports
- String encoding/decoding
- Reflection and getattr
- Lambda obfuscation
- Code generation
- Base64/hex encoding

CVE Patterns: CWE-78, CWE-89, CWE-94, CWE-502
"""

import sys
import base64
import codecs

# ============================================
# OBFUSCATION TECHNIQUE 1: Dynamic imports
# ============================================

def get_module(name):
    """Dynamically import module to hide dangerous imports"""
    return __import__(name)

def get_submodule(parent, child):
    """Get submodule via getattr"""
    mod = get_module(parent)
    return getattr(mod, child)

# Hidden os.system via dynamic import
def _exec_hidden(cmd):
    # Build module name
    m = chr(111) + chr(115)  # "os"
    # Build function name  
    f = chr(115) + chr(121) + chr(115) + chr(116) + chr(101) + chr(109)  # "system"
    
    # HIDDEN VULN: os.system via dynamic access
    os_mod = get_module(m)
    exec_func = getattr(os_mod, f)
    return exec_func(cmd)


# ============================================
# OBFUSCATION TECHNIQUE 2: Encoded payloads
# ============================================

# Base64 encoded dangerous function names
ENCODED_FUNCS = {
    'exec': 'ZXhlYw==',           # exec
    'eval': 'ZXZhbA==',           # eval  
    'system': 'c3lzdGVt',         # system
    'popen': 'cG9wZW4=',          # popen
    'import': 'X19pbXBvcnRfXw=='  # __import__
}

def decode_func_name(key):
    """Decode function name from base64"""
    return base64.b64decode(ENCODED_FUNCS[key]).decode()

def get_builtin(encoded_name):
    """Get builtin function by encoded name"""
    name = base64.b64decode(encoded_name).decode()
    return getattr(__builtins__, name) if hasattr(__builtins__, name) else eval(name)


# Hex-encoded command template
HEX_CMD = "6563686f202770776e656427"  # echo 'pwned'

def run_hex_cmd(hex_cmd):
    """Execute hex-encoded command"""
    cmd = bytes.fromhex(hex_cmd).decode()
    # HIDDEN VULN: Command injection
    return _exec_hidden(cmd)


# ROT13 encoded SQL
def rot13(s):
    return codecs.encode(s, 'rot_13')

def build_query(table, condition):
    """Build SQL query with ROT13 'obfuscation'"""
    # ROT13("FRYRPG * SEBZ") = "SELECT * FROM"
    select = rot13("FRYRPG * SEBZ")
    # HIDDEN VULN: SQL injection - condition is not sanitized
    return f"{select} {table} WHERE {condition}"


# ============================================
# OBFUSCATION TECHNIQUE 3: Lambda chains
# ============================================

# Obfuscated eval via lambda chain
_e = lambda x: eval(x)
_c = lambda f, a: f(a)
_r = lambda s: _c(_e, s)

def evaluate_expression(expr):
    """Evaluate expression via lambda chain"""
    # HIDDEN VULN: eval via lambda
    return _r(expr)


# Obfuscated exec
_x = (lambda: exec).__code__.co_consts  # Get exec
execute = lambda code: eval(compile(code, '<string>', 'exec'))

def run_code(code):
    """Execute code via obfuscated exec"""
    # HIDDEN VULN: Code execution
    execute(code)


# ============================================
# OBFUSCATION TECHNIQUE 4: Reflection
# ============================================

class SafeLookingClass:
    """Class that hides dangerous operations"""
    
    def __init__(self):
        # Build method names at runtime
        self._methods = {
            'process': '_do_' + chr(101) + chr(120) + chr(101) + chr(99),  # _do_exec
            'query': '_do_' + chr(113) + chr(117) + chr(101) + chr(114) + chr(121)  # _do_query
        }
    
    def _do_exec(self, cmd):
        """Hidden command execution"""
        import os
        return os.popen(cmd).read()
    
    def _do_query(self, sql):
        """Hidden SQL execution (simulated)"""
        print(f"[SQL] Executing: {sql}")
        return sql
    
    def dispatch(self, action, data):
        """Dispatch to hidden methods via reflection"""
        if action in self._methods:
            method_name = self._methods[action]
            # HIDDEN VULN: getattr to dangerous methods
            method = getattr(self, method_name)
            return method(data)


# ============================================
# OBFUSCATION TECHNIQUE 5: Code generation
# ============================================

def generate_and_exec(template, **kwargs):
    """Generate code from template and execute"""
    code = template.format(**kwargs)
    # HIDDEN VULN: Dynamic code generation and execution
    exec(code)

# Innocent-looking template
TEMPLATE = """
def process_{name}(data):
    import {module}
    return {module}.{func}(data)

result = process_{name}({arg!r})
print(result)
"""

def run_generated(name, module, func, arg):
    """Run generated code - looks safe, actually dangerous"""
    generate_and_exec(
        TEMPLATE,
        name=name,
        module=module,
        func=func,
        arg=arg
    )


# ============================================
# OBFUSCATION TECHNIQUE 6: Pickle wrapper
# ============================================

def safe_load(data):
    """Innocent-looking data loader"""
    import pickle
    import base64
    
    # HIDDEN VULN: Pickle deserialization
    decoded = base64.b64decode(data)
    return pickle.loads(decoded)

def create_payload(cmd):
    """Create obfuscated pickle payload"""
    import pickle
    import base64
    import os
    
    class Payload:
        def __reduce__(self):
            return (os.system, (cmd,))
    
    return base64.b64encode(pickle.dumps(Payload())).decode()


# ============================================
# OBFUSCATION TECHNIQUE 7: String manipulation
# ============================================

def build_cmd_from_chars(*chars):
    """Build command from individual characters"""
    return ''.join(chr(c) if isinstance(c, int) else c for c in chars)

def exec_from_parts():
    """Build and execute command from parts"""
    # Build "id" command: chr(105) = 'i', chr(100) = 'd'
    cmd = build_cmd_from_chars(105, 100)
    # HIDDEN VULN: Command execution
    _exec_hidden(cmd)


# ============================================
# COMBINED OBFUSCATED ATTACK
# ============================================

def process_request(user_input, action):
    """
    Process request with multiple hidden vulnerabilities
    """
    handler = SafeLookingClass()
    
    if action == "search":
        # HIDDEN SQL injection
        query = build_query("users", f"name='{user_input}'")
        handler.dispatch("query", query)
        
    elif action == "run":
        # HIDDEN command injection
        handler.dispatch("process", user_input)
        
    elif action == "calc":
        # HIDDEN eval injection
        result = evaluate_expression(user_input)
        print(f"Result: {result}")
        
    elif action == "load":
        # HIDDEN pickle deserialization
        data = safe_load(user_input)
        print(f"Loaded: {data}")


def main():
    print("=" * 50)
    print("Obfuscated Vulnerabilities Demo (Python)")
    print("=" * 50)
    
    if len(sys.argv) < 3:
        print(f"\nUsage: {sys.argv[0]} <action> <input>")
        print("\nActions:")
        print("  search <term>     - Hidden SQL injection")
        print("  run <command>     - Hidden command injection")
        print("  calc <expr>       - Hidden eval injection")
        print("  load <b64data>    - Hidden pickle deserialization")
        print("  genpayload <cmd>  - Generate pickle payload")
        print("\nExamples:")
        print(f"  {sys.argv[0]} search \"' OR '1'='1\"")
        print(f"  {sys.argv[0]} run 'id'")
        print(f"  {sys.argv[0]} calc '__import__(\"os\").system(\"id\")'")
        print(f"  {sys.argv[0]} genpayload 'id'")
        return
    
    action = sys.argv[1]
    user_input = sys.argv[2]
    
    if action == "genpayload":
        payload = create_payload(user_input)
        print(f"Payload: {payload}")
        print(f"\nTo execute: {sys.argv[0]} load '{payload}'")
    else:
        process_request(user_input, action)


if __name__ == "__main__":
    main()

