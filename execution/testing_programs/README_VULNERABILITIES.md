# Vulnerable Test Programs for Security Analysis

This directory contains intentionally vulnerable programs for testing security analysis tools.

> ⚠️ **WARNING**: These programs contain REAL vulnerabilities. Do NOT use in production!
> They are designed for testing security scanners, static analysis tools, and educational purposes only.

## Single Vulnerability Programs

| File | Language | Vulnerabilities | CWE |
|------|----------|-----------------|-----|
| `vuln_buffer_overflow.c` | C | Stack buffer overflow (strcpy, gets, sprintf) | CWE-121 |
| `vuln_format_string.c` | C | Format string attacks (printf user input) | CWE-134 |
| `vuln_sql_injection.py` | Python | SQL injection (string concatenation in queries) | CWE-89 |
| `vuln_command_injection.py` | Python | OS command injection (os.system, subprocess) | CWE-78 |
| `vuln_use_after_free.c` | C | Use-after-free, double-free | CWE-416 |
| `vuln_integer_overflow.c` | C | Integer overflow/underflow, type truncation | CWE-190/191 |
| `vuln_path_traversal.py` | Python | Directory traversal (../ in paths) | CWE-22 |
| `vuln_hardcoded_secrets.py` | Python | Hardcoded credentials, weak crypto | CWE-798 |
| `vuln_heap_overflow.c` | C | Heap buffer overflow, off-by-one | CWE-122 |
| `vuln_race_condition.c` | C | TOCTOU race conditions | CWE-367 |
| `vuln_deserialization.py` | Python | Insecure deserialization (pickle, yaml) | CWE-502 |

## Multi-Vulnerability Programs (Combined)

| File | Language | Vulnerabilities | CWEs |
|------|----------|-----------------|------|
| `vuln_multi_memory_corruption.c` | C | Buffer overflow + Format string + Integer overflow + UAF | CWE-121, 134, 190, 416 |
| `vuln_multi_injection.py` | Python | SQLi + Command injection + Path traversal + Code injection | CWE-89, 78, 22, 94 |
| `vuln_crypto_weak.c` | C | Weak crypto + Hardcoded keys + Info disclosure + Weak PRNG | CWE-327, 328, 330, 200 |
| `vuln_web_multi.py` | Python | XSS + SSRF + XXE + Open redirect + IDOR | CWE-79, 918, 611, 601, 639 |

## Obfuscated Vulnerability Programs

| File | Language | Obfuscation Techniques |
|------|----------|------------------------|
| `vuln_obfuscated_c.c` | C | Macro hiding, indirect calls, encoded strings, opaque predicates, control flow obfuscation |
| `vuln_obfuscated_py.py` | Python | Dynamic imports, base64 encoding, lambda chains, reflection, code generation |

## Usage Examples

### C Programs

```bash
# Compile with debugging symbols and no protections (for testing)
gcc -g -fno-stack-protector -z execstack -o vuln_bof vuln_buffer_overflow.c

# Run buffer overflow demo
./vuln_bof $(python3 -c "print('A'*100)")

# Run format string demo
./vuln_format_string '%x.%x.%x.%x'

# Run multi-vulnerability demo
./vuln_multi_memory_corruption chain "$(python3 -c 'print(\"A\"*100)')" '%x%x%x' 0x40000001
```

### Python Programs

```bash
# SQL Injection
python3 vuln_sql_injection.py login "' OR '1'='1' --" anything

# Command Injection
python3 vuln_command_injection.py ping "8.8.8.8; id; cat /etc/passwd"

# Path Traversal
python3 vuln_path_traversal.py read "../../../etc/passwd"

# Deserialization
python3 vuln_deserialization.py generate "id"
python3 vuln_deserialization.py pickle "<base64_payload>"

# Multi-injection chain
python3 vuln_multi_injection.py chain "' OR '1'='1' --" "../../../etc/passwd" "{{__import__('os').system('id')}}"
```

### Obfuscated Programs

```bash
# C obfuscated command injection
./vuln_obfuscated_c indirect "id"

# Python obfuscated eval
python3 vuln_obfuscated_py.py calc "__import__('os').system('whoami')"
```

## Vulnerability Categories

### Memory Corruption
- Buffer overflows (stack/heap)
- Use-after-free
- Double-free
- Integer overflow leading to small allocations
- Off-by-one errors

### Injection
- SQL injection
- Command/OS injection
- Code injection (eval/exec)
- Format string injection
- XXE (XML External Entity)

### Authentication/Crypto
- Hardcoded credentials
- Weak hashing (MD5, unsalted)
- Weak encryption (XOR, Caesar, Base64)
- Predictable random numbers
- Timing side-channels

### Web Security
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Open Redirect
- Insecure Direct Object Reference (IDOR)

### File/Path
- Path traversal
- Race conditions (TOCTOU)
- Insecure temporary files

### Serialization
- Pickle deserialization
- YAML deserialization
- Unsafe JSON parsing (eval)

## Testing Security Tools

These programs are useful for testing:

1. **Static Analysis Tools** (SAST)
   - Semgrep, CodeQL, Bandit, Flawfinder
   
2. **Dynamic Analysis** (DAST)
   - Fuzzing with AFL, libFuzzer
   - Web scanners (for Python web vulns)

3. **Binary Analysis**
   - Ghidra, IDA Pro, Binary Ninja
   - Symbolic execution (angr, KLEE)

4. **Vulnerability Scanners**
   - Snyk, SonarQube, Checkmarx

## Contributing

When adding new test cases:
1. Document the specific CWE/CVE pattern
2. Include clear exploit examples
3. Add both obvious and obfuscated variants
4. Update this README

