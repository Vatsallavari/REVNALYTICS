"""
AI Agent Integration
Takes Ghidra analysis output and generates simple explanations and safety assessments
Supports multiple LLM providers with fallback: OpenAI -> Perplexity -> DeepSeek -> Mistral -> Hugging Face -> Basic
"""
import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from backend directory and project root
load_dotenv(Path(__file__).parent / ".env")  # backend/.env
load_dotenv(Path(__file__).parent.parent / ".env")  # project root .env
from typing import Dict, Any, Optional
import httpx
from prompt_manager import (
    get_system_prompt, 
    create_analysis_prompt,
    get_enhanced_system_prompt,
    create_minimal_ghidra_prompt
)

# Try to import OpenAI
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

# Try to import Mistral AI
try:
    from mistralai import Mistral
    MISTRAL_AVAILABLE = True
except ImportError:
    MISTRAL_AVAILABLE = False


# Initialize clients
openai_client = None
perplexity_client = None
mistral_client = None


def get_openai_client():
    """Initialize OpenAI client if API key is available"""
    global openai_client
    if openai_client is None and OPENAI_AVAILABLE:
        api_key = os.environ.get("OPENAI_API_KEY")
        if api_key:
            try:
                openai_client = OpenAI(api_key=api_key)
                print("[*] OpenAI client initialized")
            except Exception as e:
                print(f"[!] Failed to initialize OpenAI client: {e}")
                openai_client = False
        else:
            print("[!] Warning: OPENAI_API_KEY not set.")
            openai_client = False
    return openai_client if openai_client else None


def get_perplexity_client():
    """Initialize Perplexity AI client if API key is available (OpenAI-compatible)"""
    global perplexity_client
    if perplexity_client is None and OPENAI_AVAILABLE:
        api_key = os.environ.get("PERPLEXITY_API_KEY")
        if api_key:
            try:
                perplexity_client = OpenAI(
                    api_key=api_key,
                    base_url="https://api.perplexity.ai"
                )
                print("[*] Perplexity AI client initialized")
            except Exception as e:
                print(f"[!] Failed to initialize Perplexity client: {e}")
                perplexity_client = False
        else:
            print("[!] Warning: PERPLEXITY_API_KEY not set.")
            perplexity_client = False
    return perplexity_client if perplexity_client else None


def get_mistral_client():
    """Initialize Mistral AI client if API key is available"""
    global mistral_client
    if mistral_client is None and MISTRAL_AVAILABLE:
        api_key = os.environ.get("MISTRAL_API_KEY")
        if api_key:
            try:
                mistral_client = Mistral(api_key=api_key)
                print("[*] Mistral AI client initialized")
            except Exception as e:
                print(f"[!] Failed to initialize Mistral client: {e}")
                mistral_client = False
        else:
            print("[!] Warning: MISTRAL_API_KEY not set.")
            mistral_client = False
    return mistral_client if mistral_client else None


# Note: create_analysis_prompt is now imported from prompt_manager


def parse_ai_response(ai_response: str) -> Dict[str, Any]:
    """Parse AI response and extract JSON with new reverse_leverage format"""
    try:
        # Extract JSON if wrapped in markdown code blocks
        if "```json" in ai_response:
            json_start = ai_response.find("```json") + 7
            json_end = ai_response.find("```", json_start)
            ai_response = ai_response[json_start:json_end].strip()
        elif "```" in ai_response:
            json_start = ai_response.find("```") + 3
            json_end = ai_response.find("```", json_start)
            ai_response = ai_response[json_start:json_end].strip()
        
        result = json.loads(ai_response)
        
        # Handle new format with reverse_leverage
        return {
            "summary": result.get("summary", result.get("explanation", ai_response)),
            "function_count": result.get("function_count", 0),
            "call_flow": result.get("call_flow", ""),
            "reverse_leverage": result.get("reverse_leverage", []),
            "not_interesting": result.get("not_interesting", []),
            "recommended_focus": result.get("recommended_focus", ""),
            # Keep old fields for backward compatibility
            "explanation": result.get("summary", result.get("explanation", ai_response)),
            "safety_assessment": result.get("safety_assessment", {
                "verdict": "REVIEW NEEDED",
                "confidence": "MEDIUM",
                "reason": "See reverse_leverage for analysis"
            }),
            "key_behaviors": result.get("key_behaviors", []),
            "security_concerns": result.get("security_concerns", []),
            "vulnerable_functions": result.get("vulnerable_functions", [])
        }
    except json.JSONDecodeError:
        # If JSON parsing fails, return the raw response
        return {
            "summary": ai_response,
            "explanation": ai_response,
            "reverse_leverage": [],
            "not_interesting": [],
            "recommended_focus": "",
            "safety_assessment": {
                "verdict": "UNKNOWN",
                "confidence": "LOW",
                "reason": "AI response could not be parsed"
            },
            "key_behaviors": [],
            "security_concerns": [],
            "vulnerable_functions": []
        }
            

async def call_openai(prompt: str, system_prompt: str) -> Optional[str]:
    """Call OpenAI API
    
    Args:
        prompt: User prompt with Ghidra analysis data
        system_prompt: System prompt loaded from file
    """
    client = get_openai_client()
    if not client:
        return None
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=1500
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[!] OpenAI API error: {str(e)}")
        return None


async def call_perplexity(prompt: str, system_prompt: str) -> Optional[str]:
    """Call Perplexity AI API (OpenAI-compatible)
    
    Args:
        prompt: User prompt with Ghidra analysis data
        system_prompt: System prompt loaded from file
    """
    client = get_perplexity_client()
    if not client:
        return None
    
    try:
        response = client.chat.completions.create(
            model="sonar-pro",  # or "sonar" for faster/cheaper
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=1500
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[!] Perplexity API error: {str(e)}")
        return None


async def call_deepseek(prompt: str, system_prompt: str) -> Optional[str]:
    """Call DeepSeek AI API
    
    Args:
        prompt: User prompt with Ghidra analysis data
        system_prompt: System prompt loaded from file
    """
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        return None
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                "https://api.deepseek.com/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {
                            "role": "system",
                            "content": system_prompt
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.3,
                    "max_tokens": 1500
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                if "choices" in result and len(result["choices"]) > 0:
                    return result["choices"][0]["message"]["content"]
            else:
                print(f"[!] DeepSeek API error: {response.status_code} - {response.text}")
                return None
    except Exception as e:
        print(f"[!] DeepSeek API error: {str(e)}")
        return None


async def call_mistral(prompt: str, system_prompt: str) -> Optional[str]:
    """Call Mistral AI API
    
    Args:
        prompt: User prompt with Ghidra analysis data
        system_prompt: System prompt loaded from file
    """
    client = get_mistral_client()
    if not client:
        return None
    
    try:
        # Mistral AI uses chat.complete() method
        response = client.chat.complete(
            model="mistral-medium-latest",  # or "mistral-small-latest" for faster/cheaper
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=1500
        )
        # Access the response content
        if hasattr(response, 'choices') and len(response.choices) > 0:
            return response.choices[0].message.content
        return None
    except Exception as e:
        print(f"[!] Mistral API error: {str(e)}")
        return None


async def call_huggingface(prompt: str, system_prompt: str) -> Optional[str]:
    """Call Hugging Face Inference API (server-based, no download needed)
    
    Args:
        prompt: User prompt with Ghidra analysis data
        system_prompt: System prompt loaded from file
    """
    api_key = os.environ.get("HUGGINGFACE_API_KEY")
    if not api_key:
        return None
    
    # Using a good open-source model for analysis
    # meta-llama/Meta-Llama-3-8B-Instruct or mistralai/Mistral-7B-Instruct-v0.2
    model = "mistralai/Mistral-7B-Instruct-v0.2"
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            # Use the new router endpoint instead of deprecated api-inference
            response = await client.post(
                f"https://router.huggingface.co/models/{model}",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "inputs": f"<s>[INST] {system_prompt}\n\n{prompt} [/INST]",
                    "parameters": {
                        "temperature": 0.3,
                        "max_new_tokens": 1500,
                        "return_full_text": False
                    }
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                # Handle different response formats from Hugging Face
                if isinstance(result, list) and len(result) > 0:
                    # Some models return a list with dict containing generated_text
                    text = result[0].get("generated_text", "")
                    if text:
                        return text
                elif isinstance(result, dict):
                    # Some models return dict directly
                    text = result.get("generated_text", "")
                    if text:
                        return text
                # If no generated_text, try to extract from any text field
                if isinstance(result, str):
                    return result
            elif response.status_code == 503:
                # Model is loading, would need to wait
                print(f"[!] Hugging Face model is loading, please wait...")
                return None
            else:
                print(f"[!] Hugging Face API error: {response.status_code} - {response.text}")
                return None
    except Exception as e:
        print(f"[!] Hugging Face API error: {str(e)}")
        return None


def check_available_apis() -> Dict[str, bool]:
    """
    Check which API keys are available.
    This is called before loading prompts to determine which LLMs can be used.
    
    Returns:
        Dictionary with API availability status
    """
    available = {
        "openai": bool(os.environ.get("OPENAI_API_KEY") and OPENAI_AVAILABLE),
        "perplexity": bool(os.environ.get("PERPLEXITY_API_KEY") and OPENAI_AVAILABLE),
        "deepseek": bool(os.environ.get("DEEPSEEK_API_KEY")),
        "mistral": bool(os.environ.get("MISTRAL_API_KEY") and MISTRAL_AVAILABLE),
        "huggingface": bool(os.environ.get("HUGGINGFACE_API_KEY"))
    }
    return available


async def analyze_with_ai(ghidra_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze Ghidra output using AI with fallback chain.
    Flow: Load prompts from files -> Check API keys -> Try LLMs in order
    
    Fallback order: OpenAI -> Perplexity -> DeepSeek -> Mistral -> Hugging Face -> Basic
    
    Args:
        ghidra_data: Dictionary containing Ghidra analysis results
    
    Returns:
        Dict with 'explanation' and 'safety_assessment'
    """
    # Step 1: Load prompts from files first
    print("[*] Loading prompts from ai_agent_prompts directory...")
    
    # Use enhanced system prompt (includes all template instructions)
    system_prompt = get_enhanced_system_prompt()
    
    # Create minimal user prompt (ONLY Ghidra data, no template)
    user_prompt = create_minimal_ghidra_prompt(ghidra_data)
    
    print(f"[*] System prompt loaded ({len(system_prompt)} chars - instructions)")
    print(f"[*] User prompt created ({len(user_prompt)} chars - Ghidra data only)")
    print(f"[*] Only {len(user_prompt)} chars count as user message (template excluded)")
    
    # Step 2: Check which API keys are available
    print("[*] Checking available API keys...")
    available_apis = check_available_apis()
    
    if not any(available_apis.values()):
        print("[!] No API keys found. Using basic fallback analysis.")
        return get_fallback_analysis(ghidra_data)
    
    # Step 3: Try each LLM in order (only if API key is available)
    ai_response = None
    
    # Try OpenAI first
    if available_apis["openai"]:
        print("[*] Trying OpenAI...")
        ai_response = await call_openai(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from OpenAI")
            return parse_ai_response(ai_response)
        print("[!] OpenAI call failed")
    
    # Try Perplexity second
    if available_apis["perplexity"]:
        print("[*] OpenAI failed, trying Perplexity AI...")
        ai_response = await call_perplexity(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from Perplexity AI")
            return parse_ai_response(ai_response)
        print("[!] Perplexity call failed")
    
    # Try DeepSeek third
    if available_apis["deepseek"]:
        print("[*] Perplexity failed, trying DeepSeek...")
        ai_response = await call_deepseek(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from DeepSeek")
            return parse_ai_response(ai_response)
        print("[!] DeepSeek call failed")
    
    # Try Mistral fourth
    if available_apis["mistral"]:
        print("[*] DeepSeek failed, trying Mistral AI...")
        ai_response = await call_mistral(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from Mistral AI")
            return parse_ai_response(ai_response)
        print("[!] Mistral call failed")
    
    # Try Hugging Face fifth
    if available_apis["huggingface"]:
        print("[*] Mistral failed, trying Hugging Face...")
        ai_response = await call_huggingface(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from Hugging Face")
            return parse_ai_response(ai_response)
        print("[!] Hugging Face call failed")
    
    # Fallback to basic analysis
    print("[*] All AI providers failed, using basic fallback analysis")
    return get_fallback_analysis(ghidra_data)


async def analyze_source_with_ai(source_code: str, file_name: str, language: str) -> Dict[str, Any]:
    """
    Analyze source code directly with AI (no Ghidra needed).
    
    Args:
        source_code: The source code content
        file_name: Name of the source file
        language: Programming language
    
    Returns:
        Dict with analysis results
    """
    # Build source code analysis prompt
    system_prompt = """You are an expert security researcher and reverse engineer analyzing source code.

YOUR JOB:
Identify security vulnerabilities, dangerous patterns, and reverse engineering leverage points in the code.

LOOK FOR:
1. Buffer overflows (strcpy, sprintf, gets, etc.)
2. Format string vulnerabilities (printf with user input)
3. Command injection (system, popen, exec with user input)
4. SQL injection (string concatenation in queries)
5. Integer overflows affecting buffer sizes
6. Use-after-free patterns
7. Race conditions
8. Weak cryptography (hardcoded keys, weak algorithms)
9. Path traversal
10. Information disclosure
11. Logic bugs that can be exploited
12. Interesting comparison/validation routines (CTF-style)

RESPOND WITH JSON:
{
  "summary": "Brief description of what this code does and overall security posture",
  "reverse_leverage": [
    {
      "function_name": "function or section name",
      "leverage_type": "Buffer Overflow|Format String|Command Injection|etc.",
      "cwe": "CWE-XXX",
      "why_interesting": "Explanation of the vulnerability or interesting pattern",
      "code_evidence": ["line1", "line2", "...relevant code lines..."],
      "reverse_strategy": "How to exploit or leverage this"
    }
  ],
  "recommended_focus": "Which function/area to focus on first and why"
}

RULES:
1. Every finding MUST include code_evidence - actual lines from the source
2. Be specific about WHY something is vulnerable
3. Include CWE numbers where applicable
4. Prioritize findings by severity
5. For CTF-style code, identify comparison gates and solvable constraints
6. If the code looks safe, say so - don't invent vulnerabilities"""

    user_prompt = f"""Analyze this {language} source code for security vulnerabilities and reverse engineering leverage points.

FILE: {file_name}
LANGUAGE: {language}

SOURCE CODE:
```{language.lower()}
{source_code}
```

Identify all vulnerabilities, dangerous patterns, and interesting targets for reverse engineering."""

    print("[*] Checking available API keys for source analysis...")
    available_apis = check_available_apis()
    
    if not any(available_apis.values()):
        print("[!] No API keys found. Source code analysis requires AI.")
        return get_source_fallback_analysis(source_code, file_name, language)
    
    ai_response = None
    
    # Try each LLM in order
    if available_apis["openai"]:
        print("[*] Trying OpenAI for source analysis...")
        ai_response = await call_openai(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from OpenAI")
            return parse_ai_response(ai_response)
        print("[!] OpenAI call failed")
    
    if available_apis["perplexity"]:
        print("[*] Trying Perplexity for source analysis...")
        ai_response = await call_perplexity(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from Perplexity AI")
            return parse_ai_response(ai_response)
        print("[!] Perplexity call failed")
    
    if available_apis["deepseek"]:
        print("[*] Trying DeepSeek for source analysis...")
        ai_response = await call_deepseek(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from DeepSeek")
            return parse_ai_response(ai_response)
        print("[!] DeepSeek call failed")
    
    if available_apis["mistral"]:
        print("[*] Trying Mistral for source analysis...")
        ai_response = await call_mistral(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from Mistral AI")
            return parse_ai_response(ai_response)
        print("[!] Mistral call failed")
    
    if available_apis["huggingface"]:
        print("[*] Trying Hugging Face for source analysis...")
        ai_response = await call_huggingface(user_prompt, system_prompt)
        if ai_response:
            print("[*] Successfully got response from Hugging Face")
            return parse_ai_response(ai_response)
        print("[!] Hugging Face call failed")
    
    print("[*] All AI providers failed, using basic pattern analysis")
    return get_source_fallback_analysis(source_code, file_name, language)


def get_source_fallback_analysis(source_code: str, file_name: str, language: str) -> Dict[str, Any]:
    """
    Basic pattern-based analysis for source code when AI is unavailable.
    """
    leverage_points = []
    lines = source_code.splitlines()
    
    # Dangerous C/C++ patterns
    dangerous_c_patterns = {
        "gets(": ("Buffer Overflow", "CWE-120", "gets() has no bounds checking - always vulnerable"),
        "strcpy(": ("Potential Buffer Overflow", "CWE-120", "strcpy() has no bounds checking"),
        "strcat(": ("Potential Buffer Overflow", "CWE-120", "strcat() has no bounds checking"),
        "sprintf(": ("Potential Buffer Overflow", "CWE-120", "sprintf() has no bounds checking"),
        "scanf(\"%s\"": ("Buffer Overflow", "CWE-120", "scanf %s has no bounds checking"),
        "system(": ("Command Injection Risk", "CWE-78", "system() can execute arbitrary commands"),
        "popen(": ("Command Injection Risk", "CWE-78", "popen() can execute arbitrary commands"),
        "exec": ("Command Execution", "CWE-78", "exec functions execute external programs"),
    }
    
    # Format string patterns
    format_string_patterns = [
        (r'printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', "Format String", "CWE-134", "printf with variable as format string"),
        (r'fprintf\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', "Format String", "CWE-134", "fprintf with variable as format string"),
    ]
    
    # Python patterns
    dangerous_py_patterns = {
        "eval(": ("Code Injection", "CWE-94", "eval() executes arbitrary code"),
        "exec(": ("Code Injection", "CWE-94", "exec() executes arbitrary code"),
        "os.system(": ("Command Injection", "CWE-78", "os.system() executes shell commands"),
        "subprocess.call(": ("Command Injection Risk", "CWE-78", "subprocess with shell=True is dangerous"),
        "pickle.loads(": ("Deserialization", "CWE-502", "pickle.loads() can execute arbitrary code"),
        "__import__(": ("Dynamic Import", "CWE-94", "Dynamic imports can load malicious modules"),
    }
    
    # Scan for patterns
    for i, line in enumerate(lines, 1):
        # Check C patterns
        if language in ['C', 'C++', 'C Header', 'C++ Header']:
            for pattern, (vuln_type, cwe, desc) in dangerous_c_patterns.items():
                if pattern in line:
                    leverage_points.append({
                        "function_name": f"Line {i}",
                        "leverage_type": vuln_type,
                        "cwe": cwe,
                        "why_interesting": desc,
                        "code_evidence": [line.strip()],
                        "reverse_strategy": f"Check if user input reaches {pattern}"
                    })
        
        # Check Python patterns
        if language == 'Python':
            for pattern, (vuln_type, cwe, desc) in dangerous_py_patterns.items():
                if pattern in line:
                    leverage_points.append({
                        "function_name": f"Line {i}",
                        "leverage_type": vuln_type,
                        "cwe": cwe,
                        "why_interesting": desc,
                        "code_evidence": [line.strip()],
                        "reverse_strategy": f"Check if user input reaches {pattern}"
                    })
    
    summary = f"""Source Code Analysis (Pattern-Based - No AI)
File: {file_name}
Language: {language}
Lines: {len(lines)}
Potential Issues Found: {len(leverage_points)}

NOTE: This is basic pattern matching. AI analysis provides deeper semantic understanding."""
    
    recommended = ""
    if leverage_points:
        first = leverage_points[0]
        recommended = f"Review {first['function_name']} - {first['leverage_type']}"
    else:
        recommended = "No obvious patterns detected. Manual review recommended."
    
    return {
        "summary": summary,
        "reverse_leverage": leverage_points,
        "not_interesting": [],
        "recommended_focus": recommended,
        "explanation": summary,
        "safety_assessment": {
            "verdict": "REVIEW NEEDED" if leverage_points else "UNKNOWN",
            "confidence": "LOW",
            "reason": f"Pattern-based analysis found {len(leverage_points)} potential issues"
        }
    }


def detect_reverse_leverage(functions: list) -> tuple:
    """
    Detect REVERSE ENGINEERING LEVERAGE points in functions.
    
    This is NOT just vulnerability detection. It finds:
    1. Arithmetic constraints (solvable equations)
    2. Comparison gates (memcmp, strcmp, byte checks)
    3. Environment gates (anti-debug, time checks)
    4. State machines (loops, counters, flags)
    5. Crash leverage (traditional vulnerabilities)
    6. Crypto/encoding leverage (XOR, base64, weak crypto)
    7. Input handlers (where data enters)
    
    Returns:
        tuple: (leverage_points, not_interesting)
    """
    
    # Library/system functions - not interesting for leverage analysis
    library_functions = {
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf",
        "scanf", "fscanf", "sscanf", "vscanf", "strcpy", "strncpy", "strcat", "strncat",
        "strlen", "strcmp", "strncmp", "memcpy", "memmove", "memset", "memcmp",
        "malloc", "calloc", "realloc", "free", "fopen", "fclose", "fread", "fwrite",
        "fgets", "fputs", "open", "close", "read", "write", "gets", "puts",
        "atoi", "atol", "atof", "strtol", "strtoul", "rand", "srand", "random",
        "system", "popen", "pclose", "exit", "abort", "atexit",
        "fork", "wait", "waitpid", "pipe", "dup", "dup2",
    }
    
    skip_prefixes = [
        "_RTC_", "__RTC_", "__scrt_", "__stdio_", "__security_", "__crt_",
        "_CRT_", "__CRT_", "__acrt_", "__vcrt_", "__ucrt_", "_init", "_fini",
        "_start", "__libc_", "thunk_", "_thunk_", "__do_global", "__cxa_",
        "__gxx_", "deregister_tm", "register_tm", "frame_dummy", "__isoc",
    ]
    
    def is_library_function(name: str) -> bool:
        if name in library_functions:
            return True
        for prefix in skip_prefixes:
            if name.startswith(prefix):
                return True
        return False
    
    def is_user_function(name: str) -> bool:
        if is_library_function(name):
            return False
        if name.startswith("FUN_") or name.startswith("sub_"):
            return True
        if not name.startswith("_") and not name.startswith("."):
            return True
        return False
    
    leverage_points = []
    not_interesting = []
    seen = set()
    
    for func in functions:
        func_name = func.get("name", "unknown")
        
        if not is_user_function(func_name):
            continue
        if func_name in seen:
            continue
        seen.add(func_name)
        
        entry_point = func.get("entry_point", "")
        called_funcs = func.get("calls", [])
        risk_indicators = func.get("risk_indicators", [])
        asm_preview = func.get("assembly_preview", [])
        
        found_leverage = False
        
        # ===== CATEGORY 1: ARITHMETIC LEVERAGE =====
        # Look for IMUL, XOR, ADD, SUB chains followed by CMP
        arithmetic_ops = []
        cmp_found = False
        for asm in asm_preview:
            mnem = asm.get("mnemonic", "").upper()
            if mnem in ["IMUL", "MUL", "XOR", "ADD", "SUB", "ROL", "ROR", "SHL", "SHR"]:
                arithmetic_ops.append(asm)
            if mnem == "CMP":
                cmp_found = True
        
        if len(arithmetic_ops) >= 2 and cmp_found:
            asm_evidence = [f"{a.get('address', '')}  {a.get('operands', '')}" for a in arithmetic_ops[:5]]
            leverage_points.append({
                "function_name": func_name,
                "address": entry_point,
                "leverage_type": "Arithmetic Constraint",
                "why_interesting": f"Contains {len(arithmetic_ops)} arithmetic operations followed by comparison",
                "assembly_evidence": asm_evidence,
                "reverse_strategy": "Trace arithmetic chain, solve equation to find valid input"
            })
            found_leverage = True
        
        # ===== CATEGORY 2: COMPARISON GATE =====
        # Look for strcmp, memcmp, or byte-by-byte comparisons
        comparison_funcs = {"strcmp", "strncmp", "memcmp", "wcscmp", "stricmp", "_stricmp"}
        for called in called_funcs:
            if called in comparison_funcs:
                leverage_points.append({
                    "function_name": func_name,
                    "address": entry_point,
                    "leverage_type": "Comparison Gate",
                    "why_interesting": f"Calls {called} - input compared against reference value",
                    "assembly_evidence": [],
                    "reverse_strategy": f"Find {called} arguments, extract reference or patch conditional jump"
                })
                found_leverage = True
                break
        
        # Also check for REPE CMPSB pattern
        for asm in asm_preview:
            if "CMPS" in asm.get("mnemonic", "").upper() or "SCAS" in asm.get("mnemonic", "").upper():
                leverage_points.append({
                    "function_name": func_name,
                    "address": entry_point,
                    "leverage_type": "Comparison Gate",
                    "why_interesting": "Byte-by-byte comparison loop detected",
                    "assembly_evidence": [f"{asm.get('address', '')}  {asm.get('operands', '')}"],
                    "reverse_strategy": "This is likely key/password validation. Extract compared bytes or patch."
                })
                found_leverage = True
                break
        
        # ===== CATEGORY 3: ENVIRONMENT GATE =====
        env_funcs = {"time", "gettimeofday", "clock", "getpid", "getenv", "access", "stat",
                     "ptrace", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}
        for called in called_funcs:
            if called in env_funcs:
                leverage_points.append({
                    "function_name": func_name,
                    "address": entry_point,
                    "leverage_type": "Environment Gate",
                    "why_interesting": f"Calls {called} - behavior depends on runtime environment",
                    "assembly_evidence": [],
                    "reverse_strategy": f"Identify {called} check, bypass via patching or environment manipulation"
                })
                found_leverage = True
                break
        
        # ===== CATEGORY 4: INPUT HANDLER =====
        input_funcs = {"read", "recv", "fgets", "fread", "scanf", "gets", "getchar", "getline",
                       "ReadFile", "WSARecv", "InternetReadFile"}
        for called in called_funcs:
            if called in input_funcs:
                leverage_points.append({
                    "function_name": func_name,
                    "address": entry_point,
                    "leverage_type": "Input Handler",
                    "why_interesting": f"Calls {called} - primary input vector",
                    "assembly_evidence": [],
                    "reverse_strategy": "Trace data flow from input to interesting operations"
                })
                found_leverage = True
                break
        
        # ===== CATEGORY 5: CRASH LEVERAGE (from Ghidra risk_indicators) =====
        for risk in risk_indicators:
            risk_type = risk.get("type", "")
            
            if risk_type in ["divide_by_zero", "indirect_call", "memory_write", "syscall"]:
                context = risk.get("context", [])
                asm_context = [f"{ctx.get('address', '')}  {ctx.get('instruction', '')}" for ctx in context]
                
                leverage_points.append({
                    "function_name": func_name,
                    "address": risk.get("address", entry_point),
                    "leverage_type": "Crash Leverage",
                    "vulnerability_type": risk_type.replace("_", " ").title(),
                    "cwe": risk.get("cwe", ""),
                    "why_interesting": risk.get("issue", ""),
                    "assembly_evidence": asm_context,
                    "reverse_strategy": risk.get("impact", "Controllable crash - potential DoS or exploitation")
                })
                found_leverage = True
        
        # ===== CATEGORY 6: CRYPTO/ENCODING =====
        crypto_funcs = {"rand", "srand", "random", "CryptGenRandom", "CryptEncrypt", "CryptDecrypt"}
        for called in called_funcs:
            if called in crypto_funcs:
                leverage_points.append({
                    "function_name": func_name,
                    "address": entry_point,
                    "leverage_type": "Crypto Leverage",
                    "why_interesting": f"Uses {called} - potential weak randomness or crypto operation",
                    "assembly_evidence": [],
                    "reverse_strategy": f"Analyze {called} usage - weak seeding or predictable values?"
                })
                found_leverage = True
                break
        
        # Check for XOR loops (common in CTF crypto)
        xor_count = sum(1 for a in asm_preview if a.get("mnemonic", "").upper() == "XOR")
        if xor_count >= 3:
            leverage_points.append({
                "function_name": func_name,
                "address": entry_point,
                "leverage_type": "Crypto Leverage",
                "why_interesting": f"Contains {xor_count} XOR instructions - possible encoding/encryption",
                "assembly_evidence": [f"{a.get('address', '')}  {a.get('operands', '')}" 
                                     for a in asm_preview if a.get("mnemonic", "").upper() == "XOR"][:5],
                "reverse_strategy": "Extract XOR key from constants or derive from known plaintext"
            })
            found_leverage = True
        
        # If no leverage found, mark as not interesting
        if not found_leverage:
            not_interesting.append(f"{func_name} - no obvious leverage points")
    
    return leverage_points, not_interesting


def get_fallback_analysis(ghidra_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fallback analysis when AI is not available.
    
    Detects REVERSE ENGINEERING LEVERAGE points:
    - Arithmetic constraints
    - Comparison gates
    - Environment gates
    - Crash leverage
    - Crypto/encoding
    - Input handlers
    
    This is pattern-based detection - AI provides deeper analysis.
    """
    functions = ghidra_data.get("functions", [])
    imports = ghidra_data.get("imports", [])
    strings = ghidra_data.get("strings", [])
    entry_points = ghidra_data.get("entry_points", [])
    binary_name = ghidra_data.get("binary_name", "Unknown")
    architecture = ghidra_data.get("architecture", "Unknown")
    
    # Detect reverse engineering leverage points
    reverse_leverage, not_interesting = detect_reverse_leverage(functions)
    
    # Count user-defined functions
    user_funcs = len([f for f in functions if not f.get("is_thunk") and not f.get("is_external")])
    
    # Build summary
    summary = f"""Binary: {binary_name}
Architecture: {architecture}
Functions: {len(functions)} total ({user_funcs} user-defined)
Imports: {len(imports)} libraries
Strings: {len(strings)}

Leverage Points Found: {len(reverse_leverage)}
Not Interesting: {len(not_interesting)}

NOTE: This is pattern-based analysis WITHOUT AI. For deeper semantic analysis, AI is required."""
    
    # Determine recommended focus
    recommended_focus = ""
    if reverse_leverage:
        # Prioritize crash leverage, then arithmetic, then comparison
        priority_order = ["Crash Leverage", "Arithmetic Constraint", "Comparison Gate", "Crypto Leverage", "Environment Gate", "Input Handler"]
        for leverage_type in priority_order:
            for lev in reverse_leverage:
                if lev.get("leverage_type") == leverage_type:
                    recommended_focus = f"Start with {lev['function_name']} ({leverage_type}) - {lev.get('why_interesting', '')[:50]}"
                    break
            if recommended_focus:
                break
    
    if not recommended_focus and reverse_leverage:
        first = reverse_leverage[0]
        recommended_focus = f"Examine {first['function_name']} - {first.get('why_interesting', 'potential leverage point')[:50]}"
    elif not recommended_focus:
        recommended_focus = "No obvious leverage points detected. Manual analysis recommended."
    
    return {
        "summary": summary,
        "function_count": len(functions),
        "call_flow": "",  # Would need call graph analysis
        "reverse_leverage": reverse_leverage,
        "not_interesting": not_interesting[:20],  # Limit to avoid clutter
        "recommended_focus": recommended_focus,
        # Keep old fields for backward compatibility
        "explanation": summary,
        "safety_assessment": {
            "verdict": "REVIEW NEEDED" if reverse_leverage else "UNKNOWN",
            "confidence": "MEDIUM" if reverse_leverage else "LOW",
            "reason": f"Found {len(reverse_leverage)} leverage point(s) for reverse engineering"
        },
        "key_behaviors": [f"{len(functions)} functions", f"{len(reverse_leverage)} leverage points"],
        "security_concerns": [lev.get("why_interesting", "") for lev in reverse_leverage[:5]],
        "vulnerable_functions": []  # Deprecated - use reverse_leverage
    }
