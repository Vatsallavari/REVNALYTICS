"""
Prompt Manager
Loads and manages prompts from ai_agent_prompts directory
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional


# Get the project root directory (parent of backend)
BACKEND_DIR = Path(__file__).parent
PROJECT_ROOT = BACKEND_DIR.parent
PROMPTS_DIR = PROJECT_ROOT / "ai_agent_prompts"


def load_merged_prompt() -> str:
    """
    Load the merged prompt from ai_agent_prompts/merged_prompt.txt
    This single file contains all system instructions and analysis templates.
    
    Returns:
        Merged prompt string, or default if file not found
    """
    merged_path = PROMPTS_DIR / "merged_prompt.txt"
    
    if merged_path.exists():
        try:
            with open(merged_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            print(f"[!] Error reading merged prompt: {e}")
    
    # Fallback default prompt
    return """You are a cybersecurity expert specializing in malware analysis.
Analyze the binary data and respond with JSON containing:
- explanation: What the binary does
- key_behaviors: List of behaviors
- security_concerns: List of concerns
- vulnerable_functions: List of exploitable functions with function_name, vulnerability_type, severity, description, dangerous_calls
- safety_assessment: verdict (SAFE/SUSPICIOUS/MALICIOUS), confidence (HIGH/MEDIUM/LOW), reason"""


def get_system_prompt() -> str:
    """
    Load system prompt - now uses merged prompt file.
    
    Returns:
        System prompt string
    """
    return load_merged_prompt()


def load_analysis_prompt_template() -> str:
    """
    Load analysis prompt template - now uses merged prompt file.
    
    Returns:
        Prompt template string
    """
    return load_merged_prompt()


def format_imports_summary(imports: list, max_imports: int = 20) -> str:
    """Format imports list into a readable summary"""
    if not imports:
        return "- No imports detected"
    
    summary = ""
    for imp in imports[:max_imports]:
        lib_name = imp.get("library", "Unknown")
        symbols = imp.get("symbols", [])
        if symbols:
            summary += f"- {lib_name}: {', '.join(symbols[:10])}\n"
        else:
            summary += f"- {lib_name}\n"
    
    if len(imports) > max_imports:
        summary += f"- ... and {len(imports) - max_imports} more libraries\n"
    
    return summary.strip()


def format_functions_summary(functions: list, max_functions: int = 15) -> str:
    """
    Format functions with ASSEMBLY and DECOMPILED CODE for reverse engineering analysis.
    The AI needs to see actual instructions to analyze properly.
    """
    if not functions:
        return "No functions detected"
    
    # Filter to user-defined functions (skip library stubs)
    user_funcs = [f for f in functions if not f.get("is_thunk", False) 
                  and not f.get("is_external", False)
                  and not f.get("name", "").startswith("_")]
    
    if not user_funcs:
        user_funcs = functions  # Fallback to all if filter removes everything
    
    summary = f"Total: {len(functions)} functions ({len(user_funcs)} user-defined)\n"
    summary += "="*60 + "\n"
    
    for func in user_funcs[:max_functions]:
        func_name = func.get("name", "Unknown")
        entry_point = func.get("entry_point", "")
        signature = func.get("signature", "")
        calls = func.get("calls", [])
        decompiled = func.get("decompiled_code", "")
        asm_preview = func.get("assembly_preview", [])
        
        summary += f"\n### {func_name} @ {entry_point}\n"
        summary += f"Signature: {signature}\n"
        
        if calls:
            summary += f"Calls: {', '.join(calls[:10])}\n"
        
        # Include decompiled code (truncated)
        if decompiled:
            decompiled_lines = decompiled.strip().split('\n')[:20]
            summary += "\nDecompiled:\n```c\n"
            summary += '\n'.join(decompiled_lines)
            if len(decompiled.strip().split('\n')) > 20:
                summary += "\n... (truncated)"
            summary += "\n```\n"
        
        # Include assembly (critical for RE analysis)
        if asm_preview:
            summary += "\nAssembly:\n```asm\n"
            for asm in asm_preview[:30]:
                addr = asm.get("address", "")
                instr = asm.get("operands", asm.get("mnemonic", ""))
                summary += f"{addr}  {instr}\n"
            if len(asm_preview) > 30:
                summary += f"... ({len(asm_preview) - 30} more instructions)\n"
            summary += "```\n"
        
        summary += "-"*40 + "\n"
    
    if len(user_funcs) > max_functions:
        summary += f"\n... and {len(user_funcs) - max_functions} more user functions"
    
    return summary.strip()


def format_risk_indicators_summary(functions: list, max_risks: int = 20) -> str:
    """Extract and format risk indicators from functions"""
    risk_indicators = []
    
    for func in functions:
        risks = func.get("risk_indicators", [])
        if risks:
            risk_indicators.extend(risks)
    
    if not risk_indicators:
        return "No obvious risk indicators detected"
    
    summary = ""
    for risk in risk_indicators[:max_risks]:
        risk_type = risk.get("type", "unknown")
        severity = risk.get("severity", "unknown")
        summary += f"- {risk_type} (severity: {severity})\n"
    
    if len(risk_indicators) > max_risks:
        summary += f"- ... and {len(risk_indicators) - max_risks} more risk indicators"
    
    return summary.strip()


def format_strings_summary(strings: list, max_strings: int = 20) -> str:
    """Format strings list into a readable summary"""
    if not strings:
        return "No strings detected"
    
    summary = ""
    for string_info in strings[:max_strings]:
        string_val = string_info.get("value", "")[:100]  # Truncate long strings
        summary += f"- {string_val}\n"
    
    if len(strings) > max_strings:
        summary += f"- ... and {len(strings) - max_strings} more strings"
    
    return summary.strip()


def get_enhanced_system_prompt() -> str:
    """
    Load the merged system prompt from merged_prompt.txt.
    All instructions are in a single file for easier maintenance.
    
    Returns:
        Complete system prompt string with all instructions
    """
    prompt = load_merged_prompt()
    
    # Replace placeholders with generic descriptions since this goes in system prompt
    prompt = prompt.replace("{binary_name}", "[BINARY_NAME]")
    prompt = prompt.replace("{architecture}", "[ARCHITECTURE]")
    prompt = prompt.replace("{function_count}", "[FUNCTION_COUNT]")
    prompt = prompt.replace("{imports_summary}", "[IMPORTS_DATA]")
    prompt = prompt.replace("{functions_summary}", "[FUNCTIONS_DATA]")
    prompt = prompt.replace("{risk_indicators_summary}", "[RISK_INDICATORS_DATA]")
    prompt = prompt.replace("{strings_summary}", "[STRINGS_DATA]")
    
    return prompt


def create_minimal_ghidra_prompt(ghidra_data: Dict[str, Any]) -> str:
    """
    Create MINIMAL prompt with ONLY Ghidra data (no template text).
    All instructions are in the system prompt.
    
    Args:
        ghidra_data: Dictionary containing Ghidra analysis results
    
    Returns:
        Minimal prompt string with only Ghidra data (no instructions)
    """
    # Extract key information from Ghidra data
    binary_name = ghidra_data.get("binary_name", "Unknown")
    architecture = ghidra_data.get("architecture", "Unknown")
    functions = ghidra_data.get("functions", [])
    imports = ghidra_data.get("imports", [])
    strings = ghidra_data.get("strings", [])
    
    # Format summaries (ONLY DATA, no instructions)
    imports_summary = format_imports_summary(imports)
    functions_summary = format_functions_summary(functions)
    risk_indicators_summary = format_risk_indicators_summary(functions)
    strings_summary = format_strings_summary(strings)
    
    # Create MINIMAL prompt - just the data with minimal structure
    prompt = f"""BINARY INFORMATION:
- File Name: {binary_name}
- Architecture: {architecture}
- Total Functions: {len(functions)}

IMPORTED LIBRARIES:
{imports_summary}

FUNCTIONS ANALYSIS:
{functions_summary}

RISK INDICATORS:
{risk_indicators_summary}

INTERESTING STRINGS:
{strings_summary}"""
    
    return prompt


def create_analysis_prompt(ghidra_data: Dict[str, Any]) -> str:
    """
    Create a prompt for the AI agent based on Ghidra analysis.
    Loads template from file and fills it with Ghidra data.
    
    NOTE: This is the OLD method. Consider using create_minimal_ghidra_prompt() instead
    for better cost efficiency (only data counts as characters).
    
    Args:
        ghidra_data: Dictionary containing Ghidra analysis results
    
    Returns:
        Formatted prompt string ready for LLM
    """
    # Load template from file
    template = load_analysis_prompt_template()
    
    # Extract key information from Ghidra data
    binary_name = ghidra_data.get("binary_name", "Unknown")
    architecture = ghidra_data.get("architecture", "Unknown")
    functions = ghidra_data.get("functions", [])
    imports = ghidra_data.get("imports", [])
    strings = ghidra_data.get("strings", [])
    
    # Format summaries
    imports_summary = format_imports_summary(imports)
    functions_summary = format_functions_summary(functions)
    risk_indicators_summary = format_risk_indicators_summary(functions)
    strings_summary = format_strings_summary(strings)
    
    # Fill template with data
    prompt = template.format(
        binary_name=binary_name,
        architecture=architecture,
        function_count=len(functions),
        imports_summary=imports_summary,
        functions_summary=functions_summary,
        risk_indicators_summary=risk_indicators_summary,
        strings_summary=strings_summary
    )
    
    return prompt

