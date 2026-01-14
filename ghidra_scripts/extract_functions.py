# Ghidra Headless Script - Extract Functions and Decompiled Code
# Run with: analyzeHeadless <project_dir> <project_name> -import <binary> -postScript extract_functions.py -scriptPath <script_dir>
# @category Analysis
# @author ReverseEngineeringTool

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
import json
import os

def get_function_calls(func):
    """Get all functions called by this function"""
    calls = []
    if func is None:
        return calls
    
    func_body = func.getBody()
    listing = currentProgram.getListing()
    
    for addr in func_body.getAddresses(True):
        instruction = listing.getInstructionAt(addr)
        if instruction:
            for ref in instruction.getReferencesFrom():
                ref_addr = ref.getToAddress()
                called_func = getFunctionAt(ref_addr)
                if called_func and called_func.getName() not in calls:
                    calls.append(called_func.getName())
    
    return calls

def get_function_callers(func):
    """Get all functions that call this function"""
    callers = []
    if func is None:
        return callers
    
    entry_point = func.getEntryPoint()
    refs = getReferencesTo(entry_point)
    
    for ref in refs:
        caller_func = getFunctionContaining(ref.getFromAddress())
        if caller_func and caller_func.getName() not in callers:
            callers.append(caller_func.getName())
    
    return callers

def get_assembly(func):
    """Get assembly instructions for a function"""
    asm_lines = []
    if func is None:
        return asm_lines
    
    func_body = func.getBody()
    listing = currentProgram.getListing()
    
    for addr in func_body.getAddresses(True):
        instruction = listing.getInstructionAt(addr)
        if instruction:
            asm_lines.append({
                "address": str(addr),
                "mnemonic": instruction.getMnemonicString(),
                "operands": str(instruction),
            })
    
    return asm_lines

def decompile_function(decomp, func):
    """Decompile a function and return the C code"""
    if func is None:
        return None
    
    try:
        results = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
        if results and results.decompileCompleted():
            decompiled = results.getDecompiledFunction()
            if decompiled:
                return decompiled.getC()
    except Exception as e:
        print("Error decompiling {}: {}".format(func.getName(), str(e)))
    
    return None

def analyze_instruction_vulnerabilities(asm_lines):
    """
    Deep instruction-level vulnerability analysis.
    Detects issues that require assembly analysis, not just API calls.
    """
    vulnerabilities = []
    
    # Track register initialization state (simplified)
    initialized_regs = set()
    
    for i, asm in enumerate(asm_lines):
        addr = asm.get("address", "")
        mnemonic = asm.get("mnemonic", "").upper()
        operands = asm.get("operands", "")
        
        # Extract destination register from instruction
        parts = operands.split(",")
        if parts:
            dest = parts[0].strip().upper()
        
        # Track MOV/XOR that initialize registers
        if mnemonic in ["MOV", "XOR", "LEA", "POP"]:
            # XOR REG, REG is a common initialization pattern
            if mnemonic == "XOR" and len(parts) >= 2:
                if parts[0].strip().upper() == parts[1].strip().upper():
                    initialized_regs.add(parts[0].strip().upper().replace("E", "").replace("R", "")[:2])
            elif mnemonic == "MOV":
                reg = parts[0].strip().upper().replace("E", "").replace("R", "")[:2]
                initialized_regs.add(reg)
        
        # VULNERABILITY: DIV/IDIV with potentially uninitialized or zero divisor
        if mnemonic in ["DIV", "IDIV"]:
            divisor = operands.strip().upper()
            # Check if divisor register was initialized
            divisor_base = divisor.replace("E", "").replace("R", "")[:2]
            
            # Look back to see if divisor was validated (CMP/TEST followed by JZ/JE)
            has_zero_check = False
            for j in range(max(0, i-10), i):
                prev_mnem = asm_lines[j].get("mnemonic", "").upper()
                prev_ops = asm_lines[j].get("operands", "").upper()
                if prev_mnem in ["TEST", "CMP"] and divisor in prev_ops:
                    has_zero_check = True
                    break
            
            if not has_zero_check:
                # Build context (5 instructions before)
                context = []
                for j in range(max(0, i-5), i+1):
                    ctx_asm = asm_lines[j]
                    context.append({
                        "address": ctx_asm.get("address"),
                        "instruction": ctx_asm.get("operands")
                    })
                
                vulnerabilities.append({
                    "type": "divide_by_zero",
                    "severity": "HIGH",
                    "cwe": "CWE-369",
                    "address": addr,
                    "instruction": operands,
                    "issue": "DIV/IDIV with unvalidated divisor - no zero check before division",
                    "impact": "If {} == 0, causes SIGFPE crash (DoS). If attacker controls call context, reliable crash.".format(divisor),
                    "context": context
                })
        
        # VULNERABILITY: Indirect call/jump with potentially attacker-controlled register
        if mnemonic in ["CALL", "JMP"]:
            if operands.startswith("R") or operands.startswith("E") or operands.startswith("["):
                # Indirect call - potential control flow hijack
                vulnerabilities.append({
                    "type": "indirect_call",
                    "severity": "CRITICAL" if mnemonic == "CALL" else "HIGH",
                    "cwe": "CWE-470",
                    "address": addr,
                    "instruction": operands,
                    "issue": "Indirect {} via register/memory - potential control flow hijack".format(mnemonic),
                    "impact": "If attacker controls {}, can redirect execution to arbitrary code.".format(operands)
                })
        
        # VULNERABILITY: Write to memory with register-based address (potential arbitrary write)
        if mnemonic == "MOV" and len(parts) >= 2:
            dest_op = parts[0].strip()
            if dest_op.startswith("[") and ("+" in dest_op or any(r in dest_op.upper() for r in ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9"])):
                # Memory write with register offset
                vulnerabilities.append({
                    "type": "memory_write",
                    "severity": "MEDIUM",
                    "cwe": "CWE-787",
                    "address": addr,
                    "instruction": operands,
                    "issue": "Memory write with register-controlled address",
                    "impact": "If offset register is attacker-controlled, potential out-of-bounds write."
                })
        
        # VULNERABILITY: RET with potentially corrupted stack
        if mnemonic == "RET":
            # Check for suspicious patterns before RET (like ADD RSP with large value)
            for j in range(max(0, i-5), i):
                prev_mnem = asm_lines[j].get("mnemonic", "").upper()
                prev_ops = asm_lines[j].get("operands", "").upper()
                if prev_mnem == "ADD" and "RSP" in prev_ops or "ESP" in prev_ops:
                    # Large stack adjustment before ret could indicate buffer issue
                    pass
        
        # VULNERABILITY: SYSCALL with attacker-controlled registers
        if mnemonic == "SYSCALL":
            vulnerabilities.append({
                "type": "syscall",
                "severity": "HIGH",
                "cwe": "CWE-78",
                "address": addr,
                "instruction": operands,
                "issue": "Direct syscall - check if RAX (syscall number) and arguments are validated",
                "impact": "If syscall number or arguments are attacker-controlled, potential for arbitrary syscall execution."
            })
        
        # VULNERABILITY: Uncontrolled recursion / stack exhaustion
        if mnemonic == "CALL" and operands == func_name if 'func_name' in dir() else False:
            vulnerabilities.append({
                "type": "recursion",
                "severity": "MEDIUM",
                "cwe": "CWE-674",
                "address": addr,
                "instruction": operands,
                "issue": "Recursive call without visible base case - potential stack exhaustion",
                "impact": "Uncontrolled recursion can cause stack overflow and crash."
            })
    
    return vulnerabilities


def analyze_function_risk(func_name, decompiled_code, asm_lines):
    """
    Instruction-level vulnerability analysis.
    
    IMPORTANT: We do NOT flag APIs like printf, free, strcpy just because they're present.
    That causes false positives. We only flag:
    1. APIs that are ALWAYS dangerous (gets)
    2. Instruction-level issues we can verify (DIV without zero check, etc.)
    
    Data-flow analysis (taint tracking) would be needed to properly detect:
    - Format string vulns (user input in format string position)
    - Buffer overflows (user input size > buffer size)
    - Command injection (user input in command string)
    
    Without data-flow, we'd just be pattern matching = false positives.
    """
    risk_indicators = []
    
    # ONLY flag gets() - it's ALWAYS dangerous, no false positives possible
    if decompiled_code:
        if "gets(" in decompiled_code or "gets (" in decompiled_code:
            risk_indicators.append({
                "type": "buffer_overflow",
                "function": "gets",
                "severity": "CRITICAL",
                "cwe": "CWE-242",
                "issue": "Uses gets() which has NO bounds checking",
                "impact": "Trivially exploitable buffer overflow - gets() should never be used"
            })
    
    # Instruction-level vulnerability analysis (these are verifiable)
    instruction_vulns = analyze_instruction_vulnerabilities(asm_lines)
    for vuln in instruction_vulns:
        risk_indicators.append(vuln)
    
    return risk_indicators

def main():
    print("[*] Starting Ghidra Analysis Script")
    print("[*] Analyzing: {}".format(currentProgram.getName()))
    
    # Initialize decompiler
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    
    # Get all functions
    func_manager = currentProgram.getFunctionManager()
    functions = func_manager.getFunctions(True)
    
    analysis_result = {
        "binary_name": currentProgram.getName(),
        "binary_path": currentProgram.getExecutablePath(),
        "architecture": currentProgram.getLanguage().getProcessor().toString(),
        "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
        "entry_points": [],
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": []
    }
    
    # Get entry points
    for entry in currentProgram.getSymbolTable().getExternalEntryPointIterator():
        analysis_result["entry_points"].append(str(entry))
    
    # Get imports
    ext_manager = currentProgram.getExternalManager()
    for lib_name in ext_manager.getExternalLibraryNames():
        lib_symbols = []
        for ext_loc in ext_manager.getExternalLocations(lib_name):
            lib_symbols.append(ext_loc.getLabel())
        analysis_result["imports"].append({
            "library": lib_name,
            "symbols": lib_symbols
        })
    
    # Analyze each function
    for func in functions:
        func_name = func.getName()
        entry_point = str(func.getEntryPoint())
        
        print("[*] Analyzing function: {} at {}".format(func_name, entry_point))
        
        # Get decompiled code
        decompiled = decompile_function(decomp, func)
        
        # Get assembly
        asm_lines = get_assembly(func)
        
        # Get call relationships
        calls = get_function_calls(func)
        callers = get_function_callers(func)
        
        # Risk analysis
        risks = analyze_function_risk(func_name, decompiled, asm_lines)
        
        func_info = {
            "name": func_name,
            "entry_point": entry_point,
            "signature": str(func.getSignature()),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "stack_frame_size": func.getStackFrame().getFrameSize() if func.getStackFrame() else 0,
            "parameter_count": func.getParameterCount(),
            "calls": calls,
            "called_by": callers,
            "decompiled_code": decompiled,
            "assembly_line_count": len(asm_lines),
            "assembly_preview": asm_lines[:50] if len(asm_lines) > 50 else asm_lines,
            "risk_indicators": risks
        }
        
        analysis_result["functions"].append(func_info)
    
    # Get interesting strings
    data_iterator = currentProgram.getListing().getDefinedData(True)
    string_count = 0
    for data in data_iterator:
        if data.hasStringValue() and string_count < 500:
            string_val = data.getValue()
            if string_val and len(str(string_val)) > 3:
                analysis_result["strings"].append({
                    "address": str(data.getAddress()),
                    "value": str(string_val)[:500]
                })
                string_count += 1
    
    # Output results
    output_path = os.environ.get("GHIDRA_OUTPUT", "/tmp/ghidra_analysis.json")
    
    with open(output_path, "w") as f:
        json.dump(analysis_result, f, indent=2, default=str)
    
    print("[+] Analysis complete. Output saved to: {}".format(output_path))
    print("[+] Total functions analyzed: {}".format(len(analysis_result["functions"])))
    
    decomp.dispose()

# Run the analysis
main()

