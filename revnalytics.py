#!/usr/bin/env python3
"""
Revnalytics - Command Line Malware Analysis Tool
A CLI tool for analyzing binary files using Ghidra and AI-powered analysis.
"""
import sys
import json
import asyncio
import argparse
from pathlib import Path
from datetime import datetime
import uuid

# Load environment variables from .env file FIRST
from dotenv import load_dotenv
# Try both project root and backend directory
load_dotenv()  # Project root
load_dotenv(Path(__file__).parent / "backend" / ".env")  # backend/.env

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from ghidra_integration import run_ghidra_analysis
from ai_agent import analyze_with_ai


def print_banner():
    """Print welcome banner"""
    banner = """
╔════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                            ║
║                                                                                                            ║
║           ██████╗ ███████╗██╗   ██╗███╗   ██╗ █████╗ ██╗  ██╗   ██╗████████╗██╗ ██████╗███████╗            ║
║           ██╔══██╗██╔════╝██║   ██║████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══██╔══╝██║██╔════╝██╔════╝            ║
║           ██████╔╝█████╗  ██║   ██║██╔██╗ ██║███████║██║   ╚████╔╝    ██║   ██║██║     ███████╗            ║
║           ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║╚██╗██║██╔══██║██║    ╚██╔╝     ██║   ██║██║     ╚════██║            ║
║           ██║  ██║███████╗ ╚████╔╝ ██║ ╚████║██║  ██║███████╗██║      ██║   ██║╚██████╗███████║            ║
║           ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═╝   ╚═╝ ╚═════╝╚══════╝            ║
║                                                                                                            ║
║                                                                                                            ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_section(title: str):
    """Print a section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_info(message: str):
    """Print info message"""
    print(f"[*] {message}")


def print_success(message: str):
    """Print success message"""
    print(f"[+] {message}")


def print_error(message: str):
    """Print error message"""
    print(f"[!] {message}")


def print_warning(message: str):
    """Print warning message"""
    print(f"[!] {message}")


def validate_file_path(file_path: str) -> Path:
    """Validate the provided file path"""
    # Remove quotes if user added them
    file_path = file_path.strip('"').strip("'")
    
    path = Path(file_path)
    
    # Expand user home directory
    if file_path.startswith("~"):
        path = Path.home() / file_path[2:] if file_path.startswith("~/") else Path.home() / file_path[1:]
    
    # Resolve to absolute path
    path = path.resolve()
    
    if not path.exists():
        print_error(f"File not found: {path}")
        sys.exit(1)
    
    if not path.is_file():
        print_error(f"Path is not a file: {path}")
        sys.exit(1)
    
    # Check file size (max 100MB)
    file_size = path.stat().st_size
    max_size = 100 * 1024 * 1024  # 100MB
    if file_size > max_size:
        print_error(f"File too large: {file_size / (1024*1024):.2f}MB (max 100MB)")
        sys.exit(1)
    
    return path


def display_results(analysis_id: str, ghidra_data: dict, ai_result: dict, file_name: str):
    """Display analysis results in a formatted way"""
    print_section("ANALYSIS RESULTS")
    
    # Basic Information
    print("📋 Basic Information:")
    print(f"   Analysis ID: {analysis_id}")
    print(f"   File Name: {file_name}")
    print(f"   Binary Name: {ghidra_data.get('binary_name', 'Unknown')}")
    print(f"   Architecture: {ghidra_data.get('architecture', 'Unknown')}")
    print(f"   Functions Found: {len(ghidra_data.get('functions', []))}")
    print(f"   Imports: {len(ghidra_data.get('imports', []))}")
    print(f"   Strings: {len(ghidra_data.get('strings', []))}")
    print(f"   Entry Points: {len(ghidra_data.get('entry_points', []))}")
    
    # Safety Assessment
    safety = ai_result.get('safety_assessment', {})
    verdict = safety.get('verdict', 'UNKNOWN')
    confidence = safety.get('confidence', 'UNKNOWN')
    reason = safety.get('reason', 'No reason provided')
    
    print("\n🛡️  Safety Assessment:")
    
    # Color code verdict (using ANSI codes)
    if verdict == "SAFE":
        verdict_display = f"\033[92m{verdict}\033[0m"  # Green
    elif verdict == "SUSPICIOUS":
        verdict_display = f"\033[93m{verdict}\033[0m"  # Yellow
    elif verdict == "MALICIOUS":
        verdict_display = f"\033[91m{verdict}\033[0m"  # Red
    else:
        verdict_display = verdict
    
    print(f"   Verdict: {verdict_display}")
    print(f"   Confidence: {confidence}")
    print(f"   Reason: {reason}")
    
    # AI Explanation
    explanation = ai_result.get('explanation', 'No explanation available.')
    print("\n📝 AI Analysis:")
    print(f"   {explanation}")
    
    # Key Behaviors
    behaviors = ai_result.get('key_behaviors', [])
    if behaviors:
        print("\n🔍 Key Behaviors:")
        for i, behavior in enumerate(behaviors, 1):
            print(f"   {i}. {behavior}")
    
    # Security Concerns
    concerns = ai_result.get('security_concerns', [])
    if concerns:
        print("\n⚠️  Security Concerns:")
        for i, concern in enumerate(concerns, 1):
            print(f"   {i}. {concern}")
    
    # Call Flow Summary
    functions = ghidra_data.get('functions', [])
    if functions:
        print("\n📊 Call Flow Summary:")
        # Find main entry points
        main_funcs = [f for f in functions if f.get('name', '').lower() in ['main', 'wmain', 'winmain', 'wwinmain', '_main']]
        user_funcs = [f for f in functions if f.get('name', '').startswith('FUN_') or 
                      (not f.get('name', '').startswith('_') and not f.get('name', '').startswith('.'))]
        
        # Build simple call summary
        if main_funcs:
            main_name = main_funcs[0].get('name', 'main')
            main_calls = main_funcs[0].get('calls', [])[:5]
            print(f"   Entry: {main_name} → {', '.join(main_calls) if main_calls else 'no direct calls'}")
        
        # Count function types
        total = len(functions)
        user_count = len([f for f in functions if not f.get('name', '').startswith('_')])
        print(f"   Total: {total} functions ({user_count} user-defined, {total - user_count} library/system)")
    
    # Reverse Engineering Leverage Points
    leverage_points = ai_result.get('reverse_leverage', [])
    if leverage_points:
        print("\n🎯 REVERSE ENGINEERING LEVERAGE POINTS:")
        print(f"   Found {len(leverage_points)} interesting target(s):\n")
        
        for i, lev in enumerate(leverage_points, 1):
            func_name = lev.get('function_name', 'Unknown')
            address = lev.get('address', '')
            leverage_type = lev.get('leverage_type', 'Unknown')
            why_interesting = lev.get('why_interesting', '')
            reverse_strategy = lev.get('reverse_strategy', '')
            asm_evidence = lev.get('assembly_evidence', [])
            cwe = lev.get('cwe', '')
            vuln_type = lev.get('vulnerability_type', '')
            
            # Color code leverage type
            type_colors = {
                "Crash Leverage": "\033[91m",      # Red
                "Arithmetic Constraint": "\033[95m", # Magenta
                "Comparison Gate": "\033[93m",     # Yellow
                "Environment Gate": "\033[94m",    # Blue
                "Crypto Leverage": "\033[96m",     # Cyan
                "Input Handler": "\033[92m",       # Green
            }
            color = type_colors.get(leverage_type, "\033[0m")
            type_display = f"{color}{leverage_type}\033[0m"
            
            # Format function name with address
            if address:
                func_display = f"\033[96m{func_name}\033[0m @ {address}"  # Cyan
            else:
                func_display = f"\033[96m{func_name}\033[0m"
            
            print(f"   ┌─[{i}] {func_display}")
            print(f"   │  Type: {type_display}")
            
            if vuln_type:
                print(f"   │  Vulnerability: {vuln_type}")
            if cwe:
                print(f"   │  CWE: {cwe}")
            
            print(f"   │")
            print(f"   │  \033[93mWhy Interesting:\033[0m")
            print(f"   │    {why_interesting}")
            
            # Show assembly evidence if available
            if asm_evidence:
                print(f"   │")
                print(f"   │  \033[93mAssembly Evidence:\033[0m")
                for asm_line in asm_evidence[:6]:  # Show up to 6 lines
                    print(f"   │    {asm_line}")
            
            # Show reverse strategy
            if reverse_strategy:
                print(f"   │")
                print(f"   │  \033[92mReverse Strategy:\033[0m")
                print(f"   │    {reverse_strategy}")
            
            print(f"   └─{'─' * 60}")
            print()
    else:
        print("\n🎯 Reverse Engineering Leverage:")
        print("   No obvious leverage points detected.")
        print("   This binary may require deeper manual analysis.")
    
    # Recommended Focus
    recommended = ai_result.get('recommended_focus', '')
    if recommended:
        print(f"\n🔥 \033[93mRECOMMENDED FOCUS:\033[0m")
        print(f"   {recommended}")
    
    # Not Interesting (collapsed)
    not_interesting = ai_result.get('not_interesting', [])
    if not_interesting:
        print(f"\n📋 Functions analyzed but not interesting: {len(not_interesting)}")
        if len(not_interesting) <= 5:
            for func in not_interesting:
                print(f"   • {func}")
    
    print("\n" + "="*60 + "\n")


def display_source_results(analysis_id: str, ai_result: dict, file_name: str, source_code: str):
    """Display source code analysis results"""
    print_section("SOURCE CODE ANALYSIS RESULTS")
    
    # Basic Information
    print("📋 Basic Information:")
    print(f"   Analysis ID: {analysis_id}")
    print(f"   File Name: {file_name}")
    print(f"   Lines of Code: {len(source_code.splitlines())}")
    
    # Summary
    summary = ai_result.get('summary', ai_result.get('explanation', 'No summary available.'))
    print("\n📝 Analysis Summary:")
    for line in summary.split('\n'):
        print(f"   {line}")
    
    # Reverse Engineering Leverage Points
    leverage_points = ai_result.get('reverse_leverage', [])
    if leverage_points:
        print(f"\n🎯 VULNERABILITY / LEVERAGE POINTS:")
        print(f"   Found {len(leverage_points)} interesting target(s):\n")
        
        for i, lev in enumerate(leverage_points, 1):
            func_name = lev.get('function_name', 'Unknown')
            leverage_type = lev.get('leverage_type', 'Unknown')
            why_interesting = lev.get('why_interesting', '')
            reverse_strategy = lev.get('reverse_strategy', '')
            code_evidence = lev.get('code_evidence', lev.get('assembly_evidence', []))
            cwe = lev.get('cwe', '')
            
            # Color code leverage type
            type_colors = {
                "Buffer Overflow": "\033[91m",
                "Format String": "\033[91m",
                "Command Injection": "\033[91m",
                "SQL Injection": "\033[91m",
                "Use After Free": "\033[91m",
                "Integer Overflow": "\033[93m",
                "Race Condition": "\033[93m",
                "Arithmetic Constraint": "\033[95m",
                "Comparison Gate": "\033[93m",
                "Weak Crypto": "\033[96m",
                "Input Handler": "\033[92m",
            }
            color = type_colors.get(leverage_type, "\033[94m")
            type_display = f"{color}{leverage_type}\033[0m"
            
            print(f"   ┌─[{i}] \033[96m{func_name}\033[0m")
            print(f"   │  Type: {type_display}")
            if cwe:
                print(f"   │  CWE: {cwe}")
            
            print(f"   │")
            print(f"   │  \033[93mWhy Interesting:\033[0m")
            print(f"   │    {why_interesting}")
            
            if code_evidence:
                print(f"   │")
                print(f"   │  \033[93mCode Evidence:\033[0m")
                for line in code_evidence[:8]:
                    print(f"   │    {line}")
            
            if reverse_strategy:
                print(f"   │")
                print(f"   │  \033[92mExploit Strategy:\033[0m")
                print(f"   │    {reverse_strategy}")
            
            print(f"   └─{'─' * 60}")
            print()
    else:
        print("\n🎯 Vulnerabilities / Leverage Points:")
        print("   No obvious vulnerabilities detected in source code.")
    
    # Recommended Focus
    recommended = ai_result.get('recommended_focus', '')
    if recommended:
        print(f"\n🔥 \033[93mRECOMMENDED FOCUS:\033[0m")
        print(f"   {recommended}")
    
    print("\n" + "="*60 + "\n")


async def analyze_source_code(source_path: Path, output_path: Path = None):
    """Analyze source code directly with AI (no Ghidra)"""
    analysis_id = str(uuid.uuid4())
    
    file_name = source_path.name
    print_info(f"Starting source code analysis of: {file_name}")
    print_info(f"File size: {source_path.stat().st_size / 1024:.2f} KB")
    
    # Read source code
    print_section("SOURCE CODE ANALYSIS")
    print_info("Reading source code...")
    
    try:
        with open(source_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
    except Exception as e:
        print_error(f"Failed to read source file: {str(e)}")
        return None
    
    lines = len(source_code.splitlines())
    print_success(f"Read {lines} lines of source code")
    
    # Detect language from extension
    ext = source_path.suffix.lower()
    lang_map = {
        '.c': 'C', '.h': 'C Header',
        '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++', '.hpp': 'C++ Header',
        '.py': 'Python',
        '.js': 'JavaScript', '.ts': 'TypeScript',
        '.go': 'Go',
        '.rs': 'Rust',
        '.java': 'Java',
        '.php': 'PHP',
        '.rb': 'Ruby',
        '.sh': 'Shell', '.bash': 'Bash',
        '.ps1': 'PowerShell',
    }
    language = lang_map.get(ext, 'Unknown')
    print_info(f"Detected language: {language}")
    
    # Analyze with AI
    print_info("Sending to AI for analysis...")
    
    from backend.ai_agent import analyze_source_with_ai
    
    try:
        ai_result = await analyze_source_with_ai(source_code, file_name, language)
        print_success("AI analysis completed")
    except Exception as e:
        print_error(f"AI analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    
    # Save results if output path specified
    if output_path:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump({
                    "analysis_id": analysis_id,
                    "file_name": file_name,
                    "file_path": str(source_path),
                    "language": language,
                    "lines_of_code": lines,
                    "summary": ai_result.get("summary"),
                    "reverse_leverage": ai_result.get("reverse_leverage", []),
                    "recommended_focus": ai_result.get("recommended_focus", ""),
                    "timestamp": datetime.now().isoformat()
                }, f, indent=2)
            print_success(f"Report saved to: {output_path}")
        except Exception as e:
            print_warning(f"Failed to save report: {str(e)}")
    
    # Display results
    display_source_results(analysis_id, ai_result, file_name, source_code)
    
    return {
        "analysis_id": analysis_id,
        "file_name": file_name,
        "ai_result": ai_result
    }


async def analyze_file(file_path: Path, output_path: Path = None):
    """Analyze a file using Ghidra and AI"""
    import tempfile
    import os
    
    analysis_id = str(uuid.uuid4())
    file_name = file_path.name
    
    print_info(f"Starting analysis of: {file_name}")
    print_info(f"File size: {file_path.stat().st_size / (1024*1024):.2f} MB")
    
    # Step 1: Run Ghidra analysis (use temp file, no permanent storage)
    print_section("GHIDRA ANALYSIS")
    print_info("Running Ghidra headless analysis...")
    print_info("This may take several minutes depending on file size...")
    
    # Create temporary file for Ghidra output
    temp_fd, temp_json_path = tempfile.mkstemp(suffix='.json', prefix='ghidra_')
    os.close(temp_fd)  # Close the file descriptor, Ghidra will write to the path
    
    try:
        ghidra_result = await asyncio.to_thread(
            run_ghidra_analysis,
            str(file_path),
            temp_json_path
        )
        
        if not ghidra_result["success"]:
            print_error(f"Ghidra analysis failed: {ghidra_result.get('error', 'Unknown error')}")
            # Clean up temp file on error
            if os.path.exists(temp_json_path):
                os.remove(temp_json_path)
            return None
        
        print_success("Ghidra analysis completed successfully")
        
    except Exception as e:
        print_error(f"Error during Ghidra analysis: {str(e)}")
        # Clean up temp file on error
        if os.path.exists(temp_json_path):
            os.remove(temp_json_path)
        return None
    
    # Step 2: Load Ghidra output from temp file
    try:
        with open(temp_json_path, "r") as f:
            ghidra_data = json.load(f)
    except json.JSONDecodeError as e:
        print_error(f"Failed to parse Ghidra output: {str(e)}")
        if os.path.exists(temp_json_path):
            os.remove(temp_json_path)
        return None
    except FileNotFoundError:
        print_error(f"Ghidra output file not found: {temp_json_path}")
        return None
    finally:
        # Always clean up temp file after reading
        if os.path.exists(temp_json_path):
            os.remove(temp_json_path)
    
    print_info(f"Functions found: {len(ghidra_data.get('functions', []))}")
    
    # Step 3: AI Analysis
    print_section("AI ANALYSIS")
    print_info("Sending data to AI agent for analysis...")
    
    try:
        ai_result = await analyze_with_ai(ghidra_data)
        print_success("AI analysis completed")
    except Exception as e:
        print_error(f"Error during AI analysis: {str(e)}")
        return None
    
    # Step 4: Save complete results (only if output path is specified)
    if output_path:
        try:
            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump({
                    "analysis_id": analysis_id,
                    "file_name": file_name,
                    "file_path": str(file_path),
                    "ghidra_output": ghidra_data,
                    "summary": ai_result.get("summary", ai_result.get("explanation")),
                    "reverse_leverage": ai_result.get("reverse_leverage", []),
                    "not_interesting": ai_result.get("not_interesting", []),
                    "recommended_focus": ai_result.get("recommended_focus", ""),
                    "safety_assessment": ai_result.get("safety_assessment"),
                    "timestamp": datetime.now().isoformat()
                }, f, indent=2)
            print_success(f"Report saved to: {output_path}")
        except Exception as e:
            print_warning(f"Failed to save report: {str(e)}")
    
    # Step 5: Display results
    display_results(analysis_id, ghidra_data, ai_result, file_name)
    
    return {
        "analysis_id": analysis_id,
        "ghidra_data": ghidra_data,
        "ai_result": ai_result
    }


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Revnalytics - Binary & Source Code Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f binary.exe                    # Analyze binary with Ghidra
  %(prog)s -s source.c                      # Analyze source code directly
  %(prog)s -f binary.exe -o report.json     # Analyze and save report
  %(prog)s -s vuln.c -o analysis.json       # Analyze source and save report
        """
    )
    
    # Create mutually exclusive group - at least one required
    input_group = parser.add_mutually_exclusive_group(required=True)
    
    input_group.add_argument(
        '-f', '--file',
        type=str,
        metavar='PATH',
        help='Path to the binary file to analyze (uses Ghidra)'
    )
    
    input_group.add_argument(
        '-s', '--source',
        type=str,
        metavar='PATH',
        help='Path to source code file to analyze (C, C++, Python, etc.)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        metavar='PATH',
        help='Path to save the analysis report (JSON format). If not specified, report will not be saved.'
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    print_banner()
    
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Determine output path if specified
        output_path = Path(args.output) if args.output else None
        
        # Check which mode: binary (-f) or source code (-s)
        if args.file:
            # Binary analysis mode (uses Ghidra)
            file_path = validate_file_path(args.file)
            print_info("Mode: Binary Analysis (Ghidra)")
            result = asyncio.run(analyze_file(file_path, output_path))
        elif args.source:
            # Source code analysis mode (direct AI)
            source_path = validate_file_path(args.source)
            print_info("Mode: Source Code Analysis (Direct AI)")
            result = asyncio.run(analyze_source_code(source_path, output_path))
        else:
            print_error("Either -f (binary file) or -s (source code) must be specified")
            sys.exit(1)
        
        if result:
            print_success("Analysis completed successfully!")
            print_info(f"Analysis ID: {result['analysis_id']}")
            if output_path:
                print_info(f"Report saved to: {output_path}")
        else:
            print_error("Analysis failed. Please check the error messages above.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

