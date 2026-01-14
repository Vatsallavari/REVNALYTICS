"""
Ghidra Headless Integration
Handles calling Ghidra in headless mode and running analysis scripts
"""
import subprocess
import os
from pathlib import Path
import json
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration - Update these paths for your system
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/Users/doctorranjan/Desktop/2_1NFSU/ghidra_11.4.2_PUBLIC")
GHIDRA_PROJECTS_DIR = os.environ.get("GHIDRA_PROJECTS_DIR", "/tmp/ghidra_projects")
GHIDRA_SCRIPTS_DIR = Path(__file__).parent.parent / "ghidra_scripts"
GHIDRA_ANALYSIS_SCRIPT = "extract_functions.py"
GHIDRA_TIMEOUT = int(os.environ.get("GHIDRA_TIMEOUT", "600"))  # 10 minutes


def get_ghidra_headless_path() -> Path:
    """Get the path to analyzeHeadless script"""
    ghidra_path = Path(GHIDRA_HOME)
    
    # Try different possible locations
    possible_paths = [
        ghidra_path / "support" / "analyzeHeadless",
        ghidra_path / "support" / "analyzeHeadless.sh",
    ]
    
    for path in possible_paths:
        if path.exists():
            return path
    
    raise FileNotFoundError(
        f"Ghidra analyzeHeadless not found. "
        f"Set GHIDRA_HOME environment variable. "
        f"Tried: {[str(p) for p in possible_paths]}"
    )


def run_ghidra_analysis(binary_path: str, output_json_path: str) -> Dict[str, Any]:
    """
    Run Ghidra headless analysis on a binary file.
    
    Args:
        binary_path: Path to the binary file to analyze
        output_json_path: Path where JSON output should be saved
    
    Returns:
        Dict with 'success' bool and optional 'error' message
    """
    try:
        # Ensure directories exist
        Path(GHIDRA_PROJECTS_DIR).mkdir(parents=True, exist_ok=True)
        Path(output_json_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Get Ghidra paths
        analyze_headless = get_ghidra_headless_path()
        project_name = f"auto_project_{os.path.basename(binary_path)}"
        
        # Set environment variable for output path
        env = os.environ.copy()
        env["GHIDRA_OUTPUT"] = output_json_path
        
        # Build command
        cmd = [
            str(analyze_headless),
            GHIDRA_PROJECTS_DIR,
            project_name,
            "-import", binary_path,
            "-scriptPath", str(GHIDRA_SCRIPTS_DIR),
            "-postScript", GHIDRA_ANALYSIS_SCRIPT,
            "-deleteProject",  # Clean up after analysis
        ]
        
        print(f"[*] Running Ghidra command: {' '.join(cmd)}")
        
        # Run Ghidra
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=GHIDRA_TIMEOUT,
            env=env,
        )
        
        if result.returncode != 0:
            error_msg = f"Ghidra exited with code {result.returncode}\n"
            error_msg += f"STDOUT: {result.stdout}\n"
            error_msg += f"STDERR: {result.stderr}"
            print(f"[!] Ghidra error: {error_msg}")
            return {"success": False, "error": error_msg}
        
        # Check if output file was created
        if not Path(output_json_path).exists():
            return {
                "success": False,
                "error": f"Ghidra completed but output file not found: {output_json_path}"
            }
        
        # Verify JSON is valid
        try:
            with open(output_json_path, "r") as f:
                json.load(f)  # Validate JSON
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Invalid JSON output: {str(e)}"
            }
        
        print(f"[+] Ghidra analysis completed successfully")
        return {"success": True}
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Ghidra analysis timed out after {GHIDRA_TIMEOUT} seconds"
        }
    except FileNotFoundError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}"
        }

