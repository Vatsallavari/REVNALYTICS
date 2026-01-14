# Setup Guide - Revnalytics CLI Tool

## Quick Start

### 1. Install Python Dependencies

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Ghidra

1. Download Ghidra from https://ghidra-sre.org/
2. Extract it to a location (e.g., `/Applications/ghidra_11.0.3_PUBLIC`)
3. Set environment variable:

```bash
export GHIDRA_HOME="/path/to/ghidra_11.0.3_PUBLIC"
```

Or create a `.env` file in the `backend` directory:
```env
GHIDRA_HOME=/path/to/ghidra_11.0.3_PUBLIC
GHIDRA_PROJECTS_DIR=/tmp/ghidra_projects
GHIDRA_TIMEOUT=600

# LLM API Keys (at least one recommended for AI analysis)
OPENAI_API_KEY=your_key_here
PERPLEXITY_API_KEY=your_key_here
DEEPSEEK_API_KEY=your_key_here
MISTRAL_API_KEY=your_key_here
HUGGINGFACE_API_KEY=your_key_here
```

### 3. Verify Ghidra Installation

Test that Ghidra headless is accessible:
```bash
$GHIDRA_HOME/support/analyzeHeadless --help
```

### 4. Configure AI API Keys (Optional)

For AI-powered analysis, add at least one API key to `backend/.env`. The system supports:
- OpenAI
- Perplexity
- DeepSeek
- Mistral
- Hugging Face

If not configured, the system will use a basic rule-based fallback analysis.

### 5. Make CLI Tool Executable

```bash
chmod +x revnalytics.py
```

### 6. Run the CLI Tool

```bash
python revnalytics.py
```

Or if made executable:
```bash
./revnalytics.py
```

The tool will prompt you for the path to the binary file you want to analyze.

## Troubleshooting

### Ghidra Not Found
- Verify `GHIDRA_HOME` environment variable is set
- Check that `analyzeHeadless` script exists at `$GHIDRA_HOME/support/analyzeHeadless`
- On macOS/Linux, ensure the script is executable: `chmod +x $GHIDRA_HOME/support/analyzeHeadless`

### Analysis Timeout
- Large binaries may take longer to analyze
- Increase timeout in `backend/.env`: `GHIDRA_TIMEOUT=1200` (20 minutes)

### AI API Errors
- Verify API key is correct in `backend/.env`
- Check API quota/limits
- System will automatically try other providers if one fails
- System will fall back to rule-based analysis if all AI providers unavailable

### File Path Issues
- Use absolute paths or paths relative to current directory
- Paths with spaces should work, but you can use quotes if needed
- Tilde expansion (~) is supported for home directory

## Usage Example

```bash
$ python revnalytics.py

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                    REVNALYTICS                               ║
║              Malware Analysis Tool (CLI)                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Enter the path to the binary file: /path/to/suspicious.exe

[*] Starting analysis of: suspicious.exe
[*] File size: 2.45 MB
...
```

## Next Steps

1. Run the CLI tool: `python revnalytics.py`
2. Enter the path to a binary file when prompted
3. Wait for analysis to complete (may take several minutes)
4. Review the AI-generated explanation and safety assessment displayed in the terminal
5. Check `backend/outputs/` for complete JSON results
