# Revnalytics - Malware Analysis Tool (CLI)

A command-line malware analysis tool that combines Ghidra reverse engineering with AI-powered analysis. Analyze binary files and get detailed security assessments in simple, understandable terms.

## 🏗️ Architecture

```
CLI Tool → Ghidra Headless → AI Agent → Results Display
```

1. **CLI Interface**: Command-line tool that prompts for file location
2. **Ghidra**: Headless mode analysis extracting functions, decompiled code, and security indicators
3. **AI Agent**: Multi-LLM analysis (OpenAI, Perplexity, DeepSeek, Mistral, Hugging Face) that translates technical findings into simple explanations with automatic fallback

## 📋 Prerequisites

- Python 3.8+
- Ghidra (installed and configured)
- At least one LLM API key (optional, for AI analysis):
  - OpenAI API key
  - Perplexity API key
  - DeepSeek API key
  - Mistral API key
  - Hugging Face API key

## 🚀 Setup

### 1. Install Ghidra

Download and install Ghidra from: https://ghidra-sre.org/

Set the `GHIDRA_HOME` environment variable:
```bash
export GHIDRA_HOME="/path/to/ghidra_11.0.3_PUBLIC"
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the backend directory:
```env
GHIDRA_HOME=/path/to/ghidra_11.4.2_PUBLIC
GHIDRA_PROJECTS_DIR=/tmp/ghidra_projects
GHIDRA_TIMEOUT=600

# LLM API Keys (at least one recommended for AI analysis)
# Fallback order: OpenAI -> Perplexity -> DeepSeek -> Mistral -> Hugging Face -> Basic
OPENAI_API_KEY=your_openai_api_key_here
PERPLEXITY_API_KEY=your_perplexity_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here
MISTRAL_API_KEY=your_mistral_api_key_here
HUGGINGFACE_API_KEY=your_huggingface_api_key_here
```

### 3. Make CLI Tool Executable

```bash
chmod +x revnalytics.py
```

## 🎯 Usage

### Command Line Interface

Simply run the CLI tool:

```bash
python revnalytics.py
```

Or if made executable:

```bash
./revnalytics.py
```

The tool will:
1. Display a welcome banner
2. Prompt you to enter the path to the binary file
3. Run Ghidra analysis (may take a few minutes)
4. Send results to AI for analysis
5. Display formatted results in the terminal
6. Save complete results to `backend/outputs/`

### Example Usage

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

## 📁 Project Structure

```
PRAHARI_NFSU_2_3_2/
├── revnalytics.py            # CLI entry point
├── backend/
│   ├── ghidra_integration.py # Ghidra headless wrapper
│   ├── ai_agent.py           # AI analysis integration
│   ├── prompt_manager.py     # Prompt management
│   ├── requirements.txt      # Python dependencies
│   ├── uploads/              # Temporary file storage (gitignored)
│   └── outputs/              # Analysis results (gitignored)
├── ghidra_scripts/
│   └── extract_functions.py  # Main Ghidra analysis script
└── ai_agent_prompts/         # AI prompt templates
    ├── system_prompt.txt
    └── analysis_prompt_template.txt
```

## 🔧 Configuration

### Ghidra Settings

Update `backend/ghidra_integration.py` or set environment variables:
- `GHIDRA_HOME`: Path to Ghidra installation
- `GHIDRA_PROJECTS_DIR`: Directory for Ghidra projects
- `GHIDRA_TIMEOUT`: Analysis timeout in seconds (default: 600)

### AI Agent Settings

The system supports multiple LLM providers with automatic fallback:
- **Fallback order**: OpenAI → Perplexity → DeepSeek → Mistral → Hugging Face → Basic
- All LLMs use the same prompts from `ai_agent_prompts/` directory
- Configure API keys in `backend/.env` file
- If no API keys are provided, the system uses basic rule-based analysis

To customize models, edit `backend/ai_agent.py`:
- OpenAI: Change `gpt-4o-mini` to `gpt-4` for better analysis
- Perplexity: Change `sonar-pro` to `sonar` for faster/cheaper
- DeepSeek: Uses `deepseek-chat` model
- Mistral: Change `mistral-medium-latest` to `mistral-small-latest` for faster/cheaper
- Temperature: Adjust for more/less creative responses (default: 0.3)
- Max tokens: Increase for longer explanations (default: 1500)

## 📊 Analysis Output

The system generates:

1. **Ghidra JSON Output**: Technical analysis including:
   - Functions and decompiled code
   - Assembly instructions
   - Imported libraries
   - Risk indicators
   - Strings and entry points

2. **AI Explanation**: Simple, non-technical summary displayed in terminal

3. **Safety Assessment**: 
   - Verdict: SAFE, SUSPICIOUS, or MALICIOUS (color-coded)
   - Confidence: HIGH, MEDIUM, or LOW
   - Reasoning: Brief explanation

4. **Saved Results**: Complete analysis saved to `backend/outputs/{analysis_id}_complete.json`

## 🛡️ Security Features

- File type validation
- File size limits (max 100MB)
- Secure file handling
- Timeout protection
- Error handling and logging

## 🐛 Troubleshooting

### Ghidra Not Found
- Verify `GHIDRA_HOME` is set correctly
- Check that `analyzeHeadless` script exists
- Ensure Ghidra is executable

### Analysis Timeout
- Increase `GHIDRA_TIMEOUT` in `ghidra_integration.py` or `.env` file
- Check file size (very large binaries may need more time)

### AI Analysis Not Working
- Verify at least one API key is set (OPENAI_API_KEY, PERPLEXITY_API_KEY, DEEPSEEK_API_KEY, MISTRAL_API_KEY, or HUGGINGFACE_API_KEY)
- Check API quota/limits for the provider you're using
- System will automatically try other providers if one fails
- System will fall back to rule-based analysis if all AI providers unavailable

### File Path Issues
- Use absolute paths or paths relative to current directory
- Paths with spaces should work, but you can use quotes if needed
- Tilde expansion (~) is supported for home directory

## 📝 License

This project is for educational and research purposes.

## 🙏 Acknowledgments

- Ghidra by NSA
- OpenAI, Perplexity, DeepSeek, Mistral, and Hugging Face for AI capabilities
