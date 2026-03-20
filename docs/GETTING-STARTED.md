# Getting Started with RAVEN

Welcome to RAVEN! This guide will help you get up and running quickly.

---

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+), macOS (12+), or Windows 10+ with WSL2
- **Python**: 3.11 or higher
- **Memory**: 8GB RAM minimum (16GB recommended for local LLMs)
- **Disk Space**: 10GB for installation, additional space for local LLMs if used

### Required Knowledge

- Basic command-line interface usage
- Familiarity with binary exploitation concepts (helpful but not required for learning mode)
- Understanding of security research ethics

---

## Installation

### Step 1: Install System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y python3.11 python3-pip git build-essential
```

#### macOS
```bash
brew install python@3.11 git
```

#### Windows (WSL2)
```bash
sudo apt update
sudo apt install -y python3.11 python3-pip git build-essential
```

### Step 2: Clone Repository

```bash
git clone https://github.com/yourusername/raven.git
cd raven
```

### Step 3: Create Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 4: Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 5: Install RAVEN

```bash
# Development installation
pip install -e .

# Or production installation (when released)
pip install raven-security
```

### Step 6: Verify Installation

```bash
raven --version
raven --help
```

---

## Configuration

### Initial Setup

```bash
# Initialize configuration
raven config init
```

This creates: `~/.config/raven/config.yaml`

### Configure LLM Provider

You have two options:

#### Option 1: Cloud LLM (Recommended for getting started)

```bash
# Using OpenAI
raven config set llm.provider openai
raven config set llm.model gpt-4
raven config set llm.api_key YOUR_OPENAI_API_KEY

# Or using Anthropic Claude
raven config set llm.provider anthropic
raven config set llm.model claude-opus-4-6
raven config set llm.api_key YOUR_ANTHROPIC_API_KEY
```

#### Option 2: Local LLM (Privacy-focused)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3

# Configure RAVEN
raven config set llm.local true
raven config set llm.local_model llama3
```

### Verify Configuration

```bash
raven config show
```

---

## Your First Analysis

### Step 1: Get a Test Binary

```bash
# Create a simple vulnerable program
cat > test.c << 'EOF'
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable!
    printf("You entered: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
EOF

# Compile it
gcc -o test_binary test.c -fno-stack-protector -z execstack -no-pie
```

### Step 2: Analyze the Binary

```bash
raven analyze ./test_binary
```

Expected output:
```
╭─────────────────────────────────────────╮
│        Binary Analysis Report           │
├─────────────────────────────────────────┤
│ File: ./test_binary                     │
│ Format: ELF 64-bit                      │
│ Architecture: x86_64                    │
│ Entry Point: 0x401000                   │
├─────────────────────────────────────────┤
│ Security Mechanisms:                    │
│   ✗ PIE: Disabled                       │
│   ✗ NX: Disabled                        │
│   ✗ Canary: Disabled                    │
│   ✗ ASLR: Disabled                      │
╰─────────────────────────────────────────╯
```

### Step 3: Scan for Vulnerabilities

```bash
raven scan ./test_binary --ai-powered
```

Expected output:
```
[CRITICAL] VULN_001: Buffer Overflow
  Location: vulnerable_function+0x12
  Confidence: 98%
  Exploitable: Yes
  Description: Stack buffer overflow in strcpy()
```

### Step 4: Generate Exploit

```bash
raven exploit ./test_binary --auto
```

Expected output:
```
Exploit generated successfully: exploit.py
Success probability: 95%

Usage:
  ./test_binary $(python exploit.py)
```

### Step 5: Validate Exploit

```bash
raven validate exploit.py --target ./test_binary
```

Expected output:
```
Success Rate: 10/10 (100%)
Status: RELIABLE
```

---

## Next Steps

### Learn More

1. **Read the Documentation**
   - [Product Documentation](PRODUCT.md) - Comprehensive overview
   - [CLI Guide](CLI-GUIDE.md) - Complete command reference
   - [Architecture](ARCHITECTURE.md) - Technical deep-dive

2. **Try Interactive Mode**
   ```bash
   raven interactive ./test_binary --learning-mode
   ```

3. **Explore Example Projects**
   ```bash
   cd examples/
   ls -la
   ```

### Common Workflows

#### CTF Challenge
```bash
raven analyze challenge.bin
raven scan challenge.bin --type all
raven exploit challenge.bin --auto --validate
```

#### Security Research
```bash
raven project create my-research
raven analyze target.bin --deep --plugins all
raven interactive target.bin
raven report --type full --format pdf
```

#### Learning Binary Exploitation
```bash
raven interactive training_binary --learning-mode
> explain buffer overflow
> analyze vulnerable_function
> generate exploit step by step
```

---

## Troubleshooting

### Installation Issues

**Problem**: `pip install` fails with compilation errors

**Solution**: Install build dependencies
```bash
# Ubuntu/Debian
sudo apt install python3-dev build-essential

# macOS
xcode-select --install
```

**Problem**: `ModuleNotFoundError`

**Solution**: Ensure virtual environment is activated
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration Issues

**Problem**: LLM API errors

**Solution**: Verify API key is set correctly
```bash
raven config get llm.api_key
# Re-set if needed
raven config set llm.api_key YOUR_KEY
```

**Problem**: Local LLM not working

**Solution**: Ensure Ollama is running
```bash
ollama serve  # In separate terminal
ollama list   # Verify model is installed
```

### Analysis Issues

**Problem**: "Unsupported binary format"

**Solution**: Explicitly specify architecture
```bash
raven analyze binary --arch x86_64
```

**Problem**: Analysis timeout

**Solution**: Increase timeout or disable deep analysis
```bash
raven config set analysis.timeout 600
# Or
raven analyze binary  # Without --deep flag
```

### Getting Help

1. **Check Documentation**: See docs/ directory
2. **View Logs**: `raven --debug <command>`
3. **GitHub Issues**: Report bugs and request features
4. **Community**: Join discussions on GitHub Discussions

---

## Best Practices

### Security

1. **Always get authorization** before testing any system
2. **Use sandboxed environments** for exploit validation
3. **Keep audit logs** of all operations
4. **Follow responsible disclosure** for any vulnerabilities found

### Performance

1. **Use local LLM** for repetitive tasks to save API costs
2. **Cache analysis results** using projects
3. **Limit scope** with specific function analysis when possible
4. **Use JSON output** for programmatic processing

### Workflow

1. **Create projects** for organized research
2. **Use interactive mode** for exploration
3. **Generate reports** for documentation
4. **Learn from AI explanations** to improve skills

---

## What's Next?

Now that you're set up, explore these areas:

1. **[CLI Guide](CLI-GUIDE.md)** - Master all commands
2. **[Examples](../examples/)** - Learn from sample projects
3. **[Contributing](../CONTRIBUTING.md)** - Help improve RAVEN
4. **[Roadmap](ROADMAP.md)** - See what's coming next

---

## Quick Reference Card

```bash
# Analysis
raven analyze <binary>              # Basic analysis
raven analyze <binary> --deep       # Deep analysis with AI

# Scanning
raven scan <binary>                 # Find vulnerabilities
raven scan <binary> --ai-powered    # AI-powered scanning

# Exploitation
raven exploit <binary> --auto       # Auto-generate exploit
raven exploit <binary> --vuln-id ID # Target specific vuln

# Validation
raven validate exploit.py --target <binary>

# Interactive
raven interactive <binary>          # Start interactive session

# Projects
raven project create <name>         # New project
raven project load <name>           # Load project

# Configuration
raven config show                   # View config
raven config set key value          # Set config value

# Help
raven --help                        # General help
raven <command> --help              # Command-specific help
```

---

**Welcome to RAVEN! Happy hunting! 🦅**
