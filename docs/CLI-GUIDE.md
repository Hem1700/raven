# RAVEN CLI Guide

Complete command reference for the RAVEN CLI tool.

---

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Global Options](#global-options)
3. [Commands](#commands)
   - [analyze](#analyze)
   - [scan](#scan)
   - [exploit](#exploit)
   - [validate](#validate)
   - [agent](#agent)
   - [learn](#learn)
   - [interactive](#interactive)
   - [config](#config)
   - [project](#project)
   - [report](#report)
4. [Workflows](#workflows)
5. [Configuration](#configuration)
6. [Tips & Tricks](#tips--tricks)

---

## Installation & Setup

### Installation

```bash
# Install via pip (when released)
pip install raven-security

# Or install from source
git clone https://github.com/yourusername/raven.git
cd raven
pip install -e .
```

### Initial Setup

```bash
# Initialize configuration
raven config init

# Set up LLM provider (optional - for cloud LLMs)
raven config set llm.provider openai
raven config set llm.api_key YOUR_API_KEY

# Or use local LLM
raven config set llm.local true
raven config set llm.model llama3
```

### Verify Installation

```bash
raven --version
raven --help
```

---

## Global Options

These options work with all commands:

```bash
--config PATH          Use custom config file
--verbose, -v          Verbose output
--debug               Debug mode with detailed logs
--quiet, -q           Minimal output
--no-color            Disable colored output
--format FORMAT       Output format (text|json|markdown)
--local-llm           Use local LLM only (privacy mode)
--profile PROFILE     Use named profile
--help                Show help message
```

### Examples

```bash
# Verbose mode with JSON output
raven analyze binary --verbose --format json

# Debug mode with local LLM
raven exploit binary --debug --local-llm

# Use custom config
raven scan binary --config ~/my-config.yaml
```

---

## Commands

### analyze

Perform binary analysis with semantic understanding.

#### Syntax
```bash
raven analyze <binary> [OPTIONS]
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--deep` | Deep analysis with LLM semantic understanding | False |
| `--function NAME` | Analyze specific function | All |
| `--output PATH` | Export results to file | stdout |
| `--format FORMAT` | Output format (text\|json\|markdown) | text |
| `--plugins PLUGINS` | Comma-separated analysis plugins | basic |
| `--arch ARCH` | Override architecture detection | auto |
| `--base ADDRESS` | Set base address | 0x400000 |
| `--symbols PATH` | Load symbols file | None |
| `--explain` | Include detailed explanations | False |

#### Examples

```bash
# Basic analysis
raven analyze ./binary

# Deep analysis with all plugins
raven analyze ./binary --deep --plugins all

# Analyze specific function
raven analyze ./binary --function main --explain

# Export results to JSON
raven analyze ./binary --output analysis.json --format json

# Override architecture
raven analyze ./firmware.bin --arch arm --base 0x8000000
```

#### Output

```
╭─────────────────────────────────────────╮
│        Binary Analysis Report           │
├─────────────────────────────────────────┤
│ File: ./binary                          │
│ Format: ELF 64-bit                      │
│ Architecture: x86_64                    │
│ Entry Point: 0x401000                   │
├─────────────────────────────────────────┤
│ Security Mechanisms:                    │
│   ✓ PIE: Enabled                        │
│   ✓ NX: Enabled                         │
│   ✗ Canary: Disabled                    │
│   ✓ ASLR: Enabled                       │
├─────────────────────────────────────────┤
│ Functions Identified: 42                │
│ Strings Extracted: 156                  │
│ Imports: 23                             │
│ Exports: 5                              │
╰─────────────────────────────────────────╯

Key Functions:
  • main (0x401150) - Entry point
  • vulnerable_func (0x401200) - Potential buffer overflow
  • process_input (0x401300) - User input handler
```

---

### scan

Scan for vulnerabilities using AI-powered pattern recognition.

#### Syntax
```bash
raven scan <binary> [OPTIONS]
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--type TYPE` | Vulnerability type to scan | all |
| `--exploitable` | Check exploit feasibility | False |
| `--ai-powered` | Use AI pattern recognition | False |
| `--confidence MIN` | Minimum confidence score (0-100) | 70 |
| `--output PATH` | Export findings to file | stdout |
| `--severity LEVEL` | Filter by severity | all |

#### Vulnerability Types

- `memory-corruption`: Buffer overflows, use-after-free, etc.
- `logic`: Logic bugs and business logic flaws
- `race`: Race conditions
- `format-string`: Format string vulnerabilities
- `integer`: Integer overflows/underflows
- `all`: All vulnerability types

#### Examples

```bash
# Basic vulnerability scan
raven scan ./binary

# AI-powered scan with high confidence
raven scan ./binary --ai-powered --confidence 85

# Scan for memory corruption only
raven scan ./binary --type memory-corruption

# Check exploitation feasibility
raven scan ./binary --exploitable

# Filter critical vulnerabilities
raven scan ./binary --severity critical --output vulns.json
```

#### Output

```
╭────────────────────────────────────────────╮
│       Vulnerability Scan Results           │
├────────────────────────────────────────────┤
│ Target: ./binary                           │
│ Scan Type: All                             │
│ AI-Powered: Yes                            │
├────────────────────────────────────────────┤
│ Vulnerabilities Found: 3                   │
╰────────────────────────────────────────────╯

[CRITICAL] VULN_001: Buffer Overflow
  Location: vulnerable_func+0x45 (0x401245)
  Confidence: 95%
  Exploitable: Yes
  Description: Stack buffer overflow in read() call

  Affected Code:
    char buffer[64];
    read(fd, buffer, 256);  // Reads 256 bytes into 64-byte buffer

  Exploitation: Likely exploitable via ROP chain

[HIGH] VULN_002: Format String
  Location: log_message+0x12 (0x401312)
  Confidence: 88%
  Exploitable: Possible
  Description: Format string vulnerability in printf

  Affected Code:
    printf(user_input);  // Unsanitized user input

[MEDIUM] VULN_003: Integer Overflow
  Location: allocate_buffer+0x23 (0x401423)
  Confidence: 75%
  Exploitable: Unknown
  Description: Potential integer overflow in size calculation
```

---

### exploit

Generate exploits for discovered vulnerabilities.

#### Syntax
```bash
raven exploit <binary> [OPTIONS]
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--vuln-id ID` | Target specific vulnerability | First found |
| `--auto` | Fully autonomous exploitation | False |
| `--technique TECH` | Exploitation technique | auto |
| `--target PLATFORM` | Target platform | auto |
| `--payload TYPE` | Payload type | shell |
| `--output PATH` | Save exploit to file | exploit.py |
| `--validate` | Test exploit after generation | False |
| `--iterations N` | Number of variations to try | 3 |

#### Exploitation Techniques

- `rop`: Return-Oriented Programming
- `jop`: Jump-Oriented Programming
- `heap`: Heap exploitation
- `format-string`: Format string exploitation
- `auto`: Automatically select best technique

#### Payload Types

- `shell`: Reverse/bind shell
- `exec`: Execute arbitrary command
- `privesc`: Privilege escalation
- `custom`: Custom payload

#### Examples

```bash
# Automatic exploitation
raven exploit ./binary --auto

# Exploit specific vulnerability
raven exploit ./binary --vuln-id VULN_001

# Generate ROP-based exploit
raven exploit ./binary --technique rop --validate

# Custom payload
raven exploit ./binary --payload exec --cmd "/bin/sh"

# Target specific platform
raven exploit ./binary --target linux-x64 --output my_exploit.py

# Try multiple approaches
raven exploit ./binary --iterations 5
```

#### Output

```
╭────────────────────────────────────────────╮
│          Exploit Generation                │
├────────────────────────────────────────────┤
│ Target: ./binary                           │
│ Vulnerability: VULN_001 (Buffer Overflow)  │
│ Technique: ROP                             │
│ Platform: linux-x64                        │
├────────────────────────────────────────────┤
│ Status: Success                            │
│ Reliability: 87%                           │
│ Output: exploit.py                         │
╰────────────────────────────────────────────╯

Exploit Strategy:
  1. Overflow buffer to overwrite return address
  2. Build ROP chain using gadgets from libc
  3. Call execve("/bin/sh", NULL, NULL)

Generated Exploit: exploit.py
  • Lines of code: 127
  • ROP gadgets used: 8
  • Payload size: 184 bytes

Usage:
  python exploit.py <host> <port>

Notes:
  • ASLR bypass required - using info leak
  • Reliable on Ubuntu 20.04+ with default libc
  • May need adjustment for other environments
```

---

### validate

Validate exploit reliability and effectiveness.

#### Syntax
```bash
raven validate <exploit> --target <binary> [OPTIONS]
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target BINARY` | Target binary | Required |
| `--envs ENVS` | Test environments | local |
| `--iterations N` | Number of test runs | 10 |
| `--report` | Generate detailed report | False |
| `--fix-failures` | Attempt to fix failing exploits | False |

#### Environments

- `local`: Local system
- `docker`: Docker containers
- `qemu`: QEMU emulation
- `remote`: Remote target

#### Examples

```bash
# Basic validation
raven validate exploit.py --target ./binary

# Test across multiple environments
raven validate exploit.py --target ./binary --envs docker,qemu

# Reliability testing
raven validate exploit.py --target ./binary --iterations 100

# Generate report
raven validate exploit.py --target ./binary --report --output report.pdf

# Auto-fix failures
raven validate exploit.py --target ./binary --fix-failures
```

#### Output

```
╭────────────────────────────────────────────╮
│        Exploit Validation Report           │
├────────────────────────────────────────────┤
│ Exploit: exploit.py                        │
│ Target: ./binary                           │
│ Iterations: 100                            │
├────────────────────────────────────────────┤
│ Success Rate: 87/100 (87%)                 │
│ Average Time: 1.2s                         │
│ Status: RELIABLE                           │
╰────────────────────────────────────────────╯

Results by Environment:
  • Local: 89/100 (89%)
  • Docker: 85/100 (85%)
  • QEMU: 87/100 (87%)

Failure Analysis:
  • 8 failures: Timing issues (non-critical)
  • 3 failures: Memory alignment (rare)
  • 2 failures: Unknown (investigating)

Recommendations:
  ✓ Exploit is reliable for production use
  • Consider adding retry logic for timing issues
  • Test on target environment before deployment
```

---

### agent

Manage AI agents.

#### Syntax
```bash
raven agent <subcommand> [OPTIONS]
```

#### Subcommands

| Subcommand | Description |
|------------|-------------|
| `list` | List all agents |
| `start NAME` | Start specific agent |
| `stop NAME` | Stop running agent |
| `status` | Show agent status |
| `create` | Create custom agent |
| `logs NAME` | View agent logs |

#### Examples

```bash
# List all agents
raven agent list

# Start analyst agent
raven agent start analyst

# View agent status
raven agent status

# View agent logs
raven agent logs weaponizer

# Create custom agent
raven agent create --name custom-agent --template base
```

---

### learn

Train and improve RAVEN's AI capabilities.

#### Syntax
```bash
raven learn [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--cve-db PATH` | Import CVE database |
| `--patterns PATH` | Import exploit patterns |
| `--fine-tune` | Fine-tune local LLM |
| `--data PATH` | Training data path |
| `--validate` | Validate after training |

#### Examples

```bash
# Import CVE database
raven learn --cve-db ./cve-database/

# Import custom patterns
raven learn --patterns ./my-patterns.json

# Fine-tune local LLM
raven learn --fine-tune --data ./training-data/ --validate
```

---

### interactive

Start interactive analysis session.

#### Syntax
```bash
raven interactive <binary> [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--learning-mode` | Enable educational mode |
| `--auto-analyze` | Analyze on start |

#### Examples

```bash
# Start interactive session
raven interactive ./binary

# Learning mode
raven interactive ./binary --learning-mode
```

#### Interactive Commands

```
> analyze                 # Analyze current binary
> scan                    # Scan for vulnerabilities
> exploit VULN_ID        # Generate exploit
> explain FUNCTION       # Explain function
> find PATTERN          # Find code pattern
> help                   # Show help
> exit                   # Exit session
```

---

### config

Manage configuration.

#### Syntax
```bash
raven config <subcommand> [OPTIONS]
```

#### Subcommands

| Subcommand | Description |
|------------|-------------|
| `init` | Initialize configuration |
| `show` | Display current config |
| `set KEY VALUE` | Set configuration value |
| `get KEY` | Get configuration value |
| `edit` | Open config in editor |

#### Examples

```bash
# Initialize config
raven config init

# View configuration
raven config show

# Set values
raven config set llm.provider openai
raven config set llm.model gpt-4

# Get value
raven config get llm.provider

# Edit in editor
raven config edit
```

---

### project

Manage research projects.

#### Syntax
```bash
raven project <subcommand> [OPTIONS]
```

#### Subcommands

| Subcommand | Description |
|------------|-------------|
| `create NAME` | Create new project |
| `load NAME` | Load existing project |
| `list` | List all projects |
| `delete NAME` | Delete project |
| `export NAME` | Export project |
| `import PATH` | Import project |

#### Examples

```bash
# Create project
raven project create malware-analysis

# Load project
raven project load malware-analysis

# List projects
raven project list

# Export project
raven project export malware-analysis --output project.zip
```

---

### report

Generate reports from analysis sessions.

#### Syntax
```bash
raven report [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--session ID` | Session to report on |
| `--type TYPE` | Report type |
| `--format FORMAT` | Output format |
| `--output PATH` | Save to file |
| `--include-logs` | Include detailed logs |

#### Report Types

- `full`: Complete analysis report
- `analysis`: Binary analysis only
- `exploit`: Exploitation details
- `validation`: Validation results

#### Examples

```bash
# Generate full report
raven report --session SESSION_ID --format pdf

# Analysis report
raven report --type analysis --format markdown --output report.md

# Include detailed logs
raven report --session SESSION_ID --include-logs
```

---

## Workflows

### Workflow 1: Quick CTF Challenge

```bash
# Analyze, scan, exploit in sequence
raven analyze challenge.bin
raven scan challenge.bin --type memory-corruption
raven exploit challenge.bin --auto --validate
```

### Workflow 2: Deep Research

```bash
# Create project
raven project create firmware-research

# Deep analysis
raven analyze firmware.bin --deep --plugins all

# Interactive exploration
raven interactive firmware.bin

# Generate report
raven report --type full --format pdf
```

### Workflow 3: Automated Pipeline

```bash
#!/bin/bash
# Automated security testing pipeline

# Analyze
raven analyze "$1" --output analysis.json --format json

# Scan
raven scan "$1" --ai-powered --output vulns.json --format json

# Exploit all vulnerabilities
for vuln in $(jq -r '.vulnerabilities[].id' vulns.json); do
    raven exploit "$1" --vuln-id "$vuln" --validate
done

# Generate report
raven report --format pdf --output final-report.pdf
```

---

## Configuration

### Configuration File

Location: `~/.config/raven/config.yaml`

```yaml
# LLM Configuration
llm:
  provider: openai  # openai, anthropic, local
  model: gpt-4
  api_key: YOUR_API_KEY
  local: false
  local_model: llama3

# Analysis Settings
analysis:
  default_plugins: [basic, vuln-scan]
  deep_analysis: false
  timeout: 300

# Exploitation Settings
exploitation:
  default_technique: auto
  default_payload: shell
  validate_after_gen: true
  iterations: 3

# Agent Settings
agents:
  coordinator: true
  max_concurrent: 4
  timeout: 600

# Output Settings
output:
  format: text
  color: true
  verbose: false

# Security Settings
security:
  require_confirmation: true
  log_operations: true
  sandbox_validation: true
```

---

## Tips & Tricks

### Performance Optimization

```bash
# Use local LLM for faster analysis
raven analyze binary --local-llm

# Limit analysis scope
raven analyze binary --function main

# Use JSON for programmatic access
raven analyze binary --format json | jq '.functions'
```

### Debugging

```bash
# Enable debug mode
raven analyze binary --debug

# View agent logs
raven agent logs analyst

# Verbose output
raven exploit binary --verbose
```

### Batch Processing

```bash
# Analyze multiple binaries
for binary in ./bins/*; do
    raven analyze "$binary" --output "analysis_$(basename $binary).json"
done

# Parallel processing
find ./bins -type f | parallel raven analyze {} --output {.}.json
```

### Integration with Other Tools

```bash
# Pipe to other tools
raven analyze binary --format json | jq '.vulnerabilities'

# Use with scripts
vuln_count=$(raven scan binary --format json | jq '.vulnerabilities | length')
if [ "$vuln_count" -gt 0 ]; then
    raven exploit binary --auto
fi
```

---

**For more information, see the [Product Documentation](PRODUCT.md).**
