# RAVEN Project Memory

## Project Overview
RAVEN (Reverse Analysis & Vulnerability Exploitation Network) is an AI-powered offensive security research platform at `/Users/hemparekh/Desktop/raven/`.

## Architecture
- **Layout**: Python src-layout (`src/raven/`), `from __future__ import annotations` everywhere
- **CLI**: Click framework with Rich terminal output (`raven.cli.main:cli`)
- **Agents**: BaseAgent ABC pattern in `raven.agents.base` (name, description, execute(task) -> AgentResult)
- **Memory**: SessionMemory > AgentMemory > FindingsStore (in-process, per session)
- **MessageBus**: Pub/sub in `raven.core.message_bus`
- **LLM**: StubProvider default (no crash when no LLM), supports Ollama/OpenAI
- **Config**: `RavenConfig` at `raven.core.config`, env vars RAVEN_CONFIG_DIR / RAVEN_DATA_DIR
- **KnowledgeBase**: SQLite at `~/.local/share/raven/knowledge.db`
- **Learning**: Separate SQLite at `~/.local/share/raven/learning.db`

## Phase Status
- **Phase 1 (Foundation)**: COMPLETE - 94 tests, CLI, config, logging, binary loader, Scout agent
- **Phase 2 (Core Capabilities)**: COMPLETE - 204 tests, 79% coverage, patterns, matcher, KB, Analyst, Weaponizer, scan/exploit commands
- **Phase 3 (Advanced Features)**: COMPLETE - 401 tests, 84% coverage

## Key Files
### Phase 3 Modules
- `src/raven/exploitation/advanced_rop.py` - ROP/SROP/JOP, gadget finding, chain building (97% cov)
- `src/raven/exploitation/heap.py` - Heap vulns, detection, primitives, templates (99% cov)
- `src/raven/exploitation/shellcode.py` - Pre-built shellcode library, multi-arch (100% cov)
- `src/raven/exploitation/encoders.py` - XOR, alphanumeric, null-byte elimination (99% cov)
- `src/raven/agents/validator.py` - Exploit testing: Docker/local/QEMU, failure analysis (85% cov)
- `src/raven/cli/commands/validate_cmd.py` - `raven validate` command (85% cov)
- `src/raven/core/learning.py` - Feedback loop, technique stats, recommendations (96% cov)

## Test Conventions
- conftest.py: `tmp_dir` fixture, `_isolate_config` autouse (env vars for data dir)
- Class-based tests: `class TestXxx`
- Use `pytest.fixture` for config/session/kb setup
- CliRunner for Click testing (no `mix_stderr=False` - not supported in this Click version)

## Known Issues / Quirks
- Python 3.10 (not 3.11+), so no `tomllib` in stdlib
- macOS `/bin/ls` is a fat binary (0xCAFEBABE magic) - binary loader handles this
- Click's `mix_stderr=False` not supported - removed from test runner
- Shellcode x86_64 execve is 25 bytes (not 23 as noted in description comment)
- Encoders x86 stub needed explicit `+` concatenation operators (implicit concat broken with bytes([]) interleaved)

## Available CLI Commands
`analyze`, `config`, `agent`, `scan`, `exploit`, `validate`

## Available Agents
scout (P1), analyst (P2), weaponizer (P2), validator (P3) - all status "available"
coordinator - still "planned"
