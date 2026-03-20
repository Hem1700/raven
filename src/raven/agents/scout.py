"""
RAVEN Scout Agent.

Performs initial reconnaissance and attack surface mapping on a binary:
  - Security mechanism detection (PIE, NX, canary, RELRO, ASLR)
  - Entry point identification
  - Import analysis for dangerous function usage
  - String-based intelligence gathering
  - Attack surface assessment
  - LLM-powered deep analysis (optional)
"""

from __future__ import annotations

import re
from typing import Any

from raven.agents.base import AgentResult, AgentTask, BaseAgent
from raven.analysis.binary_loader import BinaryInfo
from raven.core.config import RavenConfig
from raven.core.llm import PROMPTS, BaseLLMProvider, create_llm_provider
from raven.core.logger import get_logger
from raven.core.memory import Finding, Severity

logger = get_logger("agents.scout")


# ---------------------------------------------------------------------------
# Dangerous function categories
# ---------------------------------------------------------------------------

# Functions that are commonly associated with security vulnerabilities
_DANGEROUS_FUNCTIONS: dict[str, dict[str, str]] = {
    # Buffer overflow risks
    "gets": {"category": "buffer_overflow", "severity": "critical",
             "desc": "Unbounded read into buffer - always exploitable"},
    "strcpy": {"category": "buffer_overflow", "severity": "high",
               "desc": "No bounds checking on copy"},
    "strcat": {"category": "buffer_overflow", "severity": "high",
               "desc": "No bounds checking on concatenation"},
    "sprintf": {"category": "buffer_overflow", "severity": "high",
                "desc": "No bounds checking on formatted output"},
    "vsprintf": {"category": "buffer_overflow", "severity": "high",
                 "desc": "No bounds checking on formatted output"},
    "scanf": {"category": "buffer_overflow", "severity": "medium",
              "desc": "Potential buffer overflow without width specifier"},
    "read": {"category": "buffer_overflow", "severity": "low",
             "desc": "Manual length management needed"},

    # Format string risks
    "printf": {"category": "format_string", "severity": "medium",
               "desc": "Potential format string if user-controlled argument"},
    "fprintf": {"category": "format_string", "severity": "medium",
                "desc": "Potential format string if user-controlled argument"},
    "syslog": {"category": "format_string", "severity": "medium",
               "desc": "Potential format string vulnerability"},

    # Memory management
    "malloc": {"category": "heap", "severity": "info",
               "desc": "Dynamic allocation - check for use-after-free"},
    "free": {"category": "heap", "severity": "info",
             "desc": "Deallocation - check for double-free"},
    "realloc": {"category": "heap", "severity": "low",
                "desc": "Reallocation may return new pointer"},
    "calloc": {"category": "heap", "severity": "info",
               "desc": "Dynamic allocation"},

    # System interaction
    "system": {"category": "command_injection", "severity": "high",
               "desc": "Command execution - check for injection"},
    "popen": {"category": "command_injection", "severity": "high",
              "desc": "Command execution via shell"},
    "execve": {"category": "command_injection", "severity": "medium",
               "desc": "Direct program execution"},
    "execl": {"category": "command_injection", "severity": "medium",
              "desc": "Direct program execution"},
    "execvp": {"category": "command_injection", "severity": "medium",
               "desc": "Program execution with PATH search"},

    # File operations
    "open": {"category": "file_ops", "severity": "low",
             "desc": "File open - check for path traversal"},
    "fopen": {"category": "file_ops", "severity": "low",
              "desc": "File open - check for path traversal"},
    "access": {"category": "race_condition", "severity": "low",
               "desc": "TOCTOU race condition risk"},

    # Network
    "recv": {"category": "network", "severity": "medium",
             "desc": "Network input - untrusted data source"},
    "recvfrom": {"category": "network", "severity": "medium",
                 "desc": "Network input - untrusted data source"},
    "connect": {"category": "network", "severity": "info",
                "desc": "Network connection"},
    "bind": {"category": "network", "severity": "info",
             "desc": "Network listening"},
    "send": {"category": "network", "severity": "info",
             "desc": "Network output"},
}

# Interesting string patterns
_INTERESTING_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)password", "credential"),
    (r"(?i)secret", "credential"),
    (r"(?i)token", "credential"),
    (r"(?i)api[_\-]?key", "credential"),
    (r"/bin/sh", "shell"),
    (r"/bin/bash", "shell"),
    (r"cmd\.exe", "shell"),
    (r"(?i)debug", "debug"),
    (r"(?i)admin", "privilege"),
    (r"(?i)root", "privilege"),
    (r"http://", "url"),
    (r"https://", "url"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "ip_address"),
    (r"(?i)sql", "database"),
    (r"(?i)select\s.*from", "sql_query"),
    (r"%[dsxnp]", "format_string"),
    (r"(?i)flag\{", "ctf_flag"),
]


# ---------------------------------------------------------------------------
# Scout Agent
# ---------------------------------------------------------------------------

class ScoutAgent(BaseAgent):
    """Reconnaissance agent for initial binary analysis.

    The Scout agent is the first agent in the analysis pipeline. It
    performs lightweight static analysis to build a security profile
    of the target binary.
    """

    name = "scout"
    description = "Reconnaissance and attack surface mapping"

    def execute(self, task: AgentTask) -> AgentResult:
        """Execute a Scout reconnaissance task.

        Expected ``task.parameters``:
            - ``binary_info``: :class:`BinaryInfo` instance
            - ``deep``: bool (optional, default False)
            - ``function_name``: str (optional, specific function to focus on)
        """
        binary_info: BinaryInfo = task.parameters.get("binary_info")
        deep: bool = task.parameters.get("deep", False)
        function_name: str | None = task.parameters.get("function_name")

        if binary_info is None:
            return AgentResult(
                task_id=task.id,
                agent=self.name,
                success=False,
                errors=["No binary_info provided"],
            )

        self.publish_status("analyzing", binary=str(binary_info.path))
        report = self.analyze(binary_info, deep=deep, function_name=function_name)

        return AgentResult(
            task_id=task.id,
            agent=self.name,
            success=True,
            data=report,
            findings=list(self.session.findings.by_agent(self.name)),
        )

    def analyze(
        self,
        binary_info: BinaryInfo,
        deep: bool = False,
        function_name: str | None = None,
    ) -> dict[str, Any]:
        """Perform full Scout analysis and return a report dict.

        This is the main entry point used by the ``raven analyze`` command.

        Args:
            binary_info: Loaded binary metadata.
            deep: If True, invoke the LLM for semantic analysis.
            function_name: Optionally focus on a specific function.

        Returns:
            A report dict suitable for :func:`print_analysis_report`.
        """
        self._logger.info("Scout analysis starting for %s", binary_info.path.name)
        self.memory.remember("target", str(binary_info.path))

        # 1. Security assessment
        security_findings = self._assess_security(binary_info)

        # 2. Dangerous imports analysis
        import_findings = self._analyze_imports(binary_info)

        # 3. String intelligence
        string_intel = self._analyze_strings(binary_info)

        # 4. Attack surface mapping
        attack_surface = self._map_attack_surface(binary_info)

        # 5. Function analysis
        functions = self._analyze_functions(binary_info, function_name)

        # 6. (Optional) LLM deep analysis
        llm_analysis = ""
        if deep:
            llm_analysis = self._deep_analysis(binary_info)

        # Build the report
        report: dict[str, Any] = {
            "file": str(binary_info.path),
            "format": f"{binary_info.file_format} {binary_info.bits}-bit",
            "arch": binary_info.arch,
            "endian": binary_info.endian,
            "entry_point": hex(binary_info.entry_point),
            "base_address": hex(binary_info.base_address),
            "md5": binary_info.md5,
            "sha256": binary_info.sha256,
            "security": binary_info.security_summary,
            "stats": {
                "functions": len(binary_info.functions()),
                "strings": len(binary_info.strings),
                "imports": len(binary_info.imports),
                "exports": len(binary_info.exports),
                "sections": len(binary_info.sections),
                "libraries": len(binary_info.libraries),
            },
            "functions": functions,
            "dangerous_imports": import_findings,
            "interesting_strings": string_intel,
            "attack_surface": attack_surface,
            "libraries": binary_info.libraries,
            "sections": [s.to_dict() for s in binary_info.sections],
        }

        if llm_analysis:
            report["llm_analysis"] = llm_analysis

        self.memory.remember("report", report)
        self._logger.info("Scout analysis complete for %s", binary_info.path.name)
        return report

    # ------------------------------------------------------------------
    # Internal analysis methods
    # ------------------------------------------------------------------

    def _assess_security(self, info: BinaryInfo) -> list[dict[str, Any]]:
        """Assess security mechanisms and generate findings for weak ones."""
        findings: list[dict[str, Any]] = []

        if not info.pie:
            f = Finding(
                title="PIE Disabled",
                description=(
                    "Position Independent Executable is disabled. "
                    "The binary is loaded at a fixed address, making "
                    "return-to-libc and ROP attacks easier."
                ),
                severity=Severity.MEDIUM,
                confidence=100.0,
                location="binary",
            )
            self.add_finding(f)
            findings.append(f.to_dict())

        if not info.nx:
            f = Finding(
                title="NX Disabled (Executable Stack)",
                description=(
                    "The stack is executable. Shellcode can be placed "
                    "directly on the stack and executed."
                ),
                severity=Severity.HIGH,
                confidence=100.0,
                location="binary",
            )
            self.add_finding(f)
            findings.append(f.to_dict())

        if not info.canary:
            f = Finding(
                title="Stack Canary Disabled",
                description=(
                    "No stack canary protection detected. Stack buffer "
                    "overflows can directly overwrite the return address."
                ),
                severity=Severity.MEDIUM,
                confidence=100.0,
                location="binary",
            )
            self.add_finding(f)
            findings.append(f.to_dict())

        if info.relro == "none":
            f = Finding(
                title="No RELRO",
                description=(
                    "No RELRO protection. The GOT is writable, enabling "
                    "GOT overwrite attacks."
                ),
                severity=Severity.MEDIUM,
                confidence=100.0,
                location="binary",
            )
            self.add_finding(f)
            findings.append(f.to_dict())
        elif info.relro == "partial":
            f = Finding(
                title="Partial RELRO",
                description=(
                    "Partial RELRO enabled. The GOT is partially protected "
                    "but some entries remain writable."
                ),
                severity=Severity.LOW,
                confidence=100.0,
                location="binary",
            )
            self.add_finding(f)
            findings.append(f.to_dict())

        return findings

    def _analyze_imports(self, info: BinaryInfo) -> list[dict[str, Any]]:
        """Identify dangerous imported functions."""
        results: list[dict[str, Any]] = []

        for imp in info.imports:
            # Strip possible @plt or version suffixes
            clean_name = imp.split("@")[0]
            entry = _DANGEROUS_FUNCTIONS.get(clean_name)
            if entry:
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "info": Severity.INFO,
                }
                sev = severity_map.get(entry["severity"], Severity.INFO)

                record = {
                    "function": imp,
                    "category": entry["category"],
                    "severity": entry["severity"],
                    "description": entry["desc"],
                }
                results.append(record)

                # Only create findings for medium severity and above
                if sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                    f = Finding(
                        title=f"Dangerous Import: {imp}",
                        description=entry["desc"],
                        severity=sev,
                        confidence=80.0,
                        location=f"import:{imp}",
                    )
                    self.add_finding(f)

        return results

    def _analyze_strings(self, info: BinaryInfo) -> list[str]:
        """Extract security-relevant strings from the binary."""
        interesting: list[str] = []

        for s in info.strings:
            for pattern, category in _INTERESTING_PATTERNS:
                if re.search(pattern, s):
                    interesting.append(s)
                    break

        return interesting[:50]  # Cap output

    def _map_attack_surface(self, info: BinaryInfo) -> dict[str, Any]:
        """Build an attack surface summary."""
        # Categorize imports
        categories: dict[str, list[str]] = {}
        for imp in info.imports:
            clean = imp.split("@")[0]
            entry = _DANGEROUS_FUNCTIONS.get(clean)
            if entry:
                cat = entry["category"]
                categories.setdefault(cat, []).append(clean)

        # Determine input vectors
        input_vectors: list[str] = []
        input_funcs = {"read", "recv", "recvfrom", "fread", "fgets", "gets", "scanf", "getenv"}
        for imp in info.imports:
            if imp.split("@")[0] in input_funcs:
                input_vectors.append(imp.split("@")[0])

        # Determine if binary is networked
        network_funcs = {"socket", "connect", "bind", "listen", "accept", "recv", "send"}
        is_network = bool(network_funcs.intersection(imp.split("@")[0] for imp in info.imports))

        return {
            "input_vectors": input_vectors,
            "is_network": is_network,
            "dangerous_categories": categories,
            "total_dangerous_imports": sum(len(v) for v in categories.values()),
            "libraries": info.libraries,
            "has_symbols": not info.stripped,
        }

    def _analyze_functions(
        self, info: BinaryInfo, function_name: str | None = None
    ) -> list[dict[str, Any]]:
        """Build a list of function summaries for the report."""
        funcs = info.functions()
        if function_name:
            funcs = [f for f in funcs if f.name == function_name]

        results: list[dict[str, Any]] = []
        for fn in funcs:
            entry = {
                "name": fn.name,
                "address": hex(fn.address),
                "size": fn.size,
                "type": fn.sym_type,
            }
            # Tag known dangerous functions
            clean = fn.name.split("@")[0]
            if clean in _DANGEROUS_FUNCTIONS:
                entry["dangerous"] = True
                entry["risk"] = _DANGEROUS_FUNCTIONS[clean]["severity"]
            results.append(entry)

        # Sort: entry-point-like names first, then by address
        def _sort_key(f: dict[str, Any]) -> tuple[int, int]:
            priority = 0 if f["name"] in ("main", "_start", "entry") else 1
            return (priority, int(f["address"], 16))

        results.sort(key=_sort_key)
        return results

    def _deep_analysis(self, info: BinaryInfo) -> str:
        """Use the LLM to perform a semantic security assessment."""
        if self.llm.provider_name == "none":
            self._logger.info("No LLM configured; skipping deep analysis")
            return ""

        template = PROMPTS.get("analyze_binary")
        if template is None:
            return ""

        try:
            response = self.llm.prompt(
                template,
                filename=info.path.name,
                file_format=f"{info.file_format} {info.bits}-bit {info.arch}",
                arch=info.arch,
                security=str(info.security_summary),
                imports=", ".join(info.imports[:40]),
                strings=", ".join(info.strings[:30]),
            )
            if response.ok:
                self._logger.info("LLM deep analysis complete")
                return response.content
        except Exception as exc:
            self._logger.warning("LLM deep analysis failed: %s", exc)

        return ""
