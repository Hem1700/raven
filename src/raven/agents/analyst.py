"""
RAVEN Analyst Agent.

Performs deep binary analysis combining static pattern matching with
LLM-powered semantic analysis:
  - Runs vulnerability patterns against the binary
  - Performs control flow analysis (basic)
  - Uses LLM for semantic understanding of findings
  - Generates exploitability assessments
  - Produces structured scan reports
"""

from __future__ import annotations

from typing import Any

from raven.agents.base import AgentResult, AgentTask, BaseAgent
from raven.analysis.binary_loader import BinaryInfo
from raven.analysis.matcher import MatchResult, PatternMatcher, scan_binary
from raven.analysis.patterns import PatternCategory, PatternDatabase
from raven.core.config import RavenConfig
from raven.core.knowledge_base import KnowledgeBase
from raven.core.llm import PROMPTS, PromptTemplate
from raven.core.logger import get_logger
from raven.core.memory import Finding, Severity

logger = get_logger("agents.analyst")


# ---------------------------------------------------------------------------
# LLM prompt templates for the Analyst agent
# ---------------------------------------------------------------------------

_VULN_ANALYSIS_PROMPT = PromptTemplate(
    name="analyst_vuln_analysis",
    system=(
        "You are RAVEN's Analyst agent, an expert in binary vulnerability analysis. "
        "Given vulnerability scan results and binary metadata, provide a detailed "
        "security assessment. Focus on exploitability, attack chains, and remediation."
    ),
    user=(
        "Analyze these vulnerability scan findings for the binary:\n\n"
        "Binary: {filename} ({file_format}, {arch})\n"
        "Security: {security}\n\n"
        "Vulnerability Findings:\n{findings}\n\n"
        "Knowledge Base Context:\n{kb_context}\n\n"
        "Provide:\n"
        "1. Risk assessment for each finding\n"
        "2. Potential attack chains combining multiple vulnerabilities\n"
        "3. Exploitability rating (trivial/easy/moderate/hard)\n"
        "4. Recommended exploitation approach\n"
        "5. Remediation suggestions"
    ),
)

_FUNCTION_ANALYSIS_PROMPT = PromptTemplate(
    name="analyst_function_analysis",
    system=(
        "You are RAVEN's Analyst agent. Analyze the security implications "
        "of specific functions in a binary, considering their imports, "
        "calling conventions, and potential vulnerability patterns."
    ),
    user=(
        "Analyze the security of these functions in {filename}:\n\n"
        "Functions: {functions}\n"
        "Imports used: {imports}\n"
        "Security mechanisms: {security}\n\n"
        "For each function, identify:\n"
        "1. Potential vulnerabilities based on imports used\n"
        "2. Attack surface (network-reachable, local, etc.)\n"
        "3. Exploitation difficulty\n"
        "4. Suggested techniques for testing"
    ),
)

# Register prompts in the global library
PROMPTS["analyst_vuln_analysis"] = _VULN_ANALYSIS_PROMPT
PROMPTS["analyst_function_analysis"] = _FUNCTION_ANALYSIS_PROMPT


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


# ---------------------------------------------------------------------------
# Analyst Agent
# ---------------------------------------------------------------------------

class AnalystAgent(BaseAgent):
    """Deep analysis agent for vulnerability discovery and assessment.

    The Analyst agent extends the Scout's reconnaissance with:
      - Pattern-based vulnerability scanning
      - LLM-powered semantic analysis of findings
      - Exploitability assessment
      - Knowledge base integration for CVE/pattern context

    It is the primary agent behind the ``raven scan`` command.
    """

    name = "analyst"
    description = "Deep binary analysis and vulnerability discovery"

    def __init__(
        self,
        config: RavenConfig,
        knowledge_base: KnowledgeBase | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(config, **kwargs)
        self._kb = knowledge_base or KnowledgeBase()
        self._pattern_db = PatternDatabase()
        self._pattern_db.load_defaults()
        self._matcher = PatternMatcher(self._pattern_db)

    def execute(self, task: AgentTask) -> AgentResult:
        """Execute an Analyst scan task.

        Expected ``task.parameters``:
            - ``binary_info``: :class:`BinaryInfo` instance
            - ``vuln_type``: str (optional, e.g. ``memory-corruption``)
            - ``min_confidence``: float (optional, default 0)
            - ``min_severity``: str (optional)
            - ``exploitable_only``: bool (optional, default False)
            - ``ai_powered``: bool (optional, default False)
        """
        binary_info: BinaryInfo = task.parameters.get("binary_info")
        vuln_type: str | None = task.parameters.get("vuln_type")
        min_confidence: float = task.parameters.get("min_confidence", 0.0)
        min_severity: str | None = task.parameters.get("min_severity")
        exploitable_only: bool = task.parameters.get("exploitable_only", False)
        ai_powered: bool = task.parameters.get("ai_powered", False)

        if binary_info is None:
            return AgentResult(
                task_id=task.id,
                agent=self.name,
                success=False,
                errors=["No binary_info provided"],
            )

        self.publish_status("scanning", binary=str(binary_info.path))

        report = self.scan(
            binary_info,
            vuln_type=vuln_type,
            min_confidence=min_confidence,
            min_severity=min_severity,
            exploitable_only=exploitable_only,
            ai_powered=ai_powered,
        )

        return AgentResult(
            task_id=task.id,
            agent=self.name,
            success=True,
            data=report,
            findings=list(self.session.findings.by_agent(self.name)),
        )

    def scan(
        self,
        binary_info: BinaryInfo,
        *,
        vuln_type: str | None = None,
        min_confidence: float = 0.0,
        min_severity: str | None = None,
        exploitable_only: bool = False,
        ai_powered: bool = False,
    ) -> dict[str, Any]:
        """Perform a full vulnerability scan on the binary.

        This is the main entry point used by the ``raven scan`` command.

        Args:
            binary_info: Loaded binary metadata.
            vuln_type: Filter by vulnerability type (memory-corruption, format-string, etc.).
            min_confidence: Minimum confidence threshold (0-100).
            min_severity: Minimum severity level (critical/high/medium/low/info).
            exploitable_only: Only include exploitable findings.
            ai_powered: Use LLM for semantic analysis of findings.

        Returns:
            A scan report dict suitable for output formatting.
        """
        self._logger.info("Analyst scan starting for %s", binary_info.path.name)
        self.memory.remember("target", str(binary_info.path))

        # 1. Run pattern matching
        categories = self._resolve_categories(vuln_type)
        matches = self._matcher.match(
            binary_info,
            categories=categories,
            min_confidence=min_confidence,
            min_severity=min_severity,
        )

        # 2. Filter to exploitable only if requested
        if exploitable_only:
            matches = [m for m in matches if m.exploitable]

        # 3. Create findings from matches
        for match in matches:
            self._create_finding(match, binary_info)

        # 4. Basic control flow analysis
        control_flow = self._basic_control_flow(binary_info)

        # 5. LLM-powered semantic analysis (optional)
        llm_analysis = ""
        if ai_powered:
            llm_analysis = self._semantic_analysis(binary_info, matches)

        # 6. Build the report
        report: dict[str, Any] = {
            "file": str(binary_info.path),
            "format": f"{binary_info.file_format} {binary_info.bits}-bit",
            "arch": binary_info.arch,
            "security": binary_info.security_summary,
            "scan_summary": {
                "total_patterns_checked": self._pattern_db.count(),
                "total_matches": len(matches),
                "critical": sum(1 for m in matches if m.severity == "critical"),
                "high": sum(1 for m in matches if m.severity == "high"),
                "medium": sum(1 for m in matches if m.severity == "medium"),
                "low": sum(1 for m in matches if m.severity == "low"),
                "info": sum(1 for m in matches if m.severity == "info"),
                "exploitable": sum(1 for m in matches if m.exploitable),
            },
            "vulnerabilities": [m.to_dict() for m in matches],
            "control_flow": control_flow,
        }

        if llm_analysis:
            report["llm_analysis"] = llm_analysis

        self.memory.remember("scan_report", report)
        self._logger.info(
            "Analyst scan complete: %d vulnerabilities found", len(matches)
        )
        return report

    # ------------------------------------------------------------------
    # Internal analysis methods
    # ------------------------------------------------------------------

    def _resolve_categories(
        self, vuln_type: str | None
    ) -> list[PatternCategory] | None:
        """Map a user-facing vulnerability type string to pattern categories."""
        if vuln_type is None:
            return None

        _TYPE_MAP: dict[str, list[PatternCategory]] = {
            "memory-corruption": [
                PatternCategory.BUFFER_OVERFLOW,
                PatternCategory.HEAP_CORRUPTION,
                PatternCategory.USE_AFTER_FREE,
            ],
            "buffer-overflow": [PatternCategory.BUFFER_OVERFLOW],
            "format-string": [PatternCategory.FORMAT_STRING],
            "integer-overflow": [PatternCategory.INTEGER_OVERFLOW],
            "use-after-free": [PatternCategory.USE_AFTER_FREE],
            "command-injection": [PatternCategory.COMMAND_INJECTION],
            "race-condition": [PatternCategory.RACE_CONDITION],
            "logic": [PatternCategory.LOGIC_BUG],
            "all": None,
        }

        categories = _TYPE_MAP.get(vuln_type)
        if categories is None and vuln_type != "all":
            self._logger.warning("Unknown vuln_type '%s', scanning all categories", vuln_type)
        return categories

    def _create_finding(self, match: MatchResult, binary_info: BinaryInfo) -> None:
        """Convert a MatchResult into a session Finding."""
        sev = _SEVERITY_MAP.get(match.severity, Severity.INFO)

        location = f"pattern:{match.pattern_id}"
        if match.matched_imports:
            location += f" imports:{','.join(match.matched_imports)}"

        finding = Finding(
            title=f"[{match.pattern_id}] {match.pattern_name}",
            description=match.description,
            severity=sev,
            confidence=match.confidence,
            location=location,
            metadata={
                "pattern_id": match.pattern_id,
                "category": match.category,
                "technique": match.technique,
                "exploitable": match.exploitable,
                "exploitability": match.exploitability,
                "cwe_ids": match.cwe_ids,
                "matched_imports": match.matched_imports,
                "mitigations_present": match.mitigations_present,
                "mitigations_absent": match.mitigations_absent,
            },
        )
        self.add_finding(finding)

    def _basic_control_flow(self, binary_info: BinaryInfo) -> dict[str, Any]:
        """Perform basic control flow analysis.

        In Phase 2 this is a lightweight analysis based on function symbols
        and imports. Deeper CFG analysis will be added in later phases.
        """
        functions = binary_info.functions()
        entry_points: list[str] = []
        for fn in functions:
            if fn.name in ("main", "_start", "entry", "WinMain", "DllMain"):
                entry_points.append(fn.name)

        # Identify potentially interesting call chains based on imports
        dangerous_funcs = {
            "gets", "strcpy", "strcat", "sprintf", "system", "popen",
            "printf", "scanf", "recv", "recvfrom",
        }
        clean_imports = {imp.split("@")[0] for imp in binary_info.imports}
        dangerous_in_binary = dangerous_funcs.intersection(clean_imports)

        # Determine input sources
        input_sources = {"read", "recv", "recvfrom", "fgets", "gets", "scanf", "getenv"}
        available_inputs = input_sources.intersection(clean_imports)

        # Determine output sinks
        output_sinks = {"strcpy", "strcat", "sprintf", "system", "popen", "printf"}
        available_sinks = output_sinks.intersection(clean_imports)

        return {
            "entry_points": entry_points,
            "total_functions": len(functions),
            "dangerous_functions": sorted(dangerous_in_binary),
            "input_sources": sorted(available_inputs),
            "output_sinks": sorted(available_sinks),
            "potential_taint_paths": len(available_inputs) * len(available_sinks),
        }

    def _semantic_analysis(
        self,
        binary_info: BinaryInfo,
        matches: list[MatchResult],
    ) -> str:
        """Use the LLM for semantic analysis of scan findings."""
        if self.llm.provider_name == "none":
            self._logger.info("No LLM configured; skipping semantic analysis")
            return ""

        # Format findings for the LLM
        findings_text = ""
        for m in matches[:10]:  # cap to avoid token limits
            findings_text += (
                f"- [{m.severity.upper()}] {m.pattern_name} "
                f"(confidence: {m.confidence:.0f}%, "
                f"exploitable: {m.exploitable})\n"
                f"  Imports: {', '.join(m.matched_imports)}\n"
                f"  Description: {m.description[:200]}\n\n"
            )

        if not findings_text:
            findings_text = "No vulnerability patterns matched."

        # Get RAG context from knowledge base
        all_cwes: list[int] = []
        for m in matches:
            all_cwes.extend(m.cwe_ids)
        techniques = list({m.technique for m in matches if m.technique})

        kb_context = ""
        try:
            self._kb.initialize()
            kb_context = self._kb.get_rag_context(
                cwe_ids=list(set(all_cwes))[:5],
                technique=techniques[0] if techniques else None,
            )
        except Exception as exc:
            self._logger.debug("Knowledge base context retrieval failed: %s", exc)

        try:
            response = self.llm.prompt(
                _VULN_ANALYSIS_PROMPT,
                filename=binary_info.path.name,
                file_format=f"{binary_info.file_format} {binary_info.bits}-bit {binary_info.arch}",
                arch=binary_info.arch,
                security=str(binary_info.security_summary),
                findings=findings_text,
                kb_context=kb_context or "No relevant context available.",
            )
            if response.ok:
                self._logger.info("LLM semantic analysis complete")
                return response.content
        except Exception as exc:
            self._logger.warning("LLM semantic analysis failed: %s", exc)

        return ""
