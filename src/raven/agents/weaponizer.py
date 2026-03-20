"""
RAVEN Weaponizer Agent.

Generates exploit code from vulnerability findings and templates:
  - Matches vulnerabilities to exploitation techniques
  - Selects appropriate exploit templates
  - Fills template parameters from analysis data
  - Generates pwntools-compatible exploit scripts
  - Optionally uses LLM for custom exploit generation
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from raven.agents.base import AgentResult, AgentTask, BaseAgent
from raven.analysis.binary_loader import BinaryInfo
from raven.analysis.matcher import MatchResult
from raven.core.config import RavenConfig
from raven.core.knowledge_base import ExploitTemplate, KnowledgeBase
from raven.core.llm import PROMPTS, PromptTemplate
from raven.core.logger import get_logger
from raven.core.memory import Finding, Severity
from raven.exploitation.templates import (
    BUILTIN_TEMPLATES,
    get_template_by_technique,
    get_templates_for_match,
)

logger = get_logger("agents.weaponizer")


# ---------------------------------------------------------------------------
# LLM prompt templates for the Weaponizer agent
# ---------------------------------------------------------------------------

_EXPLOIT_GEN_PROMPT = PromptTemplate(
    name="weaponizer_exploit_gen",
    system=(
        "You are RAVEN's Weaponizer agent, an expert exploit developer. "
        "Generate a working exploit script based on the vulnerability analysis. "
        "Use pwntools for the exploit framework. The script must be self-contained "
        "and well-documented. Include clear comments explaining each step."
    ),
    user=(
        "Generate an exploit for this vulnerability:\n\n"
        "Binary: {filename} ({file_format}, {arch})\n"
        "Security: {security}\n\n"
        "Vulnerability:\n{vulnerability}\n\n"
        "Exploit Template Base:\n{template}\n\n"
        "Knowledge Base Context:\n{kb_context}\n\n"
        "Generate a complete, working pwntools exploit script. "
        "Include parameter placeholders where exact values need determination."
    ),
)

PROMPTS["weaponizer_exploit_gen"] = _EXPLOIT_GEN_PROMPT


# ---------------------------------------------------------------------------
# Exploit result model
# ---------------------------------------------------------------------------

class ExploitResult:
    """Result of exploit generation.

    Attributes:
        success: Whether exploit generation succeeded.
        technique: Exploitation technique used.
        template_id: ID of the template used (if any).
        code: Generated exploit code.
        parameters: Parameters used/needed for the exploit.
        notes: Additional notes or warnings.
        vuln_id: ID of the vulnerability being exploited.
    """

    def __init__(
        self,
        success: bool = False,
        technique: str = "",
        template_id: str = "",
        code: str = "",
        parameters: dict[str, Any] | None = None,
        notes: list[str] | None = None,
        vuln_id: str = "",
    ) -> None:
        self.success = success
        self.technique = technique
        self.template_id = template_id
        self.code = code
        self.parameters = parameters or {}
        self.notes = notes or []
        self.vuln_id = vuln_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "technique": self.technique,
            "template_id": self.template_id,
            "code": self.code,
            "parameters": self.parameters,
            "notes": self.notes,
            "vuln_id": self.vuln_id,
        }


# ---------------------------------------------------------------------------
# Weaponizer Agent
# ---------------------------------------------------------------------------

class WeaponizerAgent(BaseAgent):
    """Exploit generation agent.

    The Weaponizer takes vulnerability findings from the Analyst agent
    and generates exploit code using templates and LLM assistance.

    It supports:
      - Automatic technique selection based on vulnerability type
      - Template-based exploit generation
      - LLM-assisted custom exploit generation
      - Multiple exploitation techniques (stack overflow, format string, ROP)
    """

    name = "weaponizer"
    description = "Exploit generation and payload creation"

    def __init__(
        self,
        config: RavenConfig,
        knowledge_base: KnowledgeBase | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(config, **kwargs)
        self._kb = knowledge_base or KnowledgeBase()

    def execute(self, task: AgentTask) -> AgentResult:
        """Execute a Weaponizer exploit generation task.

        Expected ``task.parameters``:
            - ``binary_info``: :class:`BinaryInfo` instance
            - ``vulnerabilities``: list of :class:`MatchResult` dicts
            - ``vuln_id``: str (optional, target specific vulnerability)
            - ``technique``: str (optional, force specific technique)
            - ``payload``: str (optional, payload type)
            - ``auto``: bool (optional, fully autonomous mode)
        """
        binary_info: BinaryInfo = task.parameters.get("binary_info")
        vuln_dicts: list[dict] = task.parameters.get("vulnerabilities", [])
        vuln_id: str | None = task.parameters.get("vuln_id")
        technique: str | None = task.parameters.get("technique")
        auto_mode: bool = task.parameters.get("auto", False)

        if binary_info is None:
            return AgentResult(
                task_id=task.id,
                agent=self.name,
                success=False,
                errors=["No binary_info provided"],
            )

        self.publish_status("generating_exploit", binary=str(binary_info.path))

        exploits = self.generate(
            binary_info,
            vulnerabilities=vuln_dicts,
            vuln_id=vuln_id,
            technique=technique,
            auto_mode=auto_mode,
        )

        return AgentResult(
            task_id=task.id,
            agent=self.name,
            success=any(e.success for e in exploits),
            data={
                "exploits": [e.to_dict() for e in exploits],
                "total_generated": sum(1 for e in exploits if e.success),
            },
            findings=list(self.session.findings.by_agent(self.name)),
        )

    def generate(
        self,
        binary_info: BinaryInfo,
        *,
        vulnerabilities: list[dict[str, Any]] | None = None,
        vuln_id: str | None = None,
        technique: str | None = None,
        auto_mode: bool = False,
    ) -> list[ExploitResult]:
        """Generate exploits for the given binary.

        Args:
            binary_info: Loaded binary metadata.
            vulnerabilities: Vulnerability scan results (list of MatchResult dicts).
            vuln_id: Target a specific vulnerability by pattern ID.
            technique: Force a specific exploitation technique.
            auto_mode: Automatically select the best vulnerability and technique.

        Returns:
            A list of :class:`ExploitResult` objects.
        """
        self._logger.info("Weaponizer starting for %s", binary_info.path.name)
        self.memory.remember("target", str(binary_info.path))

        if not vulnerabilities:
            vulnerabilities = []

        results: list[ExploitResult] = []

        if technique:
            # User specified a technique -- generate exploit using that technique
            result = self._generate_for_technique(binary_info, technique, vulnerabilities)
            results.append(result)
        elif vuln_id:
            # User specified a vulnerability ID
            target_vuln = None
            for v in vulnerabilities:
                if v.get("pattern_id") == vuln_id:
                    target_vuln = v
                    break
            if target_vuln:
                result = self._generate_for_vuln(binary_info, target_vuln)
                results.append(result)
            else:
                results.append(ExploitResult(
                    success=False,
                    notes=[f"Vulnerability {vuln_id} not found in scan results"],
                    vuln_id=vuln_id,
                ))
        elif auto_mode:
            # Automatic mode -- find the best exploitable vulnerability
            results = self._auto_generate(binary_info, vulnerabilities)
        else:
            # Default: try to generate for each exploitable vulnerability
            exploitable = [v for v in vulnerabilities if v.get("exploitable")]
            if not exploitable:
                results.append(ExploitResult(
                    success=False,
                    notes=["No exploitable vulnerabilities found"],
                ))
            else:
                for vuln in exploitable[:3]:  # cap at 3 exploits
                    result = self._generate_for_vuln(binary_info, vuln)
                    results.append(result)

        # Record findings
        for r in results:
            if r.success:
                finding = Finding(
                    title=f"Exploit Generated: {r.technique}",
                    description=f"Generated {r.technique} exploit for {binary_info.path.name}",
                    severity=Severity.INFO,
                    confidence=70.0,
                    location=f"exploit:{r.template_id or 'custom'}",
                    metadata={"technique": r.technique, "template_id": r.template_id},
                )
                self.add_finding(finding)

        self._logger.info(
            "Weaponizer complete: %d exploits generated",
            sum(1 for r in results if r.success),
        )
        return results

    # ------------------------------------------------------------------
    # Internal generation methods
    # ------------------------------------------------------------------

    def _generate_for_technique(
        self,
        binary_info: BinaryInfo,
        technique: str,
        vulnerabilities: list[dict[str, Any]],
    ) -> ExploitResult:
        """Generate an exploit using a specific technique."""
        security = binary_info.security_summary
        templates = get_templates_for_match(
            technique, arch=binary_info.arch, security=security
        )

        if templates:
            template = templates[0]
            code = self._fill_template(template, binary_info, vulnerabilities)
            return ExploitResult(
                success=True,
                technique=technique,
                template_id=template.id,
                code=code,
                parameters=template.variables,
                notes=self._assess_notes(binary_info, template),
            )

        # No template found -- try LLM generation
        return self._llm_generate(binary_info, technique, vulnerabilities)

    def _generate_for_vuln(
        self,
        binary_info: BinaryInfo,
        vuln: dict[str, Any],
    ) -> ExploitResult:
        """Generate an exploit targeting a specific vulnerability."""
        technique = vuln.get("technique", "")
        vuln_id = vuln.get("pattern_id", "")

        if not technique:
            return ExploitResult(
                success=False,
                vuln_id=vuln_id,
                notes=["No exploitation technique associated with this vulnerability"],
            )

        security = binary_info.security_summary
        templates = get_templates_for_match(
            technique, arch=binary_info.arch, security=security
        )

        if templates:
            template = templates[0]
            code = self._fill_template(template, binary_info, [vuln])
            return ExploitResult(
                success=True,
                technique=technique,
                template_id=template.id,
                code=code,
                vuln_id=vuln_id,
                parameters=template.variables,
                notes=self._assess_notes(binary_info, template),
            )

        # Fallback: try LLM
        return self._llm_generate(binary_info, technique, [vuln])

    def _auto_generate(
        self,
        binary_info: BinaryInfo,
        vulnerabilities: list[dict[str, Any]],
    ) -> list[ExploitResult]:
        """Automatically select and exploit the best vulnerability."""
        # Sort by exploitability: prefer highest confidence, lowest difficulty
        _DIFFICULTY_SCORE = {
            "trivial": 0, "easy": 1, "moderate": 2, "hard": 3, "very_hard": 4,
        }

        scored = []
        for v in vulnerabilities:
            if not v.get("exploitable"):
                continue
            score = v.get("confidence", 0) * 10 - _DIFFICULTY_SCORE.get(
                v.get("exploitability", "very_hard"), 4
            ) * 20
            scored.append((score, v))

        scored.sort(key=lambda x: -x[0])

        if not scored:
            return [ExploitResult(
                success=False,
                notes=["No exploitable vulnerabilities found for automatic exploitation"],
            )]

        results: list[ExploitResult] = []
        for _, vuln in scored[:2]:  # try top 2
            result = self._generate_for_vuln(binary_info, vuln)
            results.append(result)
            if result.success:
                break  # one successful exploit is enough in auto mode

        return results

    def _fill_template(
        self,
        template: ExploitTemplate,
        binary_info: BinaryInfo,
        vulnerabilities: list[dict[str, Any]],
    ) -> str:
        """Fill a template with known values, leaving placeholders for unknowns."""
        code = template.template_code

        # Fill in what we know
        replacements = {
            "target_binary": str(binary_info.path),
        }

        # Try to infer offset from binary analysis
        # (In a real implementation, this would use more sophisticated analysis)
        replacements["offset"] = "0  # TODO: determine via pattern/cyclic"
        replacements["shellcode"] = 'asm(shellcraft.sh())'
        replacements["return_address"] = "0x0  # TODO: determine via debugging"

        for key, value in replacements.items():
            placeholder = "{" + key + "}"
            if placeholder in code:
                code = code.replace(placeholder, str(value))

        return code

    def _assess_notes(
        self,
        binary_info: BinaryInfo,
        template: ExploitTemplate,
    ) -> list[str]:
        """Generate notes about exploit applicability and caveats."""
        notes: list[str] = []
        security = binary_info.security_summary

        if security.get("canary"):
            notes.append(
                "WARNING: Stack canary is enabled. The canary value must be "
                "leaked or brute-forced before the exploit will work."
            )
        if security.get("pie"):
            notes.append(
                "WARNING: PIE is enabled. Binary base address must be leaked "
                "or ASLR bypassed."
            )
        if security.get("nx") and "shellcode" in template.technique:
            notes.append(
                "WARNING: NX is enabled. Shellcode-based exploitation will not "
                "work. Consider ROP or ret2libc instead."
            )
        if security.get("relro") == "full":
            notes.append(
                "WARNING: Full RELRO is enabled. GOT overwrite techniques "
                "will not work."
            )
        if not security.get("nx") and not security.get("canary"):
            notes.append(
                "NOTE: No NX and no canary -- this is the simplest exploitation "
                "scenario. Direct shellcode injection should work."
            )

        return notes

    def _llm_generate(
        self,
        binary_info: BinaryInfo,
        technique: str,
        vulnerabilities: list[dict[str, Any]],
    ) -> ExploitResult:
        """Use the LLM to generate a custom exploit."""
        if self.llm.provider_name == "none":
            self._logger.info("No LLM configured; cannot generate custom exploit")
            return ExploitResult(
                success=False,
                technique=technique,
                notes=["No template available and no LLM configured for custom generation"],
            )

        # Format vulnerability info
        vuln_text = ""
        for v in vulnerabilities[:3]:
            vuln_text += (
                f"- {v.get('pattern_name', 'Unknown')} "
                f"(severity: {v.get('severity', 'unknown')}, "
                f"confidence: {v.get('confidence', 0):.0f}%)\n"
                f"  Matched imports: {', '.join(v.get('matched_imports', []))}\n"
                f"  Description: {v.get('description', '')[:200]}\n\n"
            )

        # Get closest template as starting point
        closest = get_template_by_technique(technique, binary_info.arch)
        template_text = closest.template_code if closest else "No template available"

        # Get KB context
        kb_context = ""
        try:
            self._kb.initialize()
            kb_context = self._kb.get_rag_context(technique=technique)
        except Exception:
            pass

        try:
            response = self.llm.prompt(
                _EXPLOIT_GEN_PROMPT,
                filename=binary_info.path.name,
                file_format=f"{binary_info.file_format} {binary_info.bits}-bit {binary_info.arch}",
                arch=binary_info.arch,
                security=str(binary_info.security_summary),
                vulnerability=vuln_text or "No specific vulnerability data",
                template=template_text,
                kb_context=kb_context or "No KB context",
            )
            if response.ok:
                return ExploitResult(
                    success=True,
                    technique=technique,
                    code=response.content,
                    notes=["Generated via LLM -- review carefully before use"],
                )
        except Exception as exc:
            self._logger.warning("LLM exploit generation failed: %s", exc)

        return ExploitResult(
            success=False,
            technique=technique,
            notes=["LLM exploit generation failed"],
        )
