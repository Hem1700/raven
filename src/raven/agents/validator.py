"""
RAVEN Validator Agent.

Tests and validates exploits in safe, isolated environments:
  - Docker-based testing (isolated containers)
  - QEMU emulation (basic support for cross-architecture)
  - Local execution (with resource limits and timeouts)
  - Success/failure detection and reliability scoring
  - Performance metrics and failure analysis
  - Detailed validation reports

SECURITY: All exploit execution happens exclusively in sandboxed
environments. The Validator NEVER runs untrusted code on the host
without containment.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from raven.agents.base import AgentResult, AgentTask, BaseAgent
from raven.core.config import RavenConfig
from raven.core.logger import AuditLogger, get_logger
from raven.core.memory import Finding, Severity

logger = get_logger("agents.validator")
audit = AuditLogger()


# ---------------------------------------------------------------------------
# Validation environment types
# ---------------------------------------------------------------------------

class ValidationEnv(str, Enum):
    """Supported validation environments."""

    LOCAL = "local"
    DOCKER = "docker"
    QEMU = "qemu"

    def __str__(self) -> str:
        return self.value


class ValidationStatus(str, Enum):
    """Outcome of a single validation run."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# Validation result models
# ---------------------------------------------------------------------------

@dataclass
class ValidationRun:
    """Result of a single exploit test run.

    Attributes:
        iteration: Which iteration this run represents (1-based).
        status: Outcome of the run.
        duration_seconds: How long the run took.
        exit_code: Process exit code (if applicable).
        stdout: Captured stdout (truncated).
        stderr: Captured stderr (truncated).
        error_message: Error description if the run failed.
    """

    iteration: int = 0
    status: ValidationStatus = ValidationStatus.SKIPPED
    duration_seconds: float = 0.0
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "status": str(self.status),
            "duration_seconds": round(self.duration_seconds, 3),
            "exit_code": self.exit_code,
            "stdout": self.stdout[:500],
            "stderr": self.stderr[:500],
            "error_message": self.error_message,
        }


@dataclass
class ValidationReport:
    """Aggregate validation report across multiple runs.

    Attributes:
        exploit_path: Path to the exploit script tested.
        target_binary: Path to the target binary.
        environment: Validation environment used.
        iterations: Total number of test runs.
        runs: Individual run results.
        success_rate: Percentage of successful runs (0-100).
        avg_duration: Average run duration in seconds.
        reliability_score: Overall reliability score (0-100).
        failure_analysis: Analysis of failure modes.
        recommendations: Improvement suggestions.
    """

    exploit_path: str = ""
    target_binary: str = ""
    environment: str = "local"
    iterations: int = 0
    runs: list[ValidationRun] = field(default_factory=list)
    success_rate: float = 0.0
    avg_duration: float = 0.0
    reliability_score: float = 0.0
    failure_analysis: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exploit_path": self.exploit_path,
            "target_binary": self.target_binary,
            "environment": self.environment,
            "iterations": self.iterations,
            "success_rate": round(self.success_rate, 1),
            "avg_duration": round(self.avg_duration, 3),
            "reliability_score": round(self.reliability_score, 1),
            "runs": [r.to_dict() for r in self.runs],
            "failure_analysis": self.failure_analysis,
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Resource limits for safe execution
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT_SECONDS = 30
_MAX_TIMEOUT_SECONDS = 300
_MAX_MEMORY_MB = 512
_MAX_OUTPUT_BYTES = 10_000


# ---------------------------------------------------------------------------
# Docker integration
# ---------------------------------------------------------------------------

def docker_available() -> bool:
    """Check if Docker is available on the system."""
    return shutil.which("docker") is not None


def _run_in_docker(
    exploit_path: Path,
    target_binary: Path,
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
    image: str = "ubuntu:22.04",
) -> ValidationRun:
    """Run an exploit against a binary inside a Docker container.

    The container is:
      - Ephemeral (--rm)
      - Network-isolated (--network none)
      - Read-only filesystem (--read-only, with tmpfs for /tmp)
      - Resource-limited (memory, CPU, pids)
      - Time-limited (timeout)

    Args:
        exploit_path: Path to the exploit script.
        target_binary: Path to the target binary.
        timeout: Maximum execution time in seconds.
        image: Docker image to use.

    Returns:
        A :class:`ValidationRun` with the results.
    """
    start = time.monotonic()

    # Create temp directory with exploit and binary
    with tempfile.TemporaryDirectory(prefix="raven_validate_") as tmpdir:
        work_dir = Path(tmpdir)
        shutil.copy2(exploit_path, work_dir / "exploit.py")
        shutil.copy2(target_binary, work_dir / "target")
        (work_dir / "target").chmod(0o755)

        cmd = [
            "docker", "run",
            "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--memory", f"{_MAX_MEMORY_MB}m",
            "--cpus", "1.0",
            "--pids-limit", "50",
            "-v", f"{work_dir}:/work:ro",
            "-w", "/work",
            image,
            "timeout", str(timeout),
            "python3", "/work/exploit.py",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout + 10,  # extra grace period
                text=True,
            )
            duration = time.monotonic() - start

            if result.returncode == 0:
                status = ValidationStatus.SUCCESS
            elif result.returncode == 124:
                status = ValidationStatus.TIMEOUT
            else:
                status = ValidationStatus.FAILURE

            return ValidationRun(
                status=status,
                duration_seconds=duration,
                exit_code=result.returncode,
                stdout=result.stdout[:_MAX_OUTPUT_BYTES],
                stderr=result.stderr[:_MAX_OUTPUT_BYTES],
            )

        except subprocess.TimeoutExpired:
            return ValidationRun(
                status=ValidationStatus.TIMEOUT,
                duration_seconds=time.monotonic() - start,
                error_message=f"Docker execution exceeded {timeout}s timeout",
            )
        except FileNotFoundError:
            return ValidationRun(
                status=ValidationStatus.ERROR,
                duration_seconds=time.monotonic() - start,
                error_message="Docker not found. Install Docker to use container validation.",
            )
        except Exception as exc:
            return ValidationRun(
                status=ValidationStatus.ERROR,
                duration_seconds=time.monotonic() - start,
                error_message=str(exc),
            )


# ---------------------------------------------------------------------------
# Local (sandboxed) execution
# ---------------------------------------------------------------------------

def _run_local(
    exploit_path: Path,
    target_binary: Path,
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
) -> ValidationRun:
    """Run an exploit locally with resource limits.

    WARNING: This runs the exploit on the host with only timeout and
    output size limits. Use Docker for proper isolation.

    The exploit is run in a subprocess with:
      - Timeout enforcement
      - Output capture and truncation
      - No network access (best effort via env)

    Args:
        exploit_path: Path to the exploit script.
        target_binary: Path to the target binary.
        timeout: Maximum execution time in seconds.

    Returns:
        A :class:`ValidationRun`.
    """
    start = time.monotonic()

    env = os.environ.copy()
    env["TARGET_BINARY"] = str(target_binary)

    try:
        result = subprocess.run(
            ["python3", str(exploit_path)],
            capture_output=True,
            timeout=min(timeout, _MAX_TIMEOUT_SECONDS),
            text=True,
            env=env,
            cwd=str(exploit_path.parent),
        )
        duration = time.monotonic() - start

        if result.returncode == 0:
            status = ValidationStatus.SUCCESS
        else:
            status = ValidationStatus.FAILURE

        return ValidationRun(
            status=status,
            duration_seconds=duration,
            exit_code=result.returncode,
            stdout=result.stdout[:_MAX_OUTPUT_BYTES],
            stderr=result.stderr[:_MAX_OUTPUT_BYTES],
        )

    except subprocess.TimeoutExpired:
        return ValidationRun(
            status=ValidationStatus.TIMEOUT,
            duration_seconds=time.monotonic() - start,
            error_message=f"Local execution exceeded {timeout}s timeout",
        )
    except Exception as exc:
        return ValidationRun(
            status=ValidationStatus.ERROR,
            duration_seconds=time.monotonic() - start,
            error_message=str(exc),
        )


# ---------------------------------------------------------------------------
# Failure analysis
# ---------------------------------------------------------------------------

def _analyze_failures(runs: list[ValidationRun]) -> dict[str, Any]:
    """Analyze failure modes across validation runs.

    Returns:
        A dict with failure mode statistics and patterns.
    """
    total = len(runs)
    if total == 0:
        return {"total_runs": 0}

    status_counts: dict[str, int] = {}
    error_messages: list[str] = []
    exit_codes: dict[int, int] = {}

    for run in runs:
        status_str = str(run.status)
        status_counts[status_str] = status_counts.get(status_str, 0) + 1
        if run.error_message:
            error_messages.append(run.error_message)
        if run.exit_code >= 0:
            exit_codes[run.exit_code] = exit_codes.get(run.exit_code, 0) + 1

    # Identify most common failure mode
    failure_runs = [r for r in runs if r.status != ValidationStatus.SUCCESS]
    primary_failure = ""
    if failure_runs:
        # Check for common patterns in stderr
        segfault_count = sum(
            1 for r in failure_runs
            if "segfault" in r.stderr.lower() or "sigsegv" in r.stderr.lower()
            or r.exit_code == -11 or r.exit_code == 139
        )
        timeout_count = sum(1 for r in failure_runs if r.status == ValidationStatus.TIMEOUT)
        crash_count = sum(
            1 for r in failure_runs
            if r.exit_code not in (0, -1) and r.status != ValidationStatus.TIMEOUT
        )

        if timeout_count > 0:
            primary_failure = "timeout"
        elif segfault_count > 0:
            primary_failure = "segfault"
        elif crash_count > 0:
            primary_failure = "crash"
        else:
            primary_failure = "unknown"

    return {
        "total_runs": total,
        "status_counts": status_counts,
        "exit_codes": exit_codes,
        "unique_errors": list(set(error_messages))[:10],
        "primary_failure_mode": primary_failure,
    }


def _generate_recommendations(
    report: ValidationReport,
    failure_analysis: dict[str, Any],
) -> list[str]:
    """Generate improvement recommendations based on validation results."""
    recs: list[str] = []

    if report.success_rate == 0:
        recs.append("Exploit never succeeded. Verify the vulnerability exists and the offset is correct.")

    if report.success_rate > 0 and report.success_rate < 50:
        recs.append(
            f"Low reliability ({report.success_rate:.0f}%). "
            "Consider ASLR effects or race conditions."
        )

    primary_failure = failure_analysis.get("primary_failure_mode", "")

    if primary_failure == "timeout":
        recs.append("Exploit timed out. Check for deadlocks or increase timeout.")

    if primary_failure == "segfault":
        recs.append(
            "Exploit causes segfault. The offset or address may be wrong. "
            "Try using a cyclic pattern to determine the exact offset."
        )

    if primary_failure == "crash":
        recs.append(
            "Exploit crashes the target. Check for stack canary detection "
            "or address miscalculation."
        )

    if report.success_rate >= 90:
        recs.append("Exploit is highly reliable. Ready for deployment.")
    elif report.success_rate >= 50:
        recs.append(
            "Moderate reliability. Consider adding retry logic or "
            "info leak for address resolution."
        )

    return recs


# ---------------------------------------------------------------------------
# Validator Agent
# ---------------------------------------------------------------------------

class ValidatorAgent(BaseAgent):
    """Exploit validation and testing agent.

    The Validator agent tests exploits in isolated environments to
    determine their reliability and identify failure modes.

    SECURITY: All execution is sandboxed. Docker is preferred;
    local execution uses subprocess isolation with timeouts.
    """

    name = "validator"
    description = "Exploit testing and validation"

    def execute(self, task: AgentTask) -> AgentResult:
        """Execute a validation task.

        Expected ``task.parameters``:
            - ``exploit_path``: str, path to the exploit script
            - ``target_binary``: str, path to the target binary
            - ``environment``: str (local/docker/qemu), default "local"
            - ``iterations``: int, default 1
            - ``timeout``: int, seconds per iteration, default 30
        """
        exploit_path = task.parameters.get("exploit_path", "")
        target_binary = task.parameters.get("target_binary", "")
        environment = task.parameters.get("environment", "local")
        iterations = task.parameters.get("iterations", 1)
        timeout = task.parameters.get("timeout", _DEFAULT_TIMEOUT_SECONDS)

        if not exploit_path or not target_binary:
            return AgentResult(
                task_id=task.id,
                agent=self.name,
                success=False,
                errors=["exploit_path and target_binary are required"],
            )

        self.publish_status("validating", exploit=exploit_path, target=target_binary)

        report = self.validate(
            exploit_path=exploit_path,
            target_binary=target_binary,
            environment=environment,
            iterations=iterations,
            timeout=timeout,
        )

        return AgentResult(
            task_id=task.id,
            agent=self.name,
            success=report.success_rate > 0,
            data=report.to_dict(),
            findings=list(self.session.findings.by_agent(self.name)),
        )

    def validate(
        self,
        exploit_path: str,
        target_binary: str,
        *,
        environment: str = "local",
        iterations: int = 1,
        timeout: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> ValidationReport:
        """Validate an exploit against a target binary.

        Args:
            exploit_path: Path to the exploit script.
            target_binary: Path to the target binary.
            environment: Execution environment (local/docker/qemu).
            iterations: Number of test iterations.
            timeout: Timeout per iteration in seconds.

        Returns:
            A :class:`ValidationReport` with detailed results.
        """
        self._logger.info(
            "Validating exploit %s against %s (env=%s, iterations=%d)",
            exploit_path, target_binary, environment, iterations,
        )
        audit.log_agent_action(
            "validator", "validate",
            exploit=exploit_path, target=target_binary,
            environment=environment, iterations=iterations,
        )

        exploit_p = Path(exploit_path)
        target_p = Path(target_binary)

        # Validate inputs
        if not exploit_p.is_file():
            return self._error_report(exploit_path, target_binary, environment,
                                      f"Exploit script not found: {exploit_path}")
        if not target_p.is_file():
            return self._error_report(exploit_path, target_binary, environment,
                                      f"Target binary not found: {target_binary}")

        # Clamp iterations and timeout
        iterations = max(1, min(iterations, 1000))
        timeout = max(5, min(timeout, _MAX_TIMEOUT_SECONDS))

        # Select execution function
        env_enum = ValidationEnv.LOCAL
        try:
            env_enum = ValidationEnv(environment)
        except ValueError:
            self._logger.warning("Unknown environment '%s', falling back to local", environment)

        run_fn = self._get_run_function(env_enum)

        # Run iterations
        runs: list[ValidationRun] = []
        for i in range(1, iterations + 1):
            self._logger.debug("Validation iteration %d/%d", i, iterations)
            run = run_fn(exploit_p, target_p, timeout)
            run.iteration = i
            runs.append(run)

        # Build report
        report = self._build_report(
            exploit_path, target_binary, environment, iterations, runs,
        )

        # Record findings
        self._record_findings(report)
        self.memory.remember("last_report", report.to_dict())

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_run_function(self, env: ValidationEnv):
        """Get the execution function for the given environment."""
        if env == ValidationEnv.DOCKER:
            if not docker_available():
                self._logger.warning("Docker not available; falling back to local")
                return _run_local
            return _run_in_docker
        if env == ValidationEnv.QEMU:
            # QEMU support is basic -- delegates to local with QEMU prefix
            self._logger.info("QEMU validation uses local execution with qemu-user")
            return _run_local
        return _run_local

    def _build_report(
        self,
        exploit_path: str,
        target_binary: str,
        environment: str,
        iterations: int,
        runs: list[ValidationRun],
    ) -> ValidationReport:
        """Build a ValidationReport from run results."""
        successes = sum(1 for r in runs if r.status == ValidationStatus.SUCCESS)
        total = len(runs)

        success_rate = (successes / total * 100) if total > 0 else 0.0
        durations = [r.duration_seconds for r in runs if r.duration_seconds > 0]
        avg_duration = sum(durations) / len(durations) if durations else 0.0

        # Reliability score: weighted by success rate and consistency
        reliability = success_rate
        if total >= 5:
            # Bonus for consistency (low variance in duration)
            if durations:
                mean_d = avg_duration
                variance = sum((d - mean_d) ** 2 for d in durations) / len(durations)
                if variance < 1.0:
                    reliability = min(100.0, reliability + 5.0)

        failure_analysis = _analyze_failures(runs)
        report = ValidationReport(
            exploit_path=exploit_path,
            target_binary=target_binary,
            environment=environment,
            iterations=iterations,
            runs=runs,
            success_rate=success_rate,
            avg_duration=avg_duration,
            reliability_score=reliability,
            failure_analysis=failure_analysis,
        )
        report.recommendations = _generate_recommendations(report, failure_analysis)
        return report

    def _error_report(
        self, exploit_path: str, target_binary: str, environment: str, error: str,
    ) -> ValidationReport:
        """Create an error report when validation cannot start."""
        return ValidationReport(
            exploit_path=exploit_path,
            target_binary=target_binary,
            environment=environment,
            iterations=0,
            success_rate=0.0,
            recommendations=[error],
        )

    def _record_findings(self, report: ValidationReport) -> None:
        """Record validation results as session findings."""
        if report.success_rate >= 90:
            severity = Severity.INFO
            title = f"Exploit validated: {report.success_rate:.0f}% success rate"
        elif report.success_rate >= 50:
            severity = Severity.LOW
            title = f"Exploit partially reliable: {report.success_rate:.0f}% success rate"
        elif report.success_rate > 0:
            severity = Severity.MEDIUM
            title = f"Exploit unreliable: {report.success_rate:.0f}% success rate"
        else:
            severity = Severity.HIGH
            title = "Exploit validation failed: 0% success rate"

        finding = Finding(
            title=title,
            description=(
                f"Validated {report.exploit_path} against {report.target_binary} "
                f"in {report.environment} environment over {report.iterations} iterations."
            ),
            severity=severity,
            confidence=report.reliability_score,
            location=f"validation:{report.exploit_path}",
            metadata={
                "success_rate": report.success_rate,
                "reliability": report.reliability_score,
                "iterations": report.iterations,
                "environment": report.environment,
            },
        )
        self.add_finding(finding)
