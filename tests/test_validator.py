"""Tests for the RAVEN Validator Agent."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from raven.agents.base import AgentTask
from raven.agents.validator import (
    ValidatorAgent,
    ValidationEnv,
    ValidationReport,
    ValidationRun,
    ValidationStatus,
    _analyze_failures,
    _generate_recommendations,
    _run_local,
    docker_available,
)
from raven.core.config import RavenConfig
from raven.core.memory import SessionMemory


class TestValidationEnums:
    """Tests for validation enum types."""

    def test_validation_env(self) -> None:
        assert str(ValidationEnv.LOCAL) == "local"
        assert str(ValidationEnv.DOCKER) == "docker"
        assert str(ValidationEnv.QEMU) == "qemu"

    def test_validation_status(self) -> None:
        assert str(ValidationStatus.SUCCESS) == "success"
        assert str(ValidationStatus.FAILURE) == "failure"
        assert str(ValidationStatus.TIMEOUT) == "timeout"
        assert str(ValidationStatus.ERROR) == "error"
        assert str(ValidationStatus.SKIPPED) == "skipped"


class TestValidationRun:
    """Tests for the ValidationRun dataclass."""

    def test_defaults(self) -> None:
        run = ValidationRun()
        assert run.iteration == 0
        assert run.status == ValidationStatus.SKIPPED
        assert run.exit_code == -1

    def test_to_dict(self) -> None:
        run = ValidationRun(
            iteration=1,
            status=ValidationStatus.SUCCESS,
            duration_seconds=1.234,
            exit_code=0,
            stdout="ok",
            stderr="",
        )
        d = run.to_dict()
        assert d["iteration"] == 1
        assert d["status"] == "success"
        assert d["duration_seconds"] == 1.234
        assert d["exit_code"] == 0

    def test_output_truncation(self) -> None:
        run = ValidationRun(stdout="X" * 1000, stderr="Y" * 1000)
        d = run.to_dict()
        assert len(d["stdout"]) <= 500
        assert len(d["stderr"]) <= 500


class TestValidationReport:
    """Tests for the ValidationReport dataclass."""

    def test_defaults(self) -> None:
        report = ValidationReport()
        assert report.success_rate == 0.0
        assert report.iterations == 0
        assert report.runs == []

    def test_to_dict(self) -> None:
        runs = [
            ValidationRun(iteration=1, status=ValidationStatus.SUCCESS, duration_seconds=0.5),
            ValidationRun(iteration=2, status=ValidationStatus.FAILURE, duration_seconds=0.3),
        ]
        report = ValidationReport(
            exploit_path="/tmp/exploit.py",
            target_binary="/tmp/target",
            environment="local",
            iterations=2,
            runs=runs,
            success_rate=50.0,
            avg_duration=0.4,
            reliability_score=50.0,
        )
        d = report.to_dict()
        assert d["success_rate"] == 50.0
        assert len(d["runs"]) == 2
        assert d["exploit_path"] == "/tmp/exploit.py"


class TestAnalyzeFailures:
    """Tests for the failure analysis function."""

    def test_empty_runs(self) -> None:
        result = _analyze_failures([])
        assert result["total_runs"] == 0

    def test_all_success(self) -> None:
        runs = [
            ValidationRun(status=ValidationStatus.SUCCESS, exit_code=0)
            for _ in range(5)
        ]
        result = _analyze_failures(runs)
        assert result["status_counts"]["success"] == 5
        assert result["primary_failure_mode"] == ""

    def test_timeout_detection(self) -> None:
        runs = [
            ValidationRun(status=ValidationStatus.SUCCESS, exit_code=0),
            ValidationRun(status=ValidationStatus.TIMEOUT, exit_code=-1),
            ValidationRun(status=ValidationStatus.TIMEOUT, exit_code=-1),
        ]
        result = _analyze_failures(runs)
        assert result["primary_failure_mode"] == "timeout"

    def test_segfault_detection(self) -> None:
        runs = [
            ValidationRun(
                status=ValidationStatus.FAILURE,
                exit_code=139,
                stderr="Segmentation fault (core dumped)",
            ),
        ]
        result = _analyze_failures(runs)
        assert result["primary_failure_mode"] == "segfault"

    def test_crash_detection(self) -> None:
        runs = [
            ValidationRun(status=ValidationStatus.FAILURE, exit_code=1),
        ]
        result = _analyze_failures(runs)
        assert result["primary_failure_mode"] == "crash"


class TestGenerateRecommendations:
    """Tests for the recommendation generator."""

    def test_zero_success_rate(self) -> None:
        report = ValidationReport(success_rate=0.0)
        recs = _generate_recommendations(report, {"primary_failure_mode": ""})
        assert any("never succeeded" in r.lower() for r in recs)

    def test_low_success_rate(self) -> None:
        report = ValidationReport(success_rate=30.0)
        recs = _generate_recommendations(report, {"primary_failure_mode": ""})
        assert any("low reliability" in r.lower() for r in recs)

    def test_timeout_recommendation(self) -> None:
        report = ValidationReport(success_rate=50.0)
        recs = _generate_recommendations(report, {"primary_failure_mode": "timeout"})
        assert any("timeout" in r.lower() for r in recs)

    def test_segfault_recommendation(self) -> None:
        report = ValidationReport(success_rate=50.0)
        recs = _generate_recommendations(report, {"primary_failure_mode": "segfault"})
        assert any("segfault" in r.lower() for r in recs)

    def test_high_success_rate(self) -> None:
        report = ValidationReport(success_rate=95.0)
        recs = _generate_recommendations(report, {"primary_failure_mode": ""})
        assert any("reliable" in r.lower() for r in recs)


class TestRunLocal:
    """Tests for local exploit execution."""

    def test_successful_exploit(self, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"fake binary")

        run = _run_local(exploit, target, timeout=10)
        assert run.status == ValidationStatus.SUCCESS
        assert run.exit_code == 0
        assert run.duration_seconds > 0

    def test_failed_exploit(self, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(1)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"fake binary")

        run = _run_local(exploit, target, timeout=10)
        assert run.status == ValidationStatus.FAILURE
        assert run.exit_code == 1

    def test_timeout_exploit(self, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import time; time.sleep(30)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"fake binary")

        run = _run_local(exploit, target, timeout=1)
        assert run.status == ValidationStatus.TIMEOUT

    def test_exploit_with_output(self, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text(textwrap.dedent("""\
            import sys
            print("exploit output")
            print("error output", file=sys.stderr)
            sys.exit(0)
        """))
        target = tmp_dir / "target"
        target.write_bytes(b"fake binary")

        run = _run_local(exploit, target, timeout=10)
        assert "exploit output" in run.stdout
        assert "error output" in run.stderr

    def test_target_binary_passed_as_env(self, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text(textwrap.dedent("""\
            import os, sys
            target = os.environ.get("TARGET_BINARY", "")
            if "target" in target:
                sys.exit(0)
            sys.exit(1)
        """))
        target = tmp_dir / "target"
        target.write_bytes(b"fake binary")

        run = _run_local(exploit, target, timeout=10)
        assert run.status == ValidationStatus.SUCCESS


class TestDockerAvailable:
    """Tests for Docker availability check."""

    def test_docker_available_with_mock(self) -> None:
        with patch("raven.agents.validator.shutil.which", return_value="/usr/bin/docker"):
            assert docker_available() is True

    def test_docker_unavailable_with_mock(self) -> None:
        with patch("raven.agents.validator.shutil.which", return_value=None):
            assert docker_available() is False


class TestValidatorAgent:
    """Tests for the ValidatorAgent class."""

    @pytest.fixture
    def config(self, tmp_dir: Path) -> RavenConfig:
        return RavenConfig(config_path=tmp_dir / "cfg.yaml")

    @pytest.fixture
    def session(self) -> SessionMemory:
        return SessionMemory()

    @pytest.fixture
    def validator(self, config: RavenConfig, session: SessionMemory) -> ValidatorAgent:
        return ValidatorAgent(config=config, session=session)

    def test_agent_properties(self, validator: ValidatorAgent) -> None:
        assert validator.name == "validator"
        assert "testing" in validator.description.lower() or "validation" in validator.description.lower()

    def test_validate_missing_exploit(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        target = tmp_dir / "target"
        target.write_bytes(b"binary")
        report = validator.validate(
            exploit_path=str(tmp_dir / "nonexistent.py"),
            target_binary=str(target),
        )
        assert report.success_rate == 0.0
        assert len(report.recommendations) > 0

    def test_validate_missing_target(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        report = validator.validate(
            exploit_path=str(exploit),
            target_binary=str(tmp_dir / "nonexistent"),
        )
        assert report.success_rate == 0.0

    def test_validate_success(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        report = validator.validate(
            exploit_path=str(exploit),
            target_binary=str(target),
            iterations=3,
            timeout=10,
        )
        assert report.success_rate == 100.0
        assert report.iterations == 3
        assert len(report.runs) == 3

    def test_validate_failure(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(1)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        report = validator.validate(
            exploit_path=str(exploit),
            target_binary=str(target),
            iterations=2,
            timeout=10,
        )
        assert report.success_rate == 0.0
        assert all(r.status == ValidationStatus.FAILURE for r in report.runs)

    def test_validate_records_findings(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        report = validator.validate(
            exploit_path=str(exploit),
            target_binary=str(target),
        )
        findings = list(validator.session.findings.by_agent("validator"))
        assert len(findings) >= 1

    def test_validate_clamps_iterations(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        # Negative iterations should be clamped to 1
        report = validator.validate(
            exploit_path=str(exploit),
            target_binary=str(target),
            iterations=-5,
        )
        assert report.iterations == 1

    def test_validate_docker_fallback(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        """Docker env falls back to local when Docker is not available."""
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        with patch("raven.agents.validator.docker_available", return_value=False):
            report = validator.validate(
                exploit_path=str(exploit),
                target_binary=str(target),
                environment="docker",
            )
            # Should still succeed via local fallback
            assert report.success_rate == 100.0

    def test_execute_task(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        task = AgentTask(
            id="task-1",
            name="validate",
            parameters={
                "exploit_path": str(exploit),
                "target_binary": str(target),
                "iterations": 1,
                "timeout": 10,
            },
        )
        result = validator.execute(task)
        assert result.success is True
        assert result.data["success_rate"] == 100.0

    def test_execute_task_missing_params(self, validator: ValidatorAgent) -> None:
        task = AgentTask(id="task-2", name="validate", parameters={})
        result = validator.execute(task)
        assert result.success is False
        assert len(result.errors) > 0

    def test_reliability_score_bonus(self, validator: ValidatorAgent, tmp_dir: Path) -> None:
        """Test that reliability score gets a consistency bonus with enough iterations."""
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        report = validator.validate(
            exploit_path=str(exploit),
            target_binary=str(target),
            iterations=5,
            timeout=10,
        )
        # With 100% success and 5+ consistent runs, reliability should be > 100%
        # (capped at 105 due to the +5 bonus)
        assert report.reliability_score >= 100.0
