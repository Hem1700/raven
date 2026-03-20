"""Tests for the RAVEN binary loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from raven.analysis.binary_loader import (
    BinaryInfo,
    _detect_format,
    _extract_strings,
    _section_entropy,
    load_binary,
)


class TestFormatDetection:
    """Tests for binary format detection."""

    def test_detect_elf(self) -> None:
        assert _detect_format(b"\x7fELF\x02\x01\x01\x00") == "ELF"

    def test_detect_pe(self) -> None:
        assert _detect_format(b"MZ\x90\x00") == "PE"

    def test_detect_macho_64_le(self) -> None:
        assert _detect_format(b"\xcf\xfa\xed\xfe") == "Mach-O"

    def test_detect_macho_32_be(self) -> None:
        assert _detect_format(b"\xfe\xed\xfa\xce") == "Mach-O"

    def test_detect_raw(self) -> None:
        assert _detect_format(b"\x00\x01\x02\x03") == "raw"

    def test_detect_empty(self) -> None:
        assert _detect_format(b"") == "raw"


class TestStringExtraction:
    """Tests for ASCII string extraction."""

    def test_basic_extraction(self) -> None:
        data = b"\x00Hello\x00World\x00"
        strings = _extract_strings(data, min_length=3)
        assert "Hello" in strings
        assert "World" in strings

    def test_min_length(self) -> None:
        data = b"\x00AB\x00ABCDE\x00"
        strings = _extract_strings(data, min_length=4)
        assert "AB" not in strings
        assert "ABCDE" in strings

    def test_empty_data(self) -> None:
        assert _extract_strings(b"") == []

    def test_no_printable(self) -> None:
        data = bytes(range(0, 20))
        assert _extract_strings(data, min_length=4) == []


class TestEntropy:
    """Tests for entropy calculation."""

    def test_zero_entropy(self) -> None:
        """Uniform bytes have zero entropy."""
        data = b"\x00" * 256
        assert _section_entropy(data) == 0.0

    def test_max_entropy(self) -> None:
        """All unique bytes approach 8.0 entropy."""
        data = bytes(range(256))
        ent = _section_entropy(data)
        assert 7.9 < ent <= 8.0

    def test_empty(self) -> None:
        assert _section_entropy(b"") == 0.0


class TestLoadBinary:
    """Tests for loading real (fixture) binaries."""

    @pytest.fixture
    def elf_path(self, fixtures_dir: Path) -> Path:
        p = fixtures_dir / "test_elf64"
        if not p.exists():
            pytest.skip("Test ELF fixture not found; run create_test_elf.py first")
        return p

    def test_load_elf(self, elf_path: Path) -> None:
        """Loading a valid ELF produces correct metadata."""
        info = load_binary(elf_path)
        assert info.file_format == "ELF"
        assert info.arch == "x86_64"
        assert info.bits == 64
        assert info.endian == "little"
        assert info.entry_point == 0x401000

    def test_elf_sections(self, elf_path: Path) -> None:
        """ELF sections are parsed."""
        info = load_binary(elf_path)
        section_names = [s.name for s in info.sections]
        assert ".text" in section_names

    def test_elf_symbols(self, elf_path: Path) -> None:
        """ELF symbols are extracted."""
        info = load_binary(elf_path)
        sym_names = [s.name for s in info.symbols]
        assert "main" in sym_names

    def test_elf_functions(self, elf_path: Path) -> None:
        """functions() filters to function symbols only."""
        info = load_binary(elf_path)
        funcs = info.functions()
        func_names = [f.name for f in funcs]
        assert "main" in func_names

    def test_elf_hashes(self, elf_path: Path) -> None:
        """MD5 and SHA256 are computed."""
        info = load_binary(elf_path)
        assert len(info.md5) == 32
        assert len(info.sha256) == 64

    def test_elf_security(self, elf_path: Path) -> None:
        """Security summary is populated."""
        info = load_binary(elf_path)
        sec = info.security_summary
        assert "pie" in sec
        assert "nx" in sec
        assert "canary" in sec

    def test_elf_nx_disabled(self, elf_path: Path) -> None:
        """Our test binary has NX disabled (executable stack)."""
        info = load_binary(elf_path)
        # The test binary sets PF_X on GNU_STACK
        assert info.nx is False

    def test_arch_override(self, elf_path: Path) -> None:
        """Architecture override is respected."""
        info = load_binary(elf_path, arch_override="arm64")
        assert info.arch == "arm64"

    def test_base_address_override_hex(self, elf_path: Path) -> None:
        """Base address override (hex string) is applied."""
        info = load_binary(elf_path, base_address="0x8000000")
        assert info.base_address == 0x8000000

    def test_file_not_found(self, tmp_dir: Path) -> None:
        """FileNotFoundError for missing binary."""
        with pytest.raises(FileNotFoundError):
            load_binary(tmp_dir / "nope")

    def test_to_dict(self, elf_path: Path) -> None:
        """to_dict() produces a serializable dict."""
        info = load_binary(elf_path)
        d = info.to_dict()
        assert d["format"] == "ELF"
        assert isinstance(d["security"], dict)
