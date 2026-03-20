"""Tests for the RAVEN Shellcode Generation module."""

from __future__ import annotations

import pytest

from raven.exploitation.shellcode import (
    SHELLCODE_LIBRARY,
    Shellcode,
    ShellcodeArch,
    ShellcodeType,
    get_shellcode,
    list_shellcodes,
)


class TestShellcodeEnums:
    """Tests for shellcode enum types."""

    def test_shellcode_type_values(self) -> None:
        assert str(ShellcodeType.EXECVE) == "execve"
        assert str(ShellcodeType.REVERSE_SHELL) == "reverse_shell"
        assert str(ShellcodeType.BIND_SHELL) == "bind_shell"
        assert str(ShellcodeType.READ_FLAG) == "read_flag"
        assert str(ShellcodeType.CUSTOM) == "custom"

    def test_shellcode_arch_values(self) -> None:
        assert str(ShellcodeArch.X86) == "x86"
        assert str(ShellcodeArch.X86_64) == "x86_64"
        assert str(ShellcodeArch.ARM) == "arm"
        assert str(ShellcodeArch.ARM64) == "arm64"


class TestShellcodeDataclass:
    """Tests for the Shellcode dataclass."""

    def test_creation(self) -> None:
        sc = Shellcode(
            name="test",
            arch=ShellcodeArch.X86_64,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x48\x31\xf6\x56",
        )
        assert sc.name == "test"
        assert sc.size == 4  # auto-computed

    def test_size_auto_computed(self) -> None:
        sc = Shellcode(
            name="test", arch=ShellcodeArch.X86_64,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x90" * 10,
        )
        assert sc.size == 10

    def test_null_free_flag_corrected(self) -> None:
        # Claim null_free but bytes contain null
        sc = Shellcode(
            name="test", arch=ShellcodeArch.X86_64,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x48\x00\xf6",
            null_free=True,
        )
        # __post_init__ should correct this
        assert sc.null_free is False

    def test_has_nulls_property(self) -> None:
        sc_with = Shellcode(
            name="test", arch=ShellcodeArch.X86,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x00\x01\x02",
        )
        assert sc_with.has_nulls is True

        sc_without = Shellcode(
            name="test", arch=ShellcodeArch.X86,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x01\x02\x03",
        )
        assert sc_without.has_nulls is False

    def test_to_dict(self) -> None:
        sc = Shellcode(
            name="test", arch=ShellcodeArch.X86_64,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x48\x31\xf6",
            null_free=True,
            description="A test shellcode",
        )
        d = sc.to_dict()
        assert d["name"] == "test"
        assert d["arch"] == "x86_64"
        assert d["type"] == "execve"
        assert d["size"] == 3
        assert d["null_free"] is True
        assert d["hex"] == "4831f6"

    def test_to_python_literal(self) -> None:
        sc = Shellcode(
            name="test", arch=ShellcodeArch.X86_64,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x48\x31\xf6",
        )
        code = sc.to_python_literal()
        assert "shellcode = (" in code
        assert "\\x48\\x31\\xf6" in code

    def test_to_c_array(self) -> None:
        sc = Shellcode(
            name="test", arch=ShellcodeArch.X86_64,
            shellcode_type=ShellcodeType.EXECVE,
            raw_bytes=b"\x48\x31\xf6",
        )
        code = sc.to_c_array()
        assert "unsigned char shellcode[3]" in code
        assert "0x48" in code
        assert "0x31" in code
        assert "0xf6" in code


class TestShellcodeLibrary:
    """Tests for the pre-built shellcode library."""

    def test_library_not_empty(self) -> None:
        assert len(SHELLCODE_LIBRARY) >= 5

    def test_execve_x86_64(self) -> None:
        sc = SHELLCODE_LIBRARY[(ShellcodeArch.X86_64, ShellcodeType.EXECVE)]
        assert sc.arch == ShellcodeArch.X86_64
        assert sc.null_free is True
        assert sc.size == 25
        assert not sc.has_nulls

    def test_execve_x86(self) -> None:
        sc = SHELLCODE_LIBRARY[(ShellcodeArch.X86, ShellcodeType.EXECVE)]
        assert sc.arch == ShellcodeArch.X86
        assert sc.null_free is True
        assert sc.size == 21

    def test_execve_arm(self) -> None:
        sc = SHELLCODE_LIBRARY[(ShellcodeArch.ARM, ShellcodeType.EXECVE)]
        assert sc.arch == ShellcodeArch.ARM
        # ARM shellcode has a null terminator for the string
        assert sc.null_free is False

    def test_reverse_shell_x86_64(self) -> None:
        sc = SHELLCODE_LIBRARY[(ShellcodeArch.X86_64, ShellcodeType.REVERSE_SHELL)]
        assert sc.arch == ShellcodeArch.X86_64
        assert sc.shellcode_type == ShellcodeType.REVERSE_SHELL
        assert sc.size > 0

    def test_bind_shell_x86_64(self) -> None:
        sc = SHELLCODE_LIBRARY[(ShellcodeArch.X86_64, ShellcodeType.BIND_SHELL)]
        assert sc.arch == ShellcodeArch.X86_64
        assert sc.shellcode_type == ShellcodeType.BIND_SHELL


class TestGetShellcode:
    """Tests for the get_shellcode() convenience function."""

    def test_get_existing(self) -> None:
        sc = get_shellcode(arch="x86_64", shellcode_type="execve")
        assert sc is not None
        assert sc.arch == ShellcodeArch.X86_64

    def test_get_nonexistent_arch(self) -> None:
        sc = get_shellcode(arch="mips", shellcode_type="execve")
        assert sc is None

    def test_get_nonexistent_type(self) -> None:
        sc = get_shellcode(arch="x86_64", shellcode_type="nonexistent")
        assert sc is None

    def test_get_nonexistent_combination(self) -> None:
        sc = get_shellcode(arch="arm64", shellcode_type="execve")
        assert sc is None  # arm64 execve not in library


class TestListShellcodes:
    """Tests for the list_shellcodes() function."""

    def test_returns_list(self) -> None:
        result = list_shellcodes()
        assert isinstance(result, list)
        assert len(result) >= 5

    def test_entries_have_required_fields(self) -> None:
        result = list_shellcodes()
        for entry in result:
            assert "arch" in entry
            assert "type" in entry
            assert "name" in entry
            assert "size" in entry
            assert "null_free" in entry
