"""Tests for the RAVEN Advanced ROP module."""

from __future__ import annotations

import struct

import pytest

from raven.exploitation.advanced_rop import (
    GadgetType,
    JOPGadget,
    ROPChain,
    ROPChainEntry,
    ROPGadget,
    SigreturnFrame,
    build_execve_chain,
    build_mprotect_chain,
    build_srop_execve,
    find_gadgets,
    find_gadgets_by_type,
    find_jop_gadgets,
    optimize_chain,
)


# ---------------------------------------------------------------------------
# Helper: construct binary data with known gadgets embedded
# ---------------------------------------------------------------------------

def _make_binary_with_gadgets() -> tuple[bytes, int]:
    """Build fake binary data with known gadget byte sequences embedded.

    Returns:
        (data, base_address) suitable for ``find_gadgets``.
    """
    base = 0x400000
    # Pad + gadgets at known offsets
    data = bytearray(0x200)
    # pop rdi; ret at offset 0x10
    data[0x10] = 0x5F
    data[0x11] = 0xC3
    # pop rsi; ret at offset 0x20
    data[0x20] = 0x5E
    data[0x21] = 0xC3
    # pop rdx; ret at offset 0x30
    data[0x30] = 0x5A
    data[0x31] = 0xC3
    # pop rax; ret at offset 0x40
    data[0x40] = 0x58
    data[0x41] = 0xC3
    # syscall; ret at offset 0x50
    data[0x50] = 0x0F
    data[0x51] = 0x05
    data[0x52] = 0xC3
    # xor rsi, rsi; ret at offset 0x60
    data[0x60] = 0x48
    data[0x61] = 0x31
    data[0x62] = 0xF6
    data[0x63] = 0xC3
    # ret at offset 0x70
    data[0x70] = 0xC3
    # nop; ret at offset 0x80
    data[0x80] = 0x90
    data[0x81] = 0xC3
    # leave; ret at offset 0x90
    data[0x90] = 0xC9
    data[0x91] = 0xC3
    # jmp rax at offset 0xA0 (JOP)
    data[0xA0] = 0xFF
    data[0xA1] = 0xE0
    return bytes(data), base


class TestROPGadget:
    """Tests for the ROPGadget dataclass."""

    def test_gadget_creation(self) -> None:
        g = ROPGadget(address=0x401234, instructions="pop rdi; ret",
                      gadget_type=GadgetType.POP_REG, registers=["rdi"],
                      size=2, quality=85)
        assert g.address == 0x401234
        assert g.gadget_type == GadgetType.POP_REG
        assert "rdi" in g.registers

    def test_gadget_to_dict(self) -> None:
        g = ROPGadget(address=0x401234, instructions="pop rdi; ret")
        d = g.to_dict()
        assert d["address"] == "0x401234"
        assert d["instructions"] == "pop rdi; ret"

    def test_gadget_type_str(self) -> None:
        assert str(GadgetType.POP_REG) == "pop_reg"
        assert str(GadgetType.SYSCALL) == "syscall"


class TestROPChain:
    """Tests for the ROPChain class."""

    def test_empty_chain(self) -> None:
        chain = ROPChain()
        assert chain.length == 0
        assert chain.to_bytes() == b""

    def test_add_gadget_and_constant(self) -> None:
        chain = ROPChain(arch="x86_64")
        chain.add_gadget(0x401234, label="pop_rdi", comment="pop rdi")
        chain.add_constant(0xDEADBEEF, comment="argument")
        assert chain.length == 2
        assert chain.entries[0].is_gadget is True
        assert chain.entries[1].is_gadget is False

    def test_to_bytes_x86_64(self) -> None:
        chain = ROPChain(arch="x86_64")
        chain.add_gadget(0x401234)
        chain.add_constant(0xDEADBEEF)
        payload = chain.to_bytes()
        assert len(payload) == 16
        val1 = struct.unpack("<Q", payload[:8])[0]
        val2 = struct.unpack("<Q", payload[8:])[0]
        assert val1 == 0x401234
        assert val2 == 0xDEADBEEF

    def test_to_bytes_x86_32(self) -> None:
        chain = ROPChain(arch="x86")
        chain.add_gadget(0x0804ABCD)
        payload = chain.to_bytes()
        assert len(payload) == 4
        val = struct.unpack("<I", payload)[0]
        assert val == 0x0804ABCD

    def test_to_pwntools_code(self) -> None:
        chain = ROPChain(arch="x86_64")
        chain.add_gadget(0x401234, label="pop_rdi_ret", comment="pop rdi")
        chain.add_constant(0x42, comment="value")
        code = chain.to_pwntools_code()
        assert "p64" in code
        assert "pop_rdi_ret" in code
        assert "0x42" in code

    def test_to_dict(self) -> None:
        chain = ROPChain(arch="x86_64", description="test chain")
        chain.add_gadget(0x401234)
        d = chain.to_dict()
        assert d["arch"] == "x86_64"
        assert d["length"] == 1
        assert len(d["entries"]) == 1


class TestFindGadgets:
    """Tests for the gadget finder."""

    def test_find_gadgets_in_binary(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        assert len(gadgets) > 0
        # Check that we found at least pop rdi, pop rsi, syscall
        instructions = {g.instructions for g in gadgets}
        assert "pop rdi; ret" in instructions
        assert "pop rsi; ret" in instructions

    def test_find_gadgets_addresses(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        addrs = {g.address for g in gadgets}
        assert base + 0x10 in addrs  # pop rdi; ret
        assert base + 0x40 in addrs  # pop rax; ret

    def test_find_gadgets_empty_data(self) -> None:
        gadgets = find_gadgets(b"", base_address=0)
        assert gadgets == []

    def test_find_gadgets_wrong_arch(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base, arch="arm64")
        assert gadgets == []

    def test_find_gadgets_max_limit(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base, max_gadgets=3)
        assert len(gadgets) <= 3

    def test_find_gadgets_sorted_by_quality(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        qualities = [g.quality for g in gadgets]
        assert qualities == sorted(qualities, reverse=True)


class TestFindGadgetsByType:
    """Tests for the gadget filter helper."""

    def test_filter_by_type(self) -> None:
        data, base = _make_binary_with_gadgets()
        all_gadgets = find_gadgets(data, base_address=base)
        pops = find_gadgets_by_type(all_gadgets, GadgetType.POP_REG)
        assert all(g.gadget_type == GadgetType.POP_REG for g in pops)
        assert len(pops) >= 4  # rdi, rsi, rdx, rax at minimum

    def test_filter_by_type_and_register(self) -> None:
        data, base = _make_binary_with_gadgets()
        all_gadgets = find_gadgets(data, base_address=base)
        pop_rdi = find_gadgets_by_type(all_gadgets, GadgetType.POP_REG, "rdi")
        assert len(pop_rdi) >= 1
        assert "rdi" in pop_rdi[0].registers

    def test_filter_no_match(self) -> None:
        gadgets = [ROPGadget(address=0, instructions="ret", gadget_type=GadgetType.RET)]
        result = find_gadgets_by_type(gadgets, GadgetType.POP_REG)
        assert result == []


class TestBuildExecveChain:
    """Tests for execve ROP chain building."""

    def test_build_complete_chain(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        binsh = 0x601000
        chain = build_execve_chain(gadgets, binsh, arch="x86_64")
        assert chain.length > 0
        assert "execve" in chain.description
        assert "INCOMPLETE" not in chain.description

    def test_chain_contains_binsh_address(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        binsh = 0x601000
        chain = build_execve_chain(gadgets, binsh)
        values = [e.value for e in chain.entries]
        assert binsh in values

    def test_chain_contains_syscall_number(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        chain = build_execve_chain(gadgets, 0x601000)
        values = [e.value for e in chain.entries]
        assert 59 in values  # SYS_execve

    def test_incomplete_chain_on_missing_gadgets(self) -> None:
        # Only provide a ret gadget -- not enough for execve
        gadgets = [ROPGadget(address=0x401000, instructions="ret",
                             gadget_type=GadgetType.RET)]
        chain = build_execve_chain(gadgets, 0x601000)
        assert "INCOMPLETE" in chain.description


class TestBuildMprotectChain:
    """Tests for mprotect ROP chain building."""

    def test_build_complete_mprotect(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        chain = build_mprotect_chain(gadgets, 0x601000, 0x1000)
        assert chain.length > 0
        assert "mprotect" in chain.description
        # Check RWX permission value (7)
        values = [e.value for e in chain.entries]
        assert 7 in values
        assert 10 in values  # SYS_mprotect

    def test_incomplete_mprotect_on_missing_gadgets(self) -> None:
        gadgets = [ROPGadget(address=0x401000, instructions="pop rdi; ret",
                             gadget_type=GadgetType.POP_REG, registers=["rdi"])]
        chain = build_mprotect_chain(gadgets, 0x601000)
        assert "INCOMPLETE" in chain.description


class TestSigreturnFrame:
    """Tests for SROP sigreturn frame generation."""

    def test_frame_creation(self) -> None:
        frame = SigreturnFrame(rax=59, rdi=0x601000, rip=0x401050)
        assert frame.rax == 59
        assert frame.rdi == 0x601000
        assert frame.cs == 0x33  # 64-bit default
        assert frame.ss == 0x2B

    def test_frame_to_bytes_size(self) -> None:
        frame = SigreturnFrame()
        data = frame.to_bytes()
        assert len(data) == 248

    def test_frame_to_dict(self) -> None:
        frame = SigreturnFrame(rax=59, rdi=0x601000)
        d = frame.to_dict()
        assert d["rax"] == "0x3b"
        assert d["rdi"] == "0x601000"

    def test_build_srop_execve(self) -> None:
        chain, frame = build_srop_execve(
            syscall_addr=0x401050, binsh_addr=0x601000, stack_addr=0x700000,
        )
        assert chain.technique == "srop"
        assert frame.rax == 59
        assert frame.rdi == 0x601000
        assert frame.rip == 0x401050
        assert frame.rsp == 0x700000
        # Chain should include the sigreturn syscall number (15)
        values = [e.value for e in chain.entries]
        assert 15 in values


class TestJOPGadgets:
    """Tests for JOP (Jump-Oriented Programming) gadget finding."""

    def test_find_jop_gadgets(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_jop_gadgets(data, base_address=base)
        assert len(gadgets) >= 1  # jmp rax at 0xA0
        jmp_rax = [g for g in gadgets if g.jump_register == "rax"]
        assert len(jmp_rax) >= 1

    def test_jop_gadget_address(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_jop_gadgets(data, base_address=base)
        addrs = {g.address for g in gadgets}
        assert base + 0xA0 in addrs  # jmp rax

    def test_jop_empty_data(self) -> None:
        gadgets = find_jop_gadgets(b"", base_address=0)
        assert gadgets == []

    def test_jop_gadget_to_dict(self) -> None:
        g = JOPGadget(address=0x401234, instructions="jmp rax",
                      jump_register="rax", size=2)
        d = g.to_dict()
        assert d["address"] == "0x401234"
        assert d["jump_register"] == "rax"


class TestOptimizeChain:
    """Tests for ROP chain optimization."""

    def test_optimize_preserves_chain(self) -> None:
        data, base = _make_binary_with_gadgets()
        gadgets = find_gadgets(data, base_address=base)
        chain = build_execve_chain(gadgets, 0x601000)
        optimized = optimize_chain(chain, gadgets)
        # Optimized chain should have same number of entries
        assert optimized.length == chain.length
        assert "optimized" in optimized.description

    def test_optimize_empty_chain(self) -> None:
        chain = ROPChain()
        optimized = optimize_chain(chain, [])
        assert optimized.length == 0
