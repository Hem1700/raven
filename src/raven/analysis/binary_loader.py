"""
RAVEN Binary Loader.

Loads binary files (ELF, PE, Mach-O) and extracts structural metadata
into a unified :class:`BinaryInfo` representation that downstream agents
and analysis modules consume.

Supports:
  - ELF (via pyelftools)
  - PE  (via pefile)
  - Mach-O (lightweight built-in parser for headers)
  - Raw binaries (minimal metadata)
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raven.core.logger import get_logger

logger = get_logger("analysis.binary_loader")


# ---------------------------------------------------------------------------
# Unified data model
# ---------------------------------------------------------------------------

@dataclass
class SectionInfo:
    """A section / segment within the binary."""

    name: str
    address: int
    size: int
    entropy: float = 0.0
    flags: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "size": self.size,
            "entropy": round(self.entropy, 3),
            "flags": self.flags,
        }


@dataclass
class SymbolInfo:
    """A symbol (function / variable) from the symbol table."""

    name: str
    address: int
    size: int = 0
    sym_type: str = "unknown"  # "function", "object", "unknown"
    bind: str = ""  # "local", "global", "weak"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "size": self.size,
            "type": self.sym_type,
            "bind": self.bind,
        }


@dataclass
class BinaryInfo:
    """Unified representation of a loaded binary."""

    path: Path
    file_format: str = "unknown"       # "ELF", "PE", "Mach-O", "raw"
    arch: str = "unknown"              # "x86", "x86_64", "arm", "arm64", etc.
    bits: int = 0                      # 32 or 64
    endian: str = "little"
    entry_point: int = 0
    base_address: int = 0

    # Security mechanisms
    pie: bool = False
    nx: bool = False
    canary: bool = False
    relro: str = "none"                # "none", "partial", "full"
    fortify: bool = False
    stripped: bool = False

    # Contents
    sections: list[SectionInfo] = field(default_factory=list)
    symbols: list[SymbolInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)

    # File hashes
    md5: str = ""
    sha256: str = ""
    file_size: int = 0

    # Raw bytes (for small binaries; large ones should not be held in memory)
    raw_bytes: bytes = b""

    @property
    def is_64bit(self) -> bool:
        return self.bits == 64

    @property
    def security_summary(self) -> dict[str, Any]:
        """Return a dict of security mechanism statuses."""
        return {
            "pie": self.pie,
            "nx": self.nx,
            "canary": self.canary,
            "relro": self.relro,
            "fortify": self.fortify,
            "stripped": self.stripped,
        }

    def functions(self) -> list[SymbolInfo]:
        """Return only function symbols."""
        return [s for s in self.symbols if s.sym_type == "function"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": str(self.path),
            "format": self.file_format,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "entry_point": hex(self.entry_point),
            "base_address": hex(self.base_address),
            "security": self.security_summary,
            "md5": self.md5,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "sections": [s.to_dict() for s in self.sections],
            "symbols_count": len(self.symbols),
            "imports": self.imports,
            "exports": self.exports,
            "libraries": self.libraries,
        }


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

# Magic bytes for format identification
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit (reverse)
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit (reverse)
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe",  # Fat binary (big-endian)
    b"\xbe\xba\xfe\xca",  # Fat binary (little-endian)
}


def _detect_format(data: bytes) -> str:
    """Detect the binary format from the first few bytes."""
    if data[:4] == _ELF_MAGIC:
        return "ELF"
    if data[:2] == _PE_MAGIC:
        return "PE"
    if data[:4] in _MACHO_MAGICS:
        return "Mach-O"
    if data[:4] in _FAT_MAGICS:
        return "Mach-O"  # Universal / fat binary (contains Mach-O slices)
    return "raw"


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------

def _compute_hashes(data: bytes) -> tuple[str, str]:
    """Return (md5, sha256) hex digests for *data*."""
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

def _extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings from raw bytes.

    Args:
        data: Raw binary data.
        min_length: Minimum string length to keep.

    Returns:
        List of extracted strings (capped at 500).
    """
    strings: list[str] = []
    current: list[str] = []

    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []

    if len(current) >= min_length:
        strings.append("".join(current))

    return strings[:500]


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------

def _section_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of *data*."""
    import math

    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# ELF loader
# ---------------------------------------------------------------------------

def _load_elf(path: Path, data: bytes, arch_override: str | None = None) -> BinaryInfo:
    """Load an ELF binary using pyelftools."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
    import io

    stream = io.BytesIO(data)
    elf = ELFFile(stream)

    # Architecture mapping
    _ARCH_MAP = {
        "EM_386": "x86",
        "EM_X86_64": "x86_64",
        "EM_ARM": "arm",
        "EM_AARCH64": "arm64",
        "EM_MIPS": "mips",
        "EM_PPC": "ppc",
        "EM_PPC64": "ppc64",
    }

    arch = arch_override or _ARCH_MAP.get(elf.header.e_machine, "unknown")
    bits = 64 if elf.elfclass == 64 else 32
    endian = "little" if elf.little_endian else "big"
    entry = elf.header.e_entry

    md5, sha256 = _compute_hashes(data)

    info = BinaryInfo(
        path=path,
        file_format="ELF",
        arch=arch,
        bits=bits,
        endian=endian,
        entry_point=entry,
        md5=md5,
        sha256=sha256,
        file_size=len(data),
    )

    # Sections
    for section in elf.iter_sections():
        sec_data = section.data() if section.header.sh_size > 0 else b""
        ent = _section_entropy(sec_data) if sec_data else 0.0
        flags_val = section.header.sh_flags
        flag_str_parts = []
        if flags_val & 0x1:
            flag_str_parts.append("W")
        if flags_val & 0x2:
            flag_str_parts.append("A")
        if flags_val & 0x4:
            flag_str_parts.append("X")
        flag_str = "".join(flag_str_parts)

        info.sections.append(
            SectionInfo(
                name=section.name,
                address=section.header.sh_addr,
                size=section.header.sh_size,
                entropy=ent,
                flags=flag_str,
            )
        )

    # Symbols
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for sym in section.iter_symbols():
                if not sym.name:
                    continue
                st_info_type = sym.entry.st_info.type
                sym_type = "function" if st_info_type == "STT_FUNC" else (
                    "object" if st_info_type == "STT_OBJECT" else "unknown"
                )
                bind = sym.entry.st_info.bind.replace("STB_", "").lower()
                info.symbols.append(
                    SymbolInfo(
                        name=sym.name,
                        address=sym.entry.st_value,
                        size=sym.entry.st_size,
                        sym_type=sym_type,
                        bind=bind,
                    )
                )

    # Dynamic section - imports and libraries
    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    info.libraries.append(tag.needed)

    # Imports / Exports from dynsym
    for section in elf.iter_sections():
        if hasattr(section, "name") and section.name == ".dynsym":
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if not sym.name:
                        continue
                    if sym.entry.st_shndx == "SHN_UNDEF":
                        info.imports.append(sym.name)
                    elif sym.entry.st_info.bind == "STB_GLOBAL" and sym.entry.st_value != 0:
                        info.exports.append(sym.name)

    # Security mechanisms
    info.pie = elf.header.e_type == "ET_DYN"

    # Check NX (GNU_STACK segment)
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_GNU_STACK":
            # If PF_X is not set, NX is enabled
            info.nx = not bool(segment.header.p_flags & 0x1)
            break
    else:
        info.nx = False

    # Check RELRO
    has_gnu_relro = False
    has_bind_now = False
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_GNU_RELRO":
            has_gnu_relro = True
    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    has_bind_now = True
                if tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & 0x8:
                    has_bind_now = True

    if has_gnu_relro and has_bind_now:
        info.relro = "full"
    elif has_gnu_relro:
        info.relro = "partial"
    else:
        info.relro = "none"

    # Check for stack canary (presence of __stack_chk_fail in imports)
    info.canary = "__stack_chk_fail" in info.imports

    # Check for FORTIFY (_chk functions in imports)
    info.fortify = any("_chk" in imp for imp in info.imports)

    # Check stripped
    has_symtab = any(s.name == ".symtab" for s in info.sections)
    info.stripped = not has_symtab

    # Strings
    info.strings = _extract_strings(data)

    logger.info(
        "Loaded ELF: %s (%s, %d-bit, %s)",
        path.name, arch, bits, endian,
    )
    return info


# ---------------------------------------------------------------------------
# PE loader
# ---------------------------------------------------------------------------

def _load_pe(path: Path, data: bytes, arch_override: str | None = None) -> BinaryInfo:
    """Load a PE binary using pefile."""
    import pefile

    pe = pefile.PE(data=data, fast_load=False)

    # Architecture
    _PE_ARCH = {
        0x14C: "x86",
        0x8664: "x86_64",
        0x1C0: "arm",
        0xAA64: "arm64",
    }
    machine = pe.FILE_HEADER.Machine
    arch = arch_override or _PE_ARCH.get(machine, "unknown")
    bits = 64 if machine in (0x8664, 0xAA64) else 32

    md5, sha256 = _compute_hashes(data)

    info = BinaryInfo(
        path=path,
        file_format="PE",
        arch=arch,
        bits=bits,
        endian="little",
        entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase,
        base_address=pe.OPTIONAL_HEADER.ImageBase,
        md5=md5,
        sha256=sha256,
        file_size=len(data),
    )

    # Sections
    for section in pe.sections:
        sec_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        sec_data = section.get_data()
        info.sections.append(
            SectionInfo(
                name=sec_name,
                address=section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase,
                size=section.Misc_VirtualSize,
                entropy=_section_entropy(sec_data),
                flags=_pe_section_flags(section.Characteristics),
            )
        )

    # Imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            lib_name = entry.dll.decode("ascii", errors="replace") if entry.dll else ""
            if lib_name:
                info.libraries.append(lib_name)
            for imp in entry.imports:
                if imp.name:
                    info.imports.append(imp.name.decode("ascii", errors="replace"))

    # Exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                info.exports.append(exp.name.decode("ascii", errors="replace"))

    # Security: ASLR / DEP / PIE
    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    info.pie = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    info.nx = bool(dll_chars & 0x0100)   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT

    # Strings
    info.strings = _extract_strings(data)

    pe.close()
    logger.info("Loaded PE: %s (%s, %d-bit)", path.name, arch, bits)
    return info


def _pe_section_flags(characteristics: int) -> str:
    """Convert PE section characteristics to a flag string."""
    parts: list[str] = []
    if characteristics & 0x20000000:
        parts.append("X")
    if characteristics & 0x40000000:
        parts.append("R")
    if characteristics & 0x80000000:
        parts.append("W")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Mach-O loader (lightweight)
# ---------------------------------------------------------------------------

def _extract_fat_slice(data: bytes) -> bytes:
    """Extract the best architecture slice from a Mach-O universal (fat) binary.

    Prefers x86_64 or arm64 slices when available, otherwise returns
    the first slice. Returns the original data if not a fat binary.
    """
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (0xCAFEBABE, 0xBEBAFECA):
        return data

    # Fat header: magic(4) + nfat_arch(4)
    nfat = struct.unpack_from(">I", data, 4)[0]
    if nfat == 0 or nfat > 20:
        return data  # sanity check

    # Each fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4) = 20 bytes
    slices: list[tuple[int, int, int]] = []  # (cputype, offset, size)
    for i in range(nfat):
        base = 8 + i * 20
        if base + 20 > len(data):
            break
        cputype, cpusubtype, offset, size, align = struct.unpack_from(">IIIII", data, base)
        slices.append((cputype, offset, size))

    if not slices:
        return data

    # Prefer x86_64 (0x01000007) or arm64 (0x0100000C)
    preferred = {0x01000007, 0x0100000C}
    for cputype, offset, size in slices:
        if cputype in preferred and offset + size <= len(data):
            logger.debug("Extracted fat slice: cputype=%#x offset=%d size=%d", cputype, offset, size)
            return data[offset : offset + size]

    # Fallback: first slice
    _, offset, size = slices[0]
    if offset + size <= len(data):
        return data[offset : offset + size]

    return data


def _load_macho(path: Path, data: bytes, arch_override: str | None = None) -> BinaryInfo:
    """Load a Mach-O binary using built-in struct parsing.

    This is a lightweight parser for Phase 1; future phases may use
    a dedicated library for deeper Mach-O analysis.
    Handles universal (fat) binaries by extracting the best slice.
    """
    # Handle fat/universal binaries
    data = _extract_fat_slice(data)

    magic = struct.unpack_from("<I", data, 0)[0]
    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    is_swap = magic in (0xCEFAEDFE, 0xCFFAEDFE)  # big-endian on little-endian host
    endian_fmt = ">" if is_swap else "<"
    bits = 64 if is_64 else 32

    # Parse header
    if is_64:
        hdr_fmt = f"{endian_fmt}IIIIIII"
        hdr_size = struct.calcsize(hdr_fmt)
        magic_val, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            hdr_fmt, data, 0
        )
        # 64-bit has an extra reserved field
        offset = hdr_size + 4
    else:
        hdr_fmt = f"{endian_fmt}IIIIIII"
        hdr_size = struct.calcsize(hdr_fmt)
        magic_val, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            hdr_fmt, data, 0
        )
        offset = hdr_size

    # Architecture
    _CPU_MAP = {
        7: "x86",        # CPU_TYPE_X86
        12: "arm",       # CPU_TYPE_ARM
        0x01000007: "x86_64",   # CPU_TYPE_X86_64
        0x0100000C: "arm64",    # CPU_TYPE_ARM64
    }
    arch = arch_override or _CPU_MAP.get(cputype, "unknown")
    is_pie = bool(flags & 0x200000)  # MH_PIE

    md5, sha256 = _compute_hashes(data)

    info = BinaryInfo(
        path=path,
        file_format="Mach-O",
        arch=arch,
        bits=bits,
        endian="big" if is_swap else "little",
        pie=is_pie,
        md5=md5,
        sha256=sha256,
        file_size=len(data),
    )

    # Parse load commands to find sections and entry point
    sections: list[SectionInfo] = []
    imports: list[str] = []
    libraries: list[str] = []

    cmd_offset = offset
    for _ in range(ncmds):
        if cmd_offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(f"{endian_fmt}II", data, cmd_offset)

        # LC_SEGMENT / LC_SEGMENT_64
        if cmd in (0x01, 0x19):
            seg_name_end = cmd_offset + 8 + 16
            if seg_name_end <= len(data):
                seg_name = data[cmd_offset + 8 : seg_name_end].rstrip(b"\x00").decode(
                    "ascii", errors="replace"
                )
                if cmd == 0x19:  # 64-bit
                    if cmd_offset + 48 + 8 <= len(data):
                        vmaddr, vmsize = struct.unpack_from(
                            f"{endian_fmt}QQ", data, cmd_offset + 24
                        )
                        sections.append(
                            SectionInfo(name=seg_name, address=vmaddr, size=vmsize)
                        )
                else:  # 32-bit
                    if cmd_offset + 36 + 8 <= len(data):
                        vmaddr, vmsize = struct.unpack_from(
                            f"{endian_fmt}II", data, cmd_offset + 24
                        )
                        sections.append(
                            SectionInfo(name=seg_name, address=vmaddr, size=vmsize)
                        )

        # LC_MAIN (entry point)
        if cmd == 0x80000028:
            if cmd_offset + 16 <= len(data):
                entryoff = struct.unpack_from(f"{endian_fmt}Q", data, cmd_offset + 8)[0]
                info.entry_point = entryoff

        # LC_LOAD_DYLIB
        if cmd == 0x0C:
            str_offset_field = cmd_offset + 8
            if str_offset_field + 4 <= len(data):
                str_offset = struct.unpack_from(f"{endian_fmt}I", data, str_offset_field)[0]
                abs_offset = cmd_offset + str_offset
                end = data.find(b"\x00", abs_offset)
                if end != -1 and abs_offset < len(data):
                    lib = data[abs_offset:end].decode("ascii", errors="replace")
                    libraries.append(lib)

        cmd_offset += cmdsize

    info.sections = sections
    info.libraries = libraries
    info.strings = _extract_strings(data)

    logger.info("Loaded Mach-O: %s (%s, %d-bit)", path.name, arch, bits)
    return info


# ---------------------------------------------------------------------------
# Raw binary loader
# ---------------------------------------------------------------------------

def _load_raw(path: Path, data: bytes, arch_override: str | None = None) -> BinaryInfo:
    """Fallback loader for unrecognised formats."""
    md5, sha256 = _compute_hashes(data)
    return BinaryInfo(
        path=path,
        file_format="raw",
        arch=arch_override or "unknown",
        md5=md5,
        sha256=sha256,
        file_size=len(data),
        strings=_extract_strings(data),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_binary(
    path: Path | str,
    arch_override: str | None = None,
    base_address: str | int | None = None,
) -> BinaryInfo:
    """Load a binary file and return its :class:`BinaryInfo`.

    Args:
        path: Path to the binary file.
        arch_override: Force a specific architecture string.
        base_address: Override the base address (hex string or int).

    Returns:
        A populated :class:`BinaryInfo` instance.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the file cannot be read.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found: {path}")

    data = path.read_bytes()
    if not data:
        raise ValueError(f"Binary is empty: {path}")

    fmt = _detect_format(data)
    logger.debug("Detected format: %s for %s", fmt, path.name)

    loaders = {
        "ELF": _load_elf,
        "PE": _load_pe,
        "Mach-O": _load_macho,
        "raw": _load_raw,
    }

    loader = loaders.get(fmt, _load_raw)
    info = loader(path, data, arch_override)

    # Apply base address override
    if base_address is not None:
        if isinstance(base_address, str):
            info.base_address = int(base_address, 16) if base_address.startswith("0x") else int(base_address)
        else:
            info.base_address = int(base_address)

    return info
