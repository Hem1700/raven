#!/usr/bin/env python3
"""
Generate a minimal ELF binary for testing RAVEN's binary loader.

This creates a simple, well-formed ELF64 binary with a few sections
and symbols. It does not need to be executable -- the loader only
needs to parse the structure.
"""

from __future__ import annotations

import struct
from pathlib import Path


def create_minimal_elf64(output: Path) -> None:
    """Write a minimal ELF64 binary to *output*."""
    # ELF header constants
    EI_MAG = b"\x7fELF"
    ELFCLASS64 = 2
    ELFDATA2LSB = 1  # Little-endian
    EV_CURRENT = 1
    ELFOSABI_NONE = 0
    ET_EXEC = 2
    EM_X86_64 = 0x3E
    ENTRY = 0x401000

    # We will create: ELF header + 2 program headers + section data + section headers
    # Keep it simple: .text section with a few bytes, .shstrtab for names

    # Section name string table
    shstrtab = b"\x00.text\x00.shstrtab\x00.symtab\x00.strtab\x00"

    # Symbol string table
    strtab = b"\x00main\x00_start\x00vulnerable_func\x00"

    # .text section: just a few NOP-like bytes
    text_data = b"\xcc" * 64  # INT3 instructions

    # Symbol table entries (24 bytes each for ELF64)
    # st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
    def sym_entry(name_offset: int, value: int, size: int, info: int, shndx: int) -> bytes:
        return struct.pack("<IBBHQQ", name_offset, info, 0, shndx, value, size)

    # Null symbol + 3 function symbols
    # STT_FUNC = 2, STB_GLOBAL = 1 => info = (1 << 4) | 2 = 0x12
    symtab = b""
    symtab += sym_entry(0, 0, 0, 0, 0)  # null entry
    symtab += sym_entry(1, ENTRY, 20, 0x12, 1)  # main
    symtab += sym_entry(6, ENTRY + 20, 16, 0x12, 1)  # _start
    symtab += sym_entry(13, ENTRY + 36, 28, 0x12, 1)  # vulnerable_func

    # Layout:
    # 0x00: ELF header (64 bytes)
    # 0x40: Program header (1 entry, 56 bytes) -> PT_LOAD
    # 0x78: Program header (1 entry, 56 bytes) -> PT_GNU_STACK (NX off)
    # Then section data aligned:
    # .text
    # .symtab
    # .strtab
    # .shstrtab
    # Section headers at the end

    ehdr_size = 64
    phdr_size = 56
    phdr_count = 2
    shdr_size = 64

    data_start = ehdr_size + phdr_size * phdr_count

    text_off = data_start
    text_sz = len(text_data)

    symtab_off = text_off + text_sz
    symtab_sz = len(symtab)

    strtab_off = symtab_off + symtab_sz
    strtab_sz = len(strtab)

    shstrtab_off = strtab_off + strtab_sz
    shstrtab_sz = len(shstrtab)

    # Section headers come after all data
    shdr_off = shstrtab_off + shstrtab_sz
    # Align to 8 bytes
    if shdr_off % 8:
        padding = 8 - (shdr_off % 8)
    else:
        padding = 0
    shdr_off += padding

    # Section headers: null, .text, .symtab, .strtab, .shstrtab
    shdr_count = 5
    shstrtab_idx = 4  # index of .shstrtab section header

    # Build ELF header
    ehdr = b""
    ehdr += EI_MAG
    ehdr += struct.pack("BBBBB", ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0)
    ehdr += b"\x00" * 7  # padding
    ehdr += struct.pack("<HHIQQQIHHHHHH",
        ET_EXEC,        # e_type
        EM_X86_64,      # e_machine
        EV_CURRENT,     # e_version
        ENTRY,          # e_entry
        ehdr_size,      # e_phoff
        shdr_off,       # e_shoff
        0,              # e_flags
        ehdr_size,      # e_ehsize
        phdr_size,      # e_phentsize
        phdr_count,     # e_phnum
        shdr_size,      # e_shentsize
        shdr_count,     # e_shnum
        shstrtab_idx,   # e_shstrndx
    )

    # Program headers
    PT_LOAD = 1
    PT_GNU_STACK = 0x6474E551
    PF_R = 4
    PF_W = 2
    PF_X = 1

    phdr1 = struct.pack("<IIQQQQQQ",
        PT_LOAD,        # p_type
        PF_R | PF_X,    # p_flags
        text_off,       # p_offset
        0x400000,       # p_vaddr
        0x400000,       # p_paddr
        text_sz,        # p_filesz
        text_sz,        # p_memsz
        0x1000,         # p_align
    )

    # GNU_STACK with PF_X set = NX disabled
    phdr2 = struct.pack("<IIQQQQQQ",
        PT_GNU_STACK,   # p_type
        PF_R | PF_W | PF_X,  # p_flags (X = NX disabled)
        0, 0, 0, 0, 0, 0x10,
    )

    # Section headers
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHF_ALLOC = 2
    SHF_EXECINSTR = 4

    def shdr(name_off: int, sh_type: int, flags: int, addr: int, offset: int,
             size: int, link: int = 0, info: int = 0, addralign: int = 1,
             entsize: int = 0) -> bytes:
        return struct.pack("<IIQQQQIIqq",
            name_off, sh_type, flags, addr, offset, size,
            link, info, addralign, entsize
        )

    shdrs = b""
    # 0: null
    shdrs += shdr(0, SHT_NULL, 0, 0, 0, 0)
    # 1: .text (name at offset 1 in shstrtab)
    shdrs += shdr(1, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0x401000, text_off, text_sz, addralign=16)
    # 2: .symtab (name at offset 17 in shstrtab)
    shdrs += shdr(17, SHT_SYMTAB, 0, 0, symtab_off, symtab_sz, link=3, info=1, addralign=8, entsize=24)
    # 3: .strtab (name at offset 25 in shstrtab)
    shdrs += shdr(25, SHT_STRTAB, 0, 0, strtab_off, strtab_sz)
    # 4: .shstrtab (name at offset 7 in shstrtab)
    shdrs += shdr(7, SHT_STRTAB, 0, 0, shstrtab_off, shstrtab_sz)

    # Assemble the full binary
    binary = bytearray()
    binary += ehdr
    binary += phdr1
    binary += phdr2
    binary += text_data
    binary += symtab
    binary += strtab
    binary += shstrtab
    binary += b"\x00" * padding
    binary += shdrs

    output.write_bytes(bytes(binary))


if __name__ == "__main__":
    out = Path(__file__).parent / "test_elf64"
    create_minimal_elf64(out)
    print(f"Created {out} ({out.stat().st_size} bytes)")
