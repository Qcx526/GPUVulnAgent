# -*- coding: utf-8 -*-
"""ELF / CUBIN structure reader with no external dependency.

A CUBIN is an ELF file with ``e_machine == 190`` (EM_CUDA) holding SASS for one or more
SM targets. ``cuobjdump`` and ``nvdisasm`` come from the toolchain manifest and do the
heavy lifting; this module answers the cheap structural questions - is it ELF, which
class, which machine, which sections, does it carry ``.nv.*`` CUDA artefacts - so the
agent can decide what to run before spawning a 50 MB disassembler.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Optional

EM_NAMES = {3: "EM_386", 8: "EM_MIPS", 20: "EM_PPC", 21: "EM_PPC64", 40: "EM_ARM",
            62: "EM_X86_64", 183: "EM_AARCH64", 185: "EM_RISCV", 190: "EM_CUDA",
            243: "EM_RISCV_ALT"}
TYPE_NAMES = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}


class ElfError(ValueError):
    """Not an ELF file, or a structure this reader refuses to guess about."""


def parse_header(data: bytes) -> dict:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file: missing magic")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise ElfError("unsupported ELF class %d" % ei_class)
    if ei_data not in (1, 2):
        raise ElfError("unsupported ELF data encoding %d" % ei_data)
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    header_size = 64 if is64 else 52
    if len(data) < header_size:
        raise ElfError("truncated ELF header")
    if is64:
        (e_type, e_machine, _version, e_entry, _phoff, e_shoff, _flags, _ehsize, _phentsize,
         _phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
            endian + "HHIQQQIHHHHHH", data[16:64])
    else:
        (e_type, e_machine, _version, e_entry, _phoff, e_shoff, _flags, _ehsize, _phentsize,
         _phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
            endian + "HHIIIIIHHHHHH", data[16:52])
    return {"class": "ELF64" if is64 else "ELF32",
            "endianness": "little" if ei_data == 1 else "big",
            "osabi": data[7], "type": TYPE_NAMES.get(e_type, "0x%X" % e_type),
            "machine": e_machine, "machine_name": EM_NAMES.get(e_machine, "EM_%d" % e_machine),
            "entry": e_entry, "section_header_offset": e_shoff,
            "section_count": e_shnum, "section_entry_size": e_shentsize,
            "shstrndx": e_shstrndx, "is_cuda": e_machine == 190}


def parse_sections(data: bytes, header: Optional[dict] = None) -> List[dict]:
    header = header or parse_header(data)
    offset = header["section_header_offset"]
    count = header["section_count"]
    entry_size = header["section_entry_size"] or (64 if header["class"] == "ELF64" else 40)
    if offset == 0 or count == 0:
        return []
    if offset + count * entry_size > len(data):
        raise ElfError("section header table runs past end of file")
    endian = "<" if header["endianness"] == "little" else ">"
    raw = []
    for index in range(count):
        base = offset + index * entry_size
        if header["class"] == "ELF64":
            name, stype, flags, addr, sh_offset, size = struct.unpack(
                endian + "IIQQQQ", data[base:base + 40])
        else:
            name, stype, flags, addr, sh_offset, size = struct.unpack(
                endian + "IIIIII", data[base:base + 24])
        raw.append({"index": index, "name_offset": name, "type": stype, "flags": flags,
                    "address": addr, "offset": sh_offset, "size": size})
    names: List[str] = []
    table_index = header["shstrndx"]
    if 0 < table_index < len(raw):
        table = raw[table_index]
        blob = data[table["offset"]:table["offset"] + table["size"]]
        for item in raw:
            start = item["name_offset"]
            end = blob.find(b"\x00", start) if start < len(blob) else -1
            names.append(blob[start:end].decode("utf-8", "replace") if end > start else "")
    for item, name in zip(raw, names):
        item["name"] = name
    return raw


def summarise(path: Path, *, limit: int = 60) -> dict:
    path = Path(path)
    if not path.is_file():
        raise ElfError("no such file: %s" % path)
    data = path.read_bytes()
    header = parse_header(data)
    sections = parse_sections(data, header)
    nv = [s for s in sections if s.get("name", "").startswith(".nv")]
    return {"path": str(path), "size": len(data), "header": header,
            "sections": [{"name": s.get("name", ""), "type": s["type"], "size": s["size"]}
                         for s in sections[:limit]],
            "section_count": len(sections),
            "cuda_sections": [{"name": s.get("name", ""), "size": s["size"]} for s in nv],
            "verdict": "cubin (EM_CUDA)" if header["is_cuda"] else
                       ("elf with cuda sections" if nv else "elf")}


def find_markers(data: bytes, needles: tuple = (b"nvJitLink", b"NVVM", b"fatbin",
                                                b"sm_", b".nv.info", b"cuobjdump")) -> Dict:
    """Cheap format sniffing for files whose header does not tell the whole story."""
    found = {}
    for needle in needles:
        index = data.find(needle)
        found[needle.decode("ascii", "replace")] = index
    return found
