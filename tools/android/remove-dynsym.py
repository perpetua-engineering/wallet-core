#!/usr/bin/env python3
"""Remove a named dynamic symbol import from a 32/64-bit ELF shared object.

Used by deps/wallet-core/tools/verify-android-rng.sh to build a negative fixture with a required dynamic import renamed away, proving the
verifier rejects artifacts whose kernel-CSPRNG dependency is gone.

The rename is done in place against .dynstr (padded to the exact original
byte length) so no ELF offsets move; the resulting file is still a valid
ELF whose dynamic table simply no longer imports the target symbol.
"""
import sys, struct

def main(path, sym_name):
    data = bytearray(open(path, "rb").read())
    if data[:4] != b"\x7fELF":
        sys.exit("not an ELF")
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    def u16(o): return struct.unpack_from(endian+"H", data, o)[0]
    def u32(o): return struct.unpack_from(endian+"I", data, o)[0]
    def u64(o): return struct.unpack_from(endian+"Q", data, o)[0]

    if is64:
        e_shoff = u64(0x28)
        e_shentsize = u16(0x3A)
        e_shnum = u16(0x3C)
        e_shstrndx = u16(0x3E)
        shoff_fields = lambda b: {  # noqa: E731
            "name": u32(b), "type": u32(b+4), "offset": u64(b+0x18),
            "size": u64(b+0x20), "link": u32(b+0x28), "entsize": u64(b+0x38),
        }
    else:
        e_shoff = u32(0x20)
        e_shentsize = u16(0x2E)
        e_shnum = u16(0x30)
        e_shstrndx = u16(0x32)
        shoff_fields = lambda b: {  # noqa: E731
            "name": u32(b), "type": u32(b+4), "offset": u32(b+0x10),
            "size": u32(b+0x14), "link": u32(b+0x18), "entsize": u32(b+0x24),
        }
    if e_shnum == 0:
        # SHN_UNDEF escape: real count lives in sh_size of section header 0.
        e_shnum = u64(e_shoff + 0x20) if is64 else u32(e_shoff + 0x14)
    if e_shstrndx == 0xFFFF:
        # SHN_XINDEX escape: real index lives in sh_link of section header 0.
        e_shstrndx = u32(e_shoff + 0x28) if is64 else u32(e_shoff + 0x18)

    sh = []
    for i in range(e_shnum):
        base = e_shoff + i*e_shentsize
        sh.append(shoff_fields(base))

    shstr = sh[e_shstrndx]
    def sec_name(s):
        o = shstr["offset"] + s["name"]
        e = data.index(b"\x00", o)
        return data[o:e].decode()

    dynsym = next(s for s in sh if sec_name(s) == ".dynsym")
    dynstr = sh[dynsym["link"]]
    assert sec_name(dynstr) == ".dynstr"

    # Walk .dynstr and find offsets of the target name
    target_off = None
    o = dynstr["offset"]; end = o + dynstr["size"]
    while o < end:
        e = data.index(b"\x00", o)
        if data[o:e].decode() == sym_name:
            target_off = o - dynstr["offset"]
            break
        o = e + 1
    if target_off is None:
        sys.exit(f"symbol name {sym_name} not found in .dynstr")

    # Rename the string in .dynstr to something that can never be a real
    # import, and update any dynsym entry referencing it to reference it under
    # the new name. The verifier rejects because the target symbol no longer
    # appears as an undefined dynamic symbol.
    new_name = b"x" * len(sym_name)
    abs_off = dynstr["offset"] + target_off
    old_len = len(sym_name)
    # Overwrite the name in place, padded to the exact original length so no
    # offsets shift.
    padded = new_name
    assert len(padded) == old_len
    data[abs_off:abs_off+old_len] = padded
    open(path, "wb").write(bytes(data))
    print(f"renamed dynsym string '{sym_name}' -> '{padded.decode()}' in {path}")

main(sys.argv[1], sys.argv[2])
