#!/usr/bin/env python3
"""Print the PT_LOAD segment identity of an ELF shared object.

One line per PT_LOAD segment:
    <p_offset> <p_vaddr> <p_filesz> <p_memsz> <p_flags> <sha256(segment bytes)>

Used by deps/wallet-core/tools/verify-android-rng.sh to prove a stripped
packaging copy of libwallet_core.so executes exactly the bytes of the
verified unstripped artifact. Stripping removes only section-table data,
but llvm-strip also rewrites the ELF header's section-header bookkeeping
(e_shoff / e_shnum / e_shstrndx) to zero; those header bytes live inside
LOAD segment 0, so the hash is computed with the three fields normalized
to zero. Section-header fields are not consumed by the runtime loader —
the dynamic loader uses program headers only — so normalizing them does
not weaken the proof that the shipped binary executes identical code and
data. Every other byte of every LOAD segment must match exactly.
"""
import hashlib
import struct
import sys


PT_LOAD = 1
PN_XNUM = 0xFFFF


def unpack_from(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("truncated ELF structure")
    return struct.unpack_from(fmt, data, offset)


def elf_layout(data):
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    byte_order = data[5]
    if byte_order == 1:
        endian = "<"
    elif byte_order == 2:
        endian = ">"
    else:
        raise ValueError("unsupported ELF byte order")

    if elf_class == 2:
        header = unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        phoff, shoff = header[4], header[5]
        phentsize, phnum = header[8], header[9]
        shentsize = header[10]
        ph_fmt = endian + "IIQQQQQQ"
        sh_info_offset = 44
    elif elf_class == 1:
        header = unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        phoff, shoff = header[4], header[5]
        phentsize, phnum = header[8], header[9]
        shentsize = header[10]
        ph_fmt = endian + "IIIIIIII"
        sh_info_offset = 28
    else:
        raise ValueError("unsupported ELF class")

    expected_phentsize = struct.calcsize(ph_fmt)
    if phentsize < expected_phentsize:
        raise ValueError("invalid ELF program-header size")
    if phnum == PN_XNUM:
        if shoff == 0 or shentsize < sh_info_offset + 4:
            raise ValueError("missing extended ELF program-header count")
        (phnum,) = unpack_from(endian + "I", data, shoff + sh_info_offset)
    return elf_class, phoff, phentsize, phnum, ph_fmt


def segment_digest(data, elf_class, seg_offset, seg_size):
    """SHA-256 of one PT_LOAD segment's file bytes with the ELF header's
    section-header bookkeeping fields (e_shoff, e_shnum, e_shstrndx)
    normalized to zero. Only applies when the ELF header lies inside the
    segment (it always does for segment 0 of a shared object)."""
    end = seg_offset + seg_size
    if seg_offset < 0 or end > len(data):
        raise ValueError("PT_LOAD segment extends past end of file")
    segment = bytearray(data[seg_offset:end])
    if seg_offset == 0:
        if elf_class == 2:
            if len(segment) < 64:
                raise ValueError("truncated ELF64 header")
            segment[0x28:0x30] = b"\x00" * 8   # e_shoff
            segment[0x3C:0x3E] = b"\x00" * 2   # e_shnum
            segment[0x3E:0x40] = b"\x00" * 2   # e_shstrndx
        else:
            if len(segment) < 52:
                raise ValueError("truncated ELF32 header")
            segment[0x20:0x24] = b"\x00" * 4   # e_shoff
            segment[0x30:0x32] = b"\x00" * 2   # e_shnum
            segment[0x32:0x34] = b"\x00" * 2   # e_shstrndx
    return hashlib.sha256(segment).hexdigest()


def main(path):
    with open(path, "rb") as elf_file:
        data = elf_file.read()
    elf_class, phoff, phentsize, phnum, ph_fmt = elf_layout(data)
    load_segments = 0
    for index in range(phnum):
        fields = unpack_from(ph_fmt, data, phoff + index * phentsize)
        if elf_class == 2:
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = fields
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = fields
        if p_type != PT_LOAD:
            continue
        digest = segment_digest(data, elf_class, p_offset, p_filesz)
        print(p_offset, p_vaddr, p_filesz, p_memsz, p_flags, digest)
        load_segments += 1
    if load_segments == 0:
        raise ValueError("ELF contains no PT_LOAD segments")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <elf-file>")
    try:
        main(sys.argv[1])
    except (OSError, ValueError, struct.error) as error:
        sys.exit(f"failed to read ELF LOAD segments: {error}")
