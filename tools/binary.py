#!/usr/bin/env python3
import struct


def macho_base(data, offset=0):
    if len(data) < offset + 32:
        return None
    magic = struct.unpack_from('<I', data, offset)[0]
    if magic in (0xcafebabe, 0xcafebabf) or struct.unpack_from('>I', data, offset)[0] in (0xcafebabe, 0xcafebabf):
        n = struct.unpack_from('>I', data, offset + 4)[0]
        best = None
        for i in range(n):
            arch_off = struct.unpack_from('>I', data, offset + 8 + i * 20 + 8)[0]
            candidate = macho_base(data, arch_off)
            if candidate is not None and (best is None or candidate < best):
                best = candidate
        return best
    if magic != 0xfeedfacf:
        return None
    ncmds = struct.unpack_from('<I', data, offset + 16)[0]
    cur = offset + 32
    base = None
    for _ in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, size = struct.unpack_from('<II', data, cur)
        if cmd == 0x19 and size >= 72 and cur + 68 <= len(data):
            vmaddr, _vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, cur + 24)
            initprot = struct.unpack_from('<i', data, cur + 64)[0]
            if (initprot & 0x4) and filesize > 0:
                value = vmaddr - fileoff
                if base is None or value < base:
                    base = value
        if size <= 0:
            break
        cur += size
    return base


def elf_base(data):
    if data[:4] != b'\x7fELF':
        return None
    is64 = data[4] == 2
    try:
        if is64:
            phoff = struct.unpack_from('<Q', data, 0x20)[0]
            phentsize = struct.unpack_from('<H', data, 0x36)[0]
            phnum = struct.unpack_from('<H', data, 0x38)[0]
        else:
            phoff = struct.unpack_from('<I', data, 0x1c)[0]
            phentsize = struct.unpack_from('<H', data, 0x2a)[0]
            phnum = struct.unpack_from('<H', data, 0x2c)[0]
    except struct.error:
        return None
    base = None
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + phentsize > len(data):
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr = struct.unpack_from('<IIQQ', data, off)
        else:
            p_type, p_offset, p_vaddr, p_flags = struct.unpack_from('<IIII', data, off)
        if p_type == 1 and (p_flags & 0x1):
            value = p_vaddr - p_offset
            if base is None or value < base:
                base = value
    return base


def detect_base(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(1 << 20)
    except OSError:
        return 0
    base = elf_base(head) if head[:4] == b'\x7fELF' else macho_base(head)
    return base if base else 0
