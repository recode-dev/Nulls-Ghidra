#!/usr/bin/env python3
import struct

MH_MAGIC_64 = 0xfeedfacf
FAT_MAGICS = (0xcafebabe, 0xcafebabf)
LC_SEGMENT_64 = 0x19


def macho_base(data, offset=0):
    if len(data) < offset + 32:
        return None
    magic = struct.unpack_from('<I', data, offset)[0]
    if magic in FAT_MAGICS or struct.unpack_from('>I', data, offset)[0] in FAT_MAGICS:
        n = struct.unpack_from('>I', data, offset + 4)[0]
        best = None
        for i in range(n):
            arch_off = struct.unpack_from('>I', data, offset + 8 + i * 20 + 8)[0]
            candidate = macho_base(data, arch_off)
            if candidate is not None and (best is None or candidate < best):
                best = candidate
        return best
    if magic != MH_MAGIC_64:
        return None
    ncmds = struct.unpack_from('<I', data, offset + 16)[0]
    cur = offset + 32
    base = None
    for _ in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, size = struct.unpack_from('<II', data, cur)
        if cmd == LC_SEGMENT_64 and size >= 72 and cur + 68 <= len(data):
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


def detect_base(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(1 << 20)
    except OSError:
        return 0
    base = macho_base(head)
    return base if base else 0


def macho_sections(data, offset=0):
    if len(data) < offset + 32:
        return []
    magic = struct.unpack_from('<I', data, offset)[0]
    if magic in FAT_MAGICS or struct.unpack_from('>I', data, offset)[0] in FAT_MAGICS:
        n = struct.unpack_from('>I', data, offset + 4)[0]
        for i in range(n):
            arch_off = struct.unpack_from('>I', data, offset + 8 + i * 20 + 8)[0]
            found = macho_sections(data, arch_off)
            if found:
                for entry in found:
                    entry['fileoff'] += arch_off
                return found
        return []
    if magic != MH_MAGIC_64:
        return []
    ncmds = struct.unpack_from('<I', data, offset + 16)[0]
    cur = offset + 32
    out = []
    for _ in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, size = struct.unpack_from('<II', data, cur)
        if cmd == LC_SEGMENT_64 and size >= 72:
            nsects = struct.unpack_from('<I', data, cur + 64)[0]
            base = cur + 72
            for i in range(nsects):
                sect = base + i * 80
                if sect + 80 > len(data):
                    break
                sectname = struct.unpack_from('<16s', data, sect)[0].rstrip(b'\0').decode('utf-8', 'replace')
                segname = struct.unpack_from('<16s', data, sect + 16)[0].rstrip(b'\0').decode('utf-8', 'replace')
                addr, sz, fileoff = struct.unpack_from('<QQI', data, sect + 32)
                flags = struct.unpack_from('<I', data, sect + 64)[0]
                out.append({'seg': segname, 'sect': sectname, 'addr': addr, 'size': sz,
                            'fileoff': fileoff, 'flags': flags})
        if size <= 0:
            break
        cur += size
    return out
