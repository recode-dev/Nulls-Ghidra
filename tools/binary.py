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


CHAINED_FIXUPS = 0x80000034
CHAIN_FORMATS = {
    1: (8, 11, 62, 0xFFFF),     
    2: (4, 12, 63, 0xFFFFFF),   
    6: (4, 12, 63, 0xFFFFFF),   
    9: (8, 11, 62, 0xFFFF),     
    12: (8, 12, 62, 0xFFFFFF),  
}


def slice_offset(data):
    if len(data) < 8:
        return 0
    if struct.unpack_from('>I', data, 0)[0] in FAT_MAGICS:
        n = struct.unpack_from('>I', data, 4)[0]
        if n:
            return struct.unpack_from('>I', data, 16)[0]
    return 0


def bind_names(path):
    """{stub address: import name} from LC_DYLD_CHAINED_FIXUPS, version independent."""
    with open(path, 'rb') as f:
        data = f.read()
    base = slice_offset(data)
    if len(data) < base + 32:
        return {}
    ncmds = struct.unpack_from('<I', data, base + 16)[0]
    cur = base + 32
    blob = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, cur)
        if cmd == CHAINED_FIXUPS and size >= 16:
            off, length = struct.unpack_from('<II', data, cur + 8)
            blob = data[base + off:base + off + length]
        if size <= 0:
            break
        cur += size
    if not blob or len(blob) < 28:
        return {}
    _ver, starts_off, imports_off, symbols_off, count, fmt, _sfmt = \
        struct.unpack_from('<7I', blob, 0)
    if fmt not in (1, 2, 3):
        return {}
    names = []
    for i in range(count):
        if fmt == 3:
            raw = struct.unpack_from('<Q', blob, imports_off + i * 8)[0]
            name_off = (raw >> 32) & 0xFFFFFFFF
        else:
            raw = struct.unpack_from('<I', blob, imports_off + i * (8 if fmt == 2 else 4))[0]
            name_off = raw >> 9
        end = blob.find(b'\0', symbols_off + name_off)
        name = blob[symbols_off + name_off:end if end > 0 else None].decode('utf-8', 'replace')
        names.append(name.lstrip('_'))

    image_base = macho_base(data) or 0
    sections = macho_sections(data)
    def fileoff_of(vmaddr):
        for s in sections:
            if s['addr'] <= vmaddr < s['addr'] + s['size']:
                return s['fileoff'] + vmaddr - s['addr']
        return None

    seg_count = struct.unpack_from('<I', blob, starts_off)[0]
    slots = {}
    for seg in range(seg_count):
        info_off = struct.unpack_from('<I', blob, starts_off + 4 + seg * 4)[0]
        if not info_off:
            continue
        p = starts_off + info_off
        _size, page_size, pointer_format = struct.unpack_from('<IHH', blob, p)
        seg_addr = struct.unpack_from('<Q', blob, p + 8)[0]
        page_count = struct.unpack_from('<H', blob, p + 20)[0]
        if pointer_format not in CHAIN_FORMATS:
            continue
        stride, next_bits, bind_bit, ord_mask = CHAIN_FORMATS[pointer_format]
        for page in range(page_count):
            start = struct.unpack_from('<H', blob, p + 22 + page * 2)[0]
            if start == 0xFFFF or start & 0x8000:
                continue
            address = image_base + seg_addr + page * page_size + start
            while True:
                off = fileoff_of(address)
                if off is None or off + 8 > len(data):
                    break
                pointer = struct.unpack_from('<Q', data, off)[0]
                if (pointer >> bind_bit) & 1:
                    ordinal = pointer & ord_mask
                    if ordinal < len(names):
                        slots[address] = names[ordinal]
                step = (pointer >> 51) & ((1 << next_bits) - 1)
                if not step:
                    break
                address += step * stride

    stubs = {}
    for section in sections:
        if section['sect'] not in ('__stubs', '__auth_stubs') or not section['size']:
            continue
        for pos in range(section['addr'], section['addr'] + section['size'] - 11, 12):
            off = section['fileoff'] + pos - section['addr']
            adrp, ldr = struct.unpack_from('<II', data, off)
            if (adrp & 0x9F000000) != 0x90000000 or (ldr & 0xFFC00000) != 0xF9400000:
                continue
            rd = adrp & 0x1F
            imm = (((adrp >> 5) & 0x7FFFF) << 2) | ((adrp >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            page = (pos & ~0xFFF) + (imm << 12)
            slot = page + ((ldr >> 10) & 0xFFF) * 8
            if slot in slots:
                stubs[pos] = slots[slot]
    return stubs


if __name__ == '__main__':
    import sys
    import json as _json
    if len(sys.argv) == 3 and sys.argv[1] == '--symbols':
        print(_json.dumps({name: addr for addr, name in bind_names(sys.argv[2]).items()}))
