#!/usr/bin/env python3

import struct

from elf import elf_image

ELF_MAGIC = b'\x7fELF'
MH_MAGIC_64 = 0xfeedfacf
FAT_MAGICS = (0xcafebabe, 0xcafebabf)
CPU_TYPE_ARM64 = 0x0100000c
LC_SEGMENT_64 = 0x19
CHAINED_FIXUPS = 0x80000034
DYLD_INFO_ONLY = 0x80000022
ZEROFILL = (0x1, 0xc, 0x12)
CHAIN_FORMATS = {
    1: (8, 11, 62, 0xFFFF),
    2: (4, 12, 63, 0xFFFFFF),
    6: (4, 12, 63, 0xFFFFFF),
    9: (8, 11, 62, 0xFFFF),
    12: (8, 12, 62, 0xFFFFFF),
}


class BadImage(Exception):
    pass


def unpack(fmt, data, offset, what='field'):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise BadImage(f'{what} out of bounds at 0x{offset:x}')
    return struct.unpack_from(fmt, data, offset)


def u16(data, offset, what='field'):
    return unpack('<H', data, offset, what)[0]


def u32(data, offset, what='field'):
    return unpack('<I', data, offset, what)[0]


def u64(data, offset, what='field'):
    return unpack('<Q', data, offset, what)[0]


def fat_slice(data):
    if len(data) < 8 or struct.unpack_from('>I', data, 0)[0] not in FAT_MAGICS:
        return 0, len(data)
    count = struct.unpack_from('>I', data, 4)[0]
    fallback = None
    for index in range(count):
        pos = 8 + index * 20
        if pos + 20 > len(data):
            break
        cputype, _subtype, offset, size = struct.unpack_from('>IIII', data, pos)
        if fallback is None:
            fallback = (offset, size)
        if cputype == CPU_TYPE_ARM64:
            return offset, size
    return fallback or (0, len(data))


def _macho_image(data):
    start, size = fat_slice(data)
    end = len(data) if not size else min(len(data), start + size)
    if start + 32 > end:
        raise BadImage('truncated mach header')
    magic = struct.unpack_from('<I', data, start)[0]
    if magic != MH_MAGIC_64:
        raise BadImage(f'unsupported mach magic 0x{magic:08x}')
    cputype = struct.unpack_from('<i', data, start + 4)[0]
    ncmds = u32(data, start + 16, 'mach header')
    cur = start + 32
    base = None
    sections = []
    for _ in range(ncmds):
        cmd = u32(data, cur, 'load command')
        cmdsize = u32(data, cur + 4, 'load command')
        if cmdsize < 8 or cur + cmdsize > end:
            raise BadImage(f'bad load command at 0x{cur:x}')
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            vmaddr, _vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, cur + 24)
            initprot = struct.unpack_from('<i', data, cur + 60)[0]
            if initprot & 0x4 and filesize:
                value = vmaddr - fileoff
                if base is None or value < base:
                    base = value
            count = u32(data, cur + 64, 'segment')
            for index in range(count):
                sect = cur + 72 + index * 80
                if sect + 80 > end:
                    raise BadImage(f'truncated section at 0x{sect:x}')
                sectname = data[sect:sect + 16].rstrip(b'\0').decode('utf-8', 'replace')
                segname = data[sect + 16:sect + 32].rstrip(b'\0').decode('utf-8', 'replace')
                addr, length, offset = struct.unpack_from('<QQI', data, sect + 32)
                flags = struct.unpack_from('<I', data, sect + 64)[0]
                if (flags & 0xFF) in ZEROFILL:
                    continue
                sections.append({'seg': segname, 'sect': sectname, 'addr': addr, 'size': length,
                                 'fileoff': start + offset, 'flags': flags,
                                 'exec': bool(flags & 0x80000000)})
        cur += cmdsize
    return start, cputype, base or 0, sections


def file_offset(sections, address):
    for section in sections:
        if section['addr'] <= address < section['addr'] + section['size']:
            return section['fileoff'] + address - section['addr']
    return None


def load_commands(data, start):
    cur = start + 32
    for _ in range(u32(data, start + 16, 'mach header')):
        cmd = u32(data, cur, 'load command')
        cmdsize = u32(data, cur + 4, 'load command')
        if cmdsize < 8:
            return
        yield cmd, cur, cmdsize
        cur += cmdsize


def segment_bases(data, start):
    bases = []
    for cmd, cur, size in load_commands(data, start):
        if cmd == LC_SEGMENT_64 and size >= 72:
            bases.append(struct.unpack_from('<Q', data, cur + 24)[0])
    return bases


def uleb(data, offset):
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise BadImage('uleb128 out of bounds')
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        if shift > 63:
            raise BadImage('uleb128 too long')


def walk_binds(blob, bases, slots):
    pos = 0
    name = ''
    address = 0
    while pos < len(blob):
        byte = blob[pos]
        pos += 1
        opcode = byte & 0xF0
        imm = byte & 0x0F
        if opcode == 0x00:
            return
        if opcode in (0x10, 0x30, 0x50):
            continue
        if opcode in (0x20, 0x60):
            _, pos = uleb(blob, pos)
        elif opcode == 0x40:
            end = blob.find(b'\0', pos)
            if end < 0:
                return
            name = blob[pos:end].decode('utf-8', 'replace').lstrip('_')
            pos = end + 1
        elif opcode == 0x70:
            seg_offset, pos = uleb(blob, pos)
            if imm >= len(bases):
                return
            address = bases[imm] + seg_offset
        elif opcode == 0x80:
            delta, pos = uleb(blob, pos)
            address += delta
        elif opcode == 0x90:
            slots[address] = name
        elif opcode == 0xA0:
            slots[address] = name
            delta, pos = uleb(blob, pos)
            address += delta
        elif opcode == 0xB0:
            slots[address] = name
            address += imm * 8
        elif opcode == 0xC0:
            count, pos = uleb(blob, pos)
            skip, pos = uleb(blob, pos)
            for _ in range(count):
                slots[address] = name
                address += skip
        else:
            return


def classic_slots(data, start):
    slots = {}
    bases = None
    for cmd, cur, size in load_commands(data, start):
        if cmd != DYLD_INFO_ONLY or size < 48:
            continue
        for field in (16, 24, 32):
            offset = u32(data, cur + field, 'dyld info')
            length = u32(data, cur + field + 4, 'dyld info')
            if not length:
                continue
            if bases is None:
                bases = segment_bases(data, start)
            walk_binds(data[start + offset:start + offset + length], bases, slots)
    return slots


def chained_slots(data, start, base, sections):
    blob = b''
    for cmd, cur, size in load_commands(data, start):
        if cmd == CHAINED_FIXUPS and size >= 16:
            offset = u32(data, cur + 8, 'chained fixups')
            length = u32(data, cur + 12, 'chained fixups')
            blob = data[start + offset:start + offset + length]
    if len(blob) < 28:
        return {}
    _version, starts_off, imports_off, symbols_off, count, fmt, _symbol_format = \
        struct.unpack_from('<7I', blob, 0)
    if fmt not in (1, 2, 3):
        return {}

    names = []
    for index in range(count):
        if fmt == 3:
            name_off = (u64(blob, imports_off + index * 8, 'imports') >> 32) & 0xFFFFFFFF
        elif fmt == 2:
            name_off = u32(blob, imports_off + index * 8, 'imports') >> 9
        else:
            name_off = u32(blob, imports_off + index * 4, 'imports') >> 9
        begin = symbols_off + name_off
        end = blob.find(b'\0', begin) if begin < len(blob) else -1
        name = blob[begin:end].decode('utf-8', 'replace') if end > begin else ''
        names.append(name.lstrip('_'))

    segment_count = u32(blob, starts_off, 'image starts')
    if starts_off + 4 + segment_count * 4 > len(blob):
        raise BadImage('image starts truncated')
    slots = {}
    for segment in range(segment_count):
        info_off = u32(blob, starts_off + 4 + segment * 4, 'image starts')
        if not info_off:
            continue
        pos = starts_off + info_off
        if pos + 22 > len(blob):
            raise BadImage('segment starts truncated')
        _size, page_size, pointer_format = struct.unpack_from('<IHH', blob, pos)
        seg_addr = u64(blob, pos + 8, 'segment starts')
        page_count = min(u16(blob, pos + 20, 'segment starts'), (len(blob) - pos - 22) // 2)
        if pointer_format not in CHAIN_FORMATS:
            continue
        stride, next_bits, bind_bit, ord_mask = CHAIN_FORMATS[pointer_format]
        for page in range(page_count):
            begin = u16(blob, pos + 22 + page * 2, 'page starts')
            if begin == 0xFFFF or begin & 0x8000:
                continue
            address = base + seg_addr + page * page_size + begin
            while True:
                off = file_offset(sections, address)
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
    return slots


def resolve_stubs(data, sections, slots):
    stubs = {}
    for section in sections:
        if section['sect'] not in ('__stubs', '__auth_stubs') or not section['size']:
            continue
        for pos in range(section['addr'], section['addr'] + section['size'] - 11, 12):
            off = section['fileoff'] + pos - section['addr']
            if off < 0 or off + 8 > len(data):
                break
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


def bind_names(data):
    start, _cputype, base, sections = macho_image(data)
    slots = chained_slots(data, start, base, sections)
    slots.update(classic_slots(data, start))
    return resolve_stubs(data, sections, slots)



def macho_image(data):
    if len(data) >= 4 and data[:4] == ELF_MAGIC:
        return elf_image(data)
    return _macho_image(data)


def is_elf(data):
    return len(data) >= 4 and data[:4] == ELF_MAGIC


def load_image(data):
    if is_elf(data):
        return elf_image(data)
    return macho_image(data)
