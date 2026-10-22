#!/usr/bin/env python3
"""Binary-level reference graph for ARM32 (ELF) and ARM64 (Mach-O) dumps.

The decompiler driven index loses edges whenever a function body fails to
decompile (size 0 chars entries) and it resolves calls through short names that
collide across classes.  This tool reads the machine code instead, so the call
graph and the string references stay complete.

Outputs, written next to the index:
  callgraph_bin.json   {caller_rva: {callee_rva: count}}
  strings_xref_bin.json {string: [caller_rva, ...]}
"""

import argparse
import array
import bisect
import json
import os
import struct
import sys

from binary import CPU_TYPE_ARM64, load_image
from elf import EM_AARCH64, elf_relocations

R_ARM_ABS32 = 2
MAX_DEREF = 3


def parse_args():
    p = argparse.ArgumentParser(description='Extract call edges and string xrefs from machine code')
    p.add_argument('--bin', required=True, help='binary the dump was produced from')
    p.add_argument('--index', required=True, help='index directory holding functions.json')
    p.add_argument('--out', default='', help='output directory, defaults to --index')
    p.add_argument('--functions', default='functions.json', help='function index file name')
    p.add_argument('--strings', default='strings.json', help='string index file name')
    p.add_argument('--no-strings', action='store_true', help='skip string reference recovery')
    p.add_argument('--tail-calls', action='store_true', help='record unconditional B as an edge')
    return p.parse_args()


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def to_int(value):
    if isinstance(value, int):
        return value
    return int(value, 16) if isinstance(value, str) else None


def exec_sections(sections):
    found = [s for s in sections if s.get('exec') and s['size']]
    return found


def read_word(data, sections, address, width):
    """Return the integer stored at a virtual address, or None."""
    fmt = '<I' if width == 4 else '<Q'
    for section in sections:
        if section['addr'] <= address < section['addr'] + section['size']:
            offset = section['fileoff'] + address - section['addr']
            if 0 <= offset and offset + width <= len(data):
                return struct.unpack_from(fmt, data, offset)[0]
            return None
    return None


def sign(value, bits):
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def decode_arm64(blob, base):
    """Yield (site_rva, callee_rva, kind) for BL and B inside a section blob."""
    limit = len(blob) - 3
    for pos in range(0, limit, 4):
        word = struct.unpack_from('<I', blob, pos)[0]
        top = word >> 26
        if top == 0x25:
            offset = sign(word & 0x03FFFFFF, 26) * 4
        elif top == 0x05:
            offset = sign(word & 0x03FFFFFF, 26) * 4
        else:
            continue
        address = base + pos
        target = address + offset
        kind = 'bl' if top == 0x25 else 'b'
        yield pos, target - base, kind


def decode_arm32(blob, base):
    """Yield (site_rva, callee_rva, kind) for BL and BLX-immediate."""
    limit = len(blob) - 3
    for pos in range(0, limit, 4):
        word = struct.unpack_from('<I', blob, pos)[0]
        cond = word >> 28
        if cond == 0xF:
            continue
        address = base + pos
        if (word >> 24) & 0xF == 0xB:
            target = (address + 8) + sign(word & 0x00FFFFFF, 24) * 4
            yield pos, target - base, 'bl'
        elif (word >> 25) & 0x7 == 0x5:
            high = (word >> 24) & 1
            target = ((address + 8) & ~3) + sign(word & 0x00FFFFFF, 24) * 4 + high * 4
            yield pos, target - base, 'bl'


def arm64_string_targets(data, sections, blob, text_va, addr_to_string, pointer_width):
    """Resolve ADRP/ADD and ADRP/LDR pairs to string addresses.

    blob is scanned at virtual address text_va; sites are returned as VAs.
    """
    base = text_va
    cfstring = {}
    lookup = dict(addr_to_string)
    for section in sections:
        if section['sect'] != '__cfstring' or not section['size']:
            continue
        for struct_addr in range(section['addr'], section['addr'] + section['size'] - 31, 32):
            offset = section['fileoff'] + struct_addr - section['addr'] + 16
            if offset + 8 > len(data):
                break
            value = struct.unpack_from('<Q', data, offset)[0]
            text = lookup.get(value)
            if text:
                cfstring[struct_addr] = text
    merged = dict(lookup)
    merged.update(cfstring)
    starts = sorted(merged)

    def known(address):
        if address is None:
            return None
        if address in merged:
            return merged[address]
        index = bisect.bisect_right(starts, address) - 1
        if index < 0:
            return None
        origin = starts[index]
        text = merged.get(origin)
        if not text:
            return None
        if address - origin < len(text) + 1:
            return text
        return None

    result = {}
    limit = len(blob) - 3
    for pos in range(0, limit, 4):
        word = struct.unpack_from('<I', blob, pos)[0]
        address = base + pos
        if (word & 0x9F000000) != 0x90000000:
            continue
        register = word & 0x1F
        imm = ((word >> 29) & 0x3) | (((word >> 5) & 0x7FFFF) << 2)
        page = ((address & ~0xFFF) + (sign(imm, 21) << 12)) & 0xFFFFFFFFFFFFFFFF
        target = None
        for probe in range(pos + 4, min(pos + 128, limit), 4):
            second = struct.unpack_from('<I', blob, probe)[0]
            if (second & 0xFFC00000) in (0xF9400000, 0xF9000000) and ((second >> 5) & 0x1F) == register:
                slot = page + ((second >> 10) & 0xFFF) * 8
                value = read_word(data, sections, slot, pointer_width)
                if value is None:
                    continue
                target = value
                if known(target) is None:
                    inner = read_word(data, sections, value + 16, pointer_width)
                    if known(inner) is not None:
                        target = inner
                break
            if (second >> 24) & 0x3F in (0x21, 0x22) and ((second >> 5) & 0x1F) == register:
                lo12 = (second >> 5) & 0xFFF
                if (second >> 22) & 0x1:
                    lo12 <<= 12
                target = page + lo12
                break
            if (second & 0xFFC00000) == 0x91000000 and ((second >> 5) & 0x1F) == register:
                target = page + ((second >> 10) & 0xFFF)
                break
        if target is None:
            continue
        text = known(target)
        if text is None:
            continue
        result.setdefault(text, set()).add(base + pos)
    return result


def arm32_abs_relocs(data, sections):
    """Slots filled by the loader instead of the file (R_ARM_ABS32)."""
    filled = {}
    for entry in elf_relocations(data, sections):
        if entry['type'] != R_ARM_ABS32:
            continue
        value = entry['addend'] or read_word(data, sections, entry['offset'], 4)
        if value:
            filled[entry['offset']] = value
    return filled


def arm32_string_targets(blob, text_va, addr_to_string, filled):
    """Literal pools hold the absolute address of every string a function uses.

    Reading the pool slots is more reliable than decoding LDR literal encodings:
    ARM spreads the PC offset over P/U/W/B bits that differ between assemblers,
    while the pool content itself is unambiguous.  A slot owns the function whose
    byte range contains it, which is how the pool is placed by the compiler.
    """
    lookup = dict(addr_to_string)
    starts = sorted(lookup)
    low, high = (starts[0], starts[-1]) if starts else (0, 0)

    def known(address):
        if address is None:
            return None
        text = lookup.get(address)
        if text:
            return text
        if not (low <= address <= high):
            return None
        index = bisect.bisect_right(starts, address) - 1
        if index < 0:
            return None
        origin = starts[index]
        text = lookup[origin]
        return text if address - origin < len(text) + 1 else None

    result = {}
    words = array.array('I')
    words.frombytes(bytes(blob[:len(blob) & ~3]))
    for index, value in enumerate(words):
        if not value:
            continue
        text = lookup.get(value) or (known(value) if low <= value <= high else None)
        if text:
            result.setdefault(text, set()).add(text_va + index * 4)
    for slot, value in filled.items():
        if not (text_va <= slot < text_va + len(words) * 4):
            continue
        text = known(value)
        if text:
            result.setdefault(text, set()).add(slot)
    return result


def main():
    args = parse_args()
    out = args.out or args.index
    with open(args.bin, 'rb') as handle:
        data = handle.read()
    start, machine, base, sections = load_image(data)
    if machine in (CPU_TYPE_ARM64, EM_AARCH64):
        arch, pointer_width = 'arm64', 8
        decode = decode_arm64
    elif machine == 40:
        arch, pointer_width = 'arm32', 4
        decode = decode_arm32
    else:
        raise SystemExit(f'[-] unsupported machine 0x{machine:x}')

    functions = load_json(os.path.join(args.index, args.functions), {})
    if not functions:
        raise SystemExit(f'[-] {args.functions} not found in {args.index}')
    order = sorted((entry.get('offset') or to_int(key), key) for key, entry in functions.items()
                   if entry.get('size_bytes'))
    starts = [item[0] for item in order]

    def owner(rva):
        index = bisect.bisect_right(starts, rva) - 1
        if index < 0:
            return None
        origin, key = order[index]
        size = functions[key].get('size_bytes') or 0
        return key if origin <= rva < origin + size else None

    code = exec_sections(sections)
    if not code:
        raise SystemExit('[-] no executable section')

    edges = {}
    sites = {}
    for section in code:
        blob = data[section['fileoff']:section['fileoff'] + section['size']]
        section_base = section['addr'] - base
        for pos, target, kind in (decode(blob, section_base)):
            if kind == 'b' and not args.tail_calls:
                continue
            caller = owner(section_base + pos)
            callee = owner(target)
            if caller is None or callee is None or caller == callee:
                continue
            edges.setdefault(caller, {})
            edges[caller][callee] = edges[caller].get(callee, 0) + 1
            sites.setdefault(callee, set()).add(caller)

    strings_xref = {}
    if not args.no_strings:
        strings = load_json(os.path.join(args.index, args.strings), {})
        addr_to_string = {}
        for text, entry in strings.items():
            address = entry.get('address') if isinstance(entry, dict) else entry
            address = to_int(address)
            if address is None:
                continue
            addr_to_string.setdefault(address, text)
        merged = {}
        filled = arm32_abs_relocs(data, sections) if arch == 'arm32' else {}
        for section in code:
            blob = data[section['fileoff']:section['fileoff'] + section['size']]
            if arch == 'arm64':
                found = arm64_string_targets(data, sections, blob, section['addr'], addr_to_string,
                                             pointer_width)
            else:
                found = arm32_string_targets(blob, section['addr'], addr_to_string, filled)
            for text, positions in found.items():
                owners = {owner(pos - base) for pos in positions}
                owners.discard(None)
                merged.setdefault(text, set()).update(owners)
        strings_xref = {text: sorted(owners) for text, owners in merged.items()}

    os.makedirs(out, exist_ok=True)
    for name, payload in (('callgraph_bin.json', edges), ('strings_xref_bin.json', strings_xref)):
        with open(os.path.join(out, name), 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, ensure_ascii=False)
    counted = sum(len(v) for v in edges.values())
    print(f'[+] {arch} sites={len(sites)} callers={len(edges)} distinct_edges={counted} '
          f'strings_xref={len(strings_xref)} -> {out}')


if __name__ == '__main__':
    sys.exit(main())
