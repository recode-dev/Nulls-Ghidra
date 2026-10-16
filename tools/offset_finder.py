#!/usr/bin/env python3
import argparse
import json
import os
import re
import struct
import urllib.request

MH_MAGIC_32 = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
FAT_MAGICS = (0xcafebabe, 0xcafebabf)
ELF_MAGIC = 0x464c457f
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
FIELD_LIMIT = 0x20000
TIGHT_SPAN = 0x20
RUN_STEP = 8
RUN_FIELD_STEP = 4
NAME_PATTERNS = (
    re.compile(r'#define\s+([A-Za-z0-9_:]+)\s+(0x[0-9a-fA-F]+)'),
    re.compile(r'["\']([A-Za-z0-9_:]+)["\']\s*:\s*["\']?(0x[0-9a-fA-F]+)'),
    re.compile(r'([A-Za-z0-9_:]+)\s*[=:]\s*(?:ptr\()?\s*["\']?(0x[0-9a-fA-F]+)'),
)


def parse_args():
    p = argparse.ArgumentParser(description='Resolve named offsets of any game from a binary plus optional dump indexes, validating every result against the binary')
    p.add_argument('--names', required=True, help='name -> value map (URL or path), or a single bare name')
    p.add_argument('--binary', default='', help='target binary (Mach-O or ELF)')
    p.add_argument('--index_dir', default='', help='dump index directory')
    p.add_argument('--code', default='', help='decompiled dump providing accessor evidence')
    p.add_argument('--reference_binary', default='', help='binary of the build the reference map belongs to; enables signature transfer')
    p.add_argument('--structural', action='store_true', help='order/size-rank alignment for code entries with class anchors')
    p.add_argument('--selftest', action='store_true', help='prove the signature masking survives address and immediate rewriting')
    p.add_argument('--filter', default='', help='restrict to names containing this substring')
    p.add_argument('--out', default='', help='resolved map output (JSON, validated entries only)')
    p.add_argument('--report', default='', help='markdown report output')
    return p.parse_args()


def read_text(src):
    if src.startswith(('http://', 'https://')):
        req = urllib.request.Request(src, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    if os.path.exists(src):
        with open(src, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return src


def read_json(path, default):
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return json.load(f)
    return default


def parse_names(text):
    found = {}
    for pat in NAME_PATTERNS:
        for m in pat.finditer(text):
            found.setdefault(m.group(1), int(m.group(2), 16))
    if not found:
        token = text.strip()
        if token and re.fullmatch(r'[A-Za-z0-9_:.\-]+', token):
            return {token: 0}
    return found


def class_of(name):
    if '__' in name:
        return name.split('__', 1)[0]
    if '::' in name:
        return name.split('::', 1)[0]
    return name.rsplit('_', 1)[0]


class Binary:
    def __init__(self, path):
        self.path = path
        self.data = b''
        self.arch = 'unknown'
        self.bits = 0
        self.image_base = 0
        self.segments = []
        self.symbols = []
        if path and os.path.exists(path):
            with open(path, 'rb') as f:
                self.data = f.read()
            self._parse()

    def _parse(self):
        if len(self.data) < 32:
            return
        magic = struct.unpack('<I', self.data[:4])[0]
        if magic == ELF_MAGIC:
            self._parse_elf()
        elif magic in FAT_MAGICS:
            count = struct.unpack('>I', self.data[4:8])[0]
            offset = struct.unpack('>I', self.data[8 + 8:8 + 12])[0]
            for i in range(count):
                cputype, _, off, _, _ = struct.unpack('>IIIII', self.data[8 + i * 20:28 + i * 20])
                if cputype == 0x0100000c:
                    offset = off
            self._parse_macho(offset)
        else:
            self._parse_macho(0)

    def _parse_macho(self, offset):
        magic, cputype, _, _, ncmds, _, _, _ = struct.unpack('<IiiIIIII', self.data[offset:offset + 32])
        if magic not in (MH_MAGIC_32, MH_MAGIC_64):
            return
        self.bits = 32 if magic == MH_MAGIC_32 else 64
        self.arch = {0x0100000c: 'arm64', 0x01000007: 'x86_64', 0xc: 'arm', 0x7: 'i386'}.get(cputype, f'cpu{cputype:#x}')
        ptr = offset + 32
        symtab = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack('<II', self.data[ptr:ptr + 8])
            if cmd in (LC_SEGMENT, LC_SEGMENT_64):
                if self.bits == 64:
                    name = self.data[ptr + 8:ptr + 24].split(b'\x00')[0].decode('utf-8', 'ignore')
                    vaddr, size, fileoff, filesize = struct.unpack('<QQQQ', self.data[ptr + 24:ptr + 56])
                else:
                    name = self.data[ptr + 8:ptr + 24].split(b'\x00')[0].decode('utf-8', 'ignore')
                    vaddr, size, fileoff, filesize = struct.unpack('<IIII', self.data[ptr + 24:ptr + 40])
                self.segments.append({'name': name, 'vaddr': vaddr, 'size': size, 'fileoff': fileoff, 'filesize': filesize})
                if name == '__TEXT' and not self.image_base:
                    self.image_base = vaddr
            elif cmd == LC_SYMTAB:
                symtab = struct.unpack('<IIII', self.data[ptr + 8:ptr + 24])
            ptr += cmdsize
        if symtab:
            self.symbols = self._read_macho_symtab(symtab)

    def _read_macho_symtab(self, symtab):
        symoff, nsyms, stroff, strsize = symtab
        strtab = self.data[stroff:stroff + strsize]
        entry_size = 16 if self.bits == 64 else 12
        out = []
        for i in range(nsyms):
            entry = self.data[symoff + i * entry_size:symoff + i * entry_size + entry_size]
            if len(entry) < entry_size:
                break
            if self.bits == 64:
                n_strx, n_type, n_sect, _, n_value = struct.unpack('<IBBHQ', entry)
            else:
                n_strx, n_value, n_type, n_sect, _ = struct.unpack('<IIIBB', entry)
            if not n_strx or n_strx >= len(strtab):
                continue
            end = strtab.find(b'\x00', n_strx)
            out.append({'name': strtab[n_strx:end].decode('utf-8', 'ignore'), 'value': n_value, 'sect': n_sect})
        return out

    def _parse_elf(self):
        self.bits = 64 if self.data[4] == 2 else 32
        machine = self.data[18]
        self.arch = {0xB7: 'arm64', 0x3E: 'x86_64', 0x28: 'arm', 0x03: 'i386'}.get(machine, f'e_machine{machine:#x}')
        if self.bits == 64:
            phoff = struct.unpack('<Q', self.data[32:40])[0]
            entsize, num = struct.unpack('<HH', self.data[54:58])
            for i in range(num):
                base = phoff + i * entsize
                p_type = struct.unpack('<I', self.data[base:base + 4])[0]
                p_offset, p_vaddr, _, p_filesz = struct.unpack('<QQQQ', self.data[base + 8:base + 40])
                if p_type == 1:
                    self.segments.append({'name': f'PT_LOAD{i}', 'vaddr': p_vaddr, 'size': p_filesz,
                                          'fileoff': p_offset, 'filesize': p_filesz})
        else:
            phoff = struct.unpack('<I', self.data[28:32])[0]
            entsize, num = struct.unpack('<HH', self.data[42:46])
            for i in range(num):
                base = phoff + i * entsize
                p_type = struct.unpack('<I', self.data[base:base + 4])[0]
                p_offset, p_vaddr, _, p_filesz = struct.unpack('<IIII', self.data[base + 4:base + 20])
                if p_type == 1:
                    self.segments.append({'name': f'PT_LOAD{i}', 'vaddr': p_vaddr, 'size': p_filesz,
                                          'fileoff': p_offset, 'filesize': p_filesz})
        offsets = [s['vaddr'] for s in self.segments if s['vaddr']]
        self.image_base = min(offsets) if offsets else 0

    def in_image(self, va):
        return any(s['vaddr'] <= va < s['vaddr'] + s['size'] for s in self.segments)

    def read_rva(self, rva, size):
        va = self.image_base + rva
        for s in self.segments:
            if s['vaddr'] <= va < s['vaddr'] + s['size']:
                off = s['fileoff'] + (va - s['vaddr'])
                return self.data[off:off + size]
        return b''

    def fileoff_to_va(self, fileoff):
        for s in self.segments:
            if s['fileoff'] <= fileoff < s['fileoff'] + s['filesize']:
                return s['vaddr'] + (fileoff - s['fileoff'])
        return None

    def find_all(self, needle, limit=8):
        out, start = [], 0
        while len(out) < limit:
            pos = self.data.find(needle, start)
            if pos < 0:
                break
            out.append(pos)
            start = pos + 1
        return out


ACCESS_RE = re.compile(r'\+\s*(0x[0-9a-fA-F]+)\)')
FN_RE = re.compile(r'\n[A-Za-z_][A-Za-z0-9_ *]*?\s+fcn\.(10[0-9a-f]+)\([^)]*\)\s*\n?\s*\{')
RET_FIELD_RE = re.compile(r'\*\s*\(\s*[A-Za-z_][A-Za-z0-9_ ]*\*?\s*\)\s*\(\s*\w+\s*\+\s*(0x[0-9a-fA-F]+)\s*\)')


def load_evidence(index_dir, code):
    funcs = read_json(os.path.join(index_dir, 'functions.json'), {})
    fps = read_json(os.path.join(index_dir, 'fingerprints.json'), {})
    symbols = read_json(os.path.join(index_dir, 'symbols_out', 'symbols.json'), {})
    strings_xref = read_json(os.path.join(index_dir, 'strings_xref.json'), {})
    vtables = read_json(os.path.join(index_dir, 'vtables.json'), {})
    readers, writers, getters = {}, {}, {}
    for off, meta in fps.items():
        addr = int(off, 16)
        for f in meta.get('fields_accessed', []):
            readers.setdefault(f, set()).add(addr)
        rf = meta.get('ret_field')
        if rf and meta.get('lines', 99) <= 14:
            getters.setdefault(rf, set()).add(addr)
    if code:
        bodies = {}
        defs = list(FN_RE.finditer(code))
        for i, d in enumerate(defs):
            end = defs[i + 1].start() if i + 1 < len(defs) else len(code)
            bodies[int(d.group(1), 16)] = code[d.start():end]
        for rva, body in bodies.items():
            for f in {m.group(1) for m in ACCESS_RE.finditer(body)}:
                readers.setdefault(f, set()).add(rva)
                if re.search(r'\+\s*' + re.escape(f) + r'\)\s*(\[[^\]]*\])*\s*=\s*[^=]', body):
                    writers.setdefault(f, set()).add(rva)
    return funcs, fps, readers, writers, getters, symbols, strings_xref, vtables


def callers_of(funcs, addr):
    return len(funcs.get(hex(addr), {}).get('callers', []))


def pick_accessor(offset, funcs, getters, readers, writers):
    for source, label in ((getters, 'getter'), (readers, 'reader'), (writers, 'writer')):
        cands = sorted(source.get(offset, set()))
        if not cands:
            continue
        ranked = sorted(cands, key=lambda a: -callers_of(funcs, a))
        top = ranked[0]
        runner = callers_of(funcs, ranked[1]) if len(ranked) > 1 else 0
        strength = 'unique' if len(ranked) == 1 else ('clear' if callers_of(funcs, top) >= 3 * max(1, runner) else 'weak')
        return top, label, strength, len(ranked)
    return None, '-', 'none', 0


def region_members(funcs, picks, window=0x20000):
    if not picks:
        return None, []
    ordered = sorted(picks)
    center = ordered[len(ordered) // 2]
    members = sorted(int(o, 16) for o in funcs if abs(int(o, 16) - center) <= window)
    return center, members


def valid_function_start(binary, rva, funcs):
    if hex(rva) not in funcs:
        return False
    if not funcs[hex(rva)].get('size_chars'):
        return False
    if binary.image_base:
        raw = binary.read_rva(rva, 4)
        if not raw:
            return False
        if raw == b'\x00\x00\x00\x00':
            return False
    return True


def code_runs(entries):
    runs = []
    current = []
    for name, value in sorted(entries.items(), key=lambda kv: kv[1]):
        if current and value - current[-1][1] == RUN_STEP:
            current.append((name, value))
        else:
            if len(current) >= 2:
                runs.append(current)
            current = [(name, value)]
    if len(current) >= 2:
        runs.append(current)
    return runs


BRANCH_MASK = 0xFC000000
PAGE_REGS = 0x9F00001F
IMM12 = 0xFFC003FF
MOVWIDE = 0xFF80001F
LITLOAD = 0xFF00001F


def mask_word(word):
    if word & BRANCH_MASK in (0x14000000, 0x94000000):
        return word & BRANCH_MASK, BRANCH_MASK
    if word & 0x9F000000 in (0x90000000, 0x10000000):
        return word & PAGE_REGS, PAGE_REGS
    if word & 0x1F000000 in (0x11000000, 0x31000000, 0x51000000, 0x71000000, 0xB1000000, 0xD1000000):
        return word & IMM12, IMM12
    if word & 0x3B000000 in (0x39000000, 0x79000000, 0xB9000000, 0xF9000000):
        return word & IMM12, IMM12
    if word & 0x7F800000 in (0x12800000, 0x32800000, 0x52800000, 0x72800000):
        return word & MOVWIDE, MOVWIDE
    if word & 0x3B000000 in (0x18000000, 0x58000000):
        return word & LITLOAD, LITLOAD
    if word & 0x7E000000 in (0x34000000, 0x36000000, 0x74000000, 0xB6000000):
        return word & 0x7E000000, 0x7E000000
    return word, 0xFFFFFFFF


def masked_words(binary, rva, count, skip=0):
    base = rva + skip * 4
    raw = binary.read_rva(base, count * 4)
    if len(raw) < count * 4 or not any(raw):
        return None
    words = struct.unpack(f'<{count}I', raw)
    return tuple(mask_word(w)[0] for w in words)


def signature(binary, rva, count=5, skip=1):
    for shift in (skip, 0, 2):
        words = masked_words(binary, rva, count, shift)
        if words:
            return shift, words
    return None, None


def build_signature_index(binary, addresses, count=5):
    index = {}
    for rva in addresses:
        skip, words = signature(binary, rva, count)
        if words is None:
            continue
        index.setdefault((skip, words), []).append(rva)
    return index


def verify_masking(binary, rvas, count=5):
    passed, rejected = 0, 0
    for rva in rvas:
        shift, words = signature(binary, rva, count)
        if words is None:
            rejected += 1
            continue
        raw = binary.read_rva(rva + shift * 4, count * 4)
        stable = True
        for word in struct.unpack(f'<{count}I', raw):
            value, mask = mask_word(word)
            if mask_word(word ^ ((~mask) & 0xFFFFFFFF))[0] != value:
                stable = False
                break
        if stable:
            passed += 1
        else:
            rejected += 1
    return passed, rejected


SIGNATURE_WIDTHS = (6, 10, 16)


def transfer(binary, ref_binary, entries, funcs):
    indices = {count: build_signature_index(binary, [int(o, 16) for o in funcs], count)
               for count in SIGNATURE_WIDTHS}
    results = {}
    for name, value in entries.items():
        rva = value - ref_binary.image_base if ref_binary.in_image(value) else value
        status, addr, candidates, width = 'NO-SIGNATURE', None, 0, 0
        for count in SIGNATURE_WIDTHS:
            shift, words = signature(ref_binary, rva, count)
            if words is None:
                continue
            hits = indices[count].get((shift, words), [])
            candidates, width = len(hits), count
            if candidates == 1:
                status, addr = 'RESOLVED', hits[0]
                break
            status = 'NO-MATCH' if not hits else 'SHORTLIST'
            if not hits:
                break
        results[name] = (status, addr, candidates, width)
    return results


def structural_map(binary, names, funcs, fps, centers):
    order_entries = {}
    size_entries = {}
    classes = {class_of(n) for n, v in names.items() if v >= FIELD_LIMIT}
    for klass in sorted(classes):
        refs = sorted(((n, v) for n, v in names.items() if class_of(n) == klass and v >= FIELD_LIMIT), key=lambda kv: kv[1])
        _, members = centers.get(klass, (None, []))
        if not members or len(refs) < 2:
            continue
        cands = sorted(members)
        ref_sizes = [refs[i + 1][1] - refs[i][1] for i in range(len(refs) - 1)]
        ref_sizes.append(sorted(ref_sizes)[len(ref_sizes) // 2] if ref_sizes else 0)
        cand_sizes = [funcs.get(hex(a), {}).get('size_chars', 0) for a in cands]
        if len(cands) == len(refs):
            order_pair = list(zip(refs, cands))
        else:
            order_pair = list(zip(refs, [cands[round(i * (len(cands) - 1) / max(1, len(refs) - 1))] for i in range(len(refs))]))
        ref_by_size = sorted(range(len(refs)), key=lambda i: -ref_sizes[i])
        cand_by_size = sorted(range(len(cands)), key=lambda i: -cand_sizes[i])
        size_map = {}
        for rank, idx in enumerate(ref_by_size):
            if rank < len(cand_by_size):
                size_map[refs[idx][0]] = cands[cand_by_size[rank]]
        for (name, value), addr in order_pair:
            order_entries[name] = addr
        for name in size_map:
            size_entries[name] = size_map[name]
    return order_entries, size_entries


def main():
    args = parse_args()
    names = parse_names(read_text(args.names))
    if args.filter:
        names = {n: v for n, v in names.items() if args.filter.lower() in n.lower()}
    binary = Binary(args.binary)
    code = read_text(args.code) if args.code and os.path.exists(args.code) else ''
    funcs, fps, readers, writers, getters, symbols, strings_xref, vtables = load_evidence(args.index_dir, code)

    fields = {n: v for n, v in names.items() if 0 < v < FIELD_LIMIT}
    rest = {n: v for n, v in names.items() if v >= FIELD_LIMIT}
    if binary.image_base:
        code_entries = {n: v for n, v in rest.items() if binary.in_image(v)}
        data_entries = {n: v for n, v in rest.items() if not binary.in_image(v)}
    else:
        code_entries, data_entries = rest, {}
    bare = {n for n, v in names.items() if v == 0}

    if args.structural:
        by_class = {}
        for name, value in fields.items():
            by_class.setdefault(class_of(name), {})[name] = value
        centers = {}
        for klass, entries in by_class.items():
            picks = []
            for name, value in entries.items():
                probe, source, strength, count = pick_accessor(hex(value), funcs, getters, readers, writers)
                if probe is not None and strength in ('unique', 'clear') and valid_function_start(binary, probe, funcs):
                    picks.append(probe)
            centers[klass] = region_members(funcs, picks)
        order_map, size_map = structural_map(binary, names, funcs, fps, centers)
        agree = sorted(n for n in order_map if size_map.get(n) == order_map[n])
        body = [f'- classes with anchors: {len(centers)}',
                f'- assigned by reference order: {len(order_map)}',
                f'- assigned by size rank: {len(size_map)}',
                f'- both methods agree: {len(agree)}',
                '', '| name | reference | order-based | size-rank | agreement | byte check |', '|---|---|---|---|---|---|']
        for n in sorted(order_map):
            a, b = order_map[n], size_map.get(n)
            body.append(f'| {n} | 0x{names[n]:x} | 0x{a:x} | {hex(b) if b is not None else "-"} | '
                        f'{"AGREE" if b == a else "disagree"} | {"real start" if valid_function_start(binary, a, funcs) else "no"} |')
        report = '# structural alignment\n\n' + '\n'.join(body)
        print(report)
        if args.report:
            with open(args.report, 'w', encoding='utf-8') as f:
                f.write(report + '\n')
        if args.out:
            with open(args.out, 'w', encoding='utf-8') as f:
                f.write('export const offsets = {\n')
                for n in agree:
                    f.write(f'    "{n}": 0x{agree[n] + binary.image_base:x},\n')
                f.write('};\n')
        return

    if args.selftest:
        sample = [int(o, 16) for o in sorted(funcs, key=lambda k: -funcs[k].get('size_chars', 0))[:3000]]
        passed, rejected = verify_masking(binary, sample)
        print(f'- arch {binary.arch}\n- sampled functions: {len(sample)}\n'
              f'- signature unchanged after rewriting every masked address/immediate bit: {passed}\n'
              f'- unusable: {rejected}\n- verdict: {"PASS" if passed and not rejected else "PARTIAL"}')
        return

    if args.reference_binary:
        ref_binary = Binary(args.reference_binary)
        entries = {n: v for n, v in names.items() if v >= FIELD_LIMIT}
        results = transfer(binary, ref_binary, entries, funcs)
        ok = sum(1 for status, *_ in results.values() if status == 'RESOLVED')
        print(f'- reference build: {os.path.basename(args.reference_binary)} arch {ref_binary.arch} '
              f'base {hex(ref_binary.image_base)}\n- target build: {os.path.basename(args.binary)} arch {binary.arch} '
              f'base {hex(binary.image_base)}\n- code entries: {len(entries)}\n'
              f'- resolved with a unique byte-level match: {ok}')
        for name in sorted(results):
            status, addr, cands, words = results[name]
            print(f'- {name}: {status}{" 0x%x" % addr if addr is not None else ""} (candidates {cands}, words {words})')
        return

    lines = ['# Offset resolution', '',
             f'- binary: {os.path.basename(args.binary) if args.binary else "none"} | arch {binary.arch} | '
             f'image base {hex(binary.image_base)} | segments {len(binary.segments)} | symbols {len(binary.symbols)}',
             f'- index: {args.index_dir or "none"} | functions {len(funcs)}',
             f'- requested {len(names)}: fields {len(fields)}, code {len(code_entries)}, data {len(data_entries)}, bare {len(bare)}',
             '', '## Field entries (struct offsets, validated by accessor evidence in the binary)', '',
             '| name | offset | status | accessors | validation |', '|---|---|---|---|---|']

    resolved = {}
    stats = {'field_validated': 0, 'field_candidate': 0, 'code_run': 0, 'code_noanchor': 0, 'bare_unique': 0}

    by_class = {}
    for name, value in fields.items():
        by_class.setdefault(class_of(name), {})[name] = value

    centers = {}
    for klass, entries in sorted(by_class.items()):
        picks = []
        for name, value in sorted(entries.items()):
            off = hex(value)
            gs = sorted(getters.get(off, set()))
            rs = sorted(readers.get(off, set()))
            ws = sorted(writers.get(off, set()))
            probe, source, strength, count = pick_accessor(off, funcs, getters, readers, writers)
            ok = probe is not None and valid_function_start(binary, probe, funcs)
            if ok and strength in ('unique', 'clear'):
                picks.append(probe)
            if ok and strength in ('unique', 'clear'):
                status, why = 'VALIDATED', f'{source} {hex(probe)} is a live function start, {count} candidate(s), calls {callers_of(funcs, probe)}'
                stats['field_validated'] += 1
                resolved[name] = value
            elif ok:
                status, why = 'CANDIDATE', f'{source} {hex(probe)} confirmed in the binary but {count} candidates share the offset'
                stats['field_candidate'] += 1
            else:
                status, why = 'NO-EVIDENCE', 'no accessor found in the binary'
            lines.append(f'| {name} | 0x{value:x} | {status} | getter {", ".join(hex(a) for a in gs[:3]) or "-"}; '
                         f'readers {len(rs)}; writers {len(ws)} | {why} |')
        centers[klass] = region_members(funcs, picks)

    lines += ['', '## Consecutive-run code entries (reference spacing 8 bytes survives into the target)', '',
              '| name | reference value | status | target | evidence |', '|---|---|---|---|---|']
    handled = set()
    for klass in sorted({class_of(n) for n in code_entries}):
        entries = {n: v for n, v in code_entries.items() if class_of(n) == klass}
        if not entries:
            continue
        _, members = centers.get(klass, (None, []))
        for run in code_runs(entries):
            width = len(run)
            pick = None
            if members:
                for i in range(len(members) - 1):
                    window = members[i:i + width]
                    if len(window) < 2:
                        continue
                    if window[1] - window[0] != RUN_STEP:
                        continue
                    f0 = fps.get(hex(window[0]), {}).get('ret_field')
                    f1 = fps.get(hex(window[1]), {}).get('ret_field')
                    if f0 and f1 and int(f1, 16) - int(f0, 16) != RUN_FIELD_STEP:
                        continue
                    pick = window
                    break
            for idx, (name, value) in enumerate(run):
                if pick and idx < len(pick) and valid_function_start(binary, pick[idx], funcs):
                    handled.add(name)
                    stats['code_run'] += 1
                    resolved[name] = pick[idx] + binary.image_base
                    lines.append(f'| {name} | 0x{value:x} | VALIDATED | 0x{pick[idx]:x} | run of {width} at 8-byte spacing, '
                                 f'fields {fps.get(hex(pick[idx]), {}).get("ret_field")}, binary start confirmed |')
                else:
                    handled.add(name)
                    stats['code_noanchor'] += 1
                    lines.append(f'| {name} | 0x{value:x} | NO-ANCHOR | - | reference value is a code address, '
                                 f'absent from this image and unverifiable without a name anchor |')

    remaining = {n: v for n, v in code_entries.items() if n not in handled}
    if remaining:
        lines += ['', '## Remaining code entries', '', '| name | reference value | status |', '|---|---|---|']
        for name, value in sorted(remaining.items(), key=lambda kv: kv[1]):
            stats['code_noanchor'] += 1
            lines.append(f'| {name} | 0x{value:x} | NO-ANCHOR |')

    if bare:
        lines += ['', '## Bare names (looked up in symbols, index names and raw binary strings)', '',
                  '| name | status | result | evidence |', '|---|---|---|---|']
        for name in sorted(bare):
            needle = name.lower()
            sym_hits = [s['value'] - binary.image_base for s in binary.symbols if needle in s['name'].lower() and s['value']]
            idx_hits = [int(o, 16) for o, d in funcs.items() if needle in str(d.get('name', '')).lower()]
            str_hits = [binary.fileoff_to_va(p) for p in binary.find_all(name.encode()) if binary.fileoff_to_va(p)]
            all_hits = sorted({h for h in sym_hits + idx_hits + str_hits if h and h > 0})
            if len(all_hits) == 1:
                stats['bare_unique'] += 1
                resolved[name] = all_hits[0] + binary.image_base
                lines.append(f'| {name} | RESOLVED | 0x{all_hits[0]:x} | single occurrence (symbols {len(sym_hits)}, '
                             f'index {len(idx_hits)}, raw strings {len(str_hits)}) |')
            else:
                lines.append(f'| {name} | {"SHORTLIST" if all_hits else "NOT-FOUND"} | '
                             f'{", ".join(hex(h) for h in all_hits[:6]) or "-"} | symbols {len(sym_hits)}, index {len(idx_hits)}, '
                             f'raw strings {len(str_hits)} |')

    total = len(names)
    lines += ['', '## Totals', '',
              f'- field entries validated against the binary: {stats["field_validated"]}/{len(fields)}',
              f'- code entries validated via run alignment: {stats["code_run"]}',
              f'- code entries with no derivable anchor: {stats["code_noanchor"]}',
              f'- data entries outside the image: {len(data_entries)}',
              f'- bare names resolved uniquely: {stats["bare_unique"]}/{len(bare)}',
              f'- **validated against the binary: {len(resolved)}/{total}**']

    report = '\n'.join(lines)
    print(report)
    if args.report:
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write(report + '\n')
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write('export const offsets = {\n')
            for name in sorted(resolved):
                value = resolved[name]
                va = value if value > binary.image_base else value + binary.image_base
                f.write(f'    "{name}": 0x{va:x},\n')
            f.write('};\n')


if __name__ == '__main__':
    main()
