import bisect
import csv
import json
import re
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

NAME_RX = re.compile(r'[A-Za-z_][A-Za-z0-9_]{2,40}::[A-Za-z_~][A-Za-z0-9_]{1,40}')
TERMINATORS = {'ret', 'retab'}
PAD = {'nop', 'udf', '#0'}
PROLOGUE_KINDS = ('stp x29, x30', 'sub sp, sp, #', 'pacibsp', 'stp x20, x19')


def parse(path):
    d = open(path, 'rb').read()
    if d[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        n, = struct.unpack_from('>I', d, 4)
        for i in range(n):
            cputype, _, off, _ = struct.unpack_from('>IIII', d, 8 + i * 20)
            if cputype == 0x0100000C:
                d = d[off:]
                break
    ncmds, = struct.unpack_from('<I', d, 16)
    p = 32
    segs, sects = {}, []
    symtab = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', d, p)
        if cmd == 0x19:
            seg = d[p+8:p+24].split(b'\0')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, p+24)
            segs[seg] = (vmaddr, vmsize, fileoff, filesize)
            nsects, = struct.unpack_from('<I', d, p+64)
            for i in range(nsects):
                q = p + 72 + i * 80
                sn = d[q:q+16].split(b'\0')[0].decode()
                sg = d[q+16:q+32].split(b'\0')[0].decode()
                addr, sz = struct.unpack_from('<QQ', d, q+32)
                off, = struct.unpack_from('<I', d, q+48)
                sects.append((sg, sn, addr, sz, off))
        elif cmd == 0x2:
            symtab = struct.unpack_from('<II', d, p+8)
        p += size
    return d, segs, sects, symtab


def syms(d, symtab, sects):
    if not symtab:
        return []
    off, sz = symtab
    strtab = None
    for sg, sn, addr, sz2, off2 in sects:
        if sn == '__strtab':
            strtab = off2
    out = []
    n = sz // 16
    for i in range(n):
        q = off + i * 16
        strx, typ, sect, desc, value = struct.unpack_from('<IBBHQ', d, q)
        if strtab is None:
            continue
        s = d[strtab + strx:d.index(b'\0', strtab + strx)].decode('utf8', 'replace')
        out.append((s, value, typ, sect))
    return out


def cstrings(d, sects):
    c = [s for s in sects if s[1] == '__cstring']
    if not c:
        return []
    sg, sn, addr, sz, off = c[0]
    blob = d[off:off + sz]
    out = []
    pos = 0
    for m in re.finditer(rb'[ -~]{4,}', blob):
        s = m.group()
        if b'\x00' not in s:
            out.append((addr + m.start(), s.decode('utf8', 'replace')))
    return out


def const_ptr_map(d, sects, str_addrs):
    res = {}
    for sg, sn, addr, sz, off in sects:
        if sn not in ('__const', '__cstring', '__cfstring', '__objc_methname', '__objc_classname', '__data'):
            continue
        for i in range(0, sz - 7, 8):
            v, = struct.unpack_from('<Q', d, off + i)
            if v in str_addrs:
                res[addr + i] = v
    return res


def sweep(d, sects):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    text = [s for s in sects if s[1] == '__text']
    starts, insns = [], {}
    for sg, sn, addr, sz, off in text:
        code = d[off:off + sz]
        seq = [(a, m, o) for a, _, m, o in md.disasm_lite(code, addr)]
        for idx, (a, m, o) in enumerate(seq):
            insns[a] = (idx, m, o)
        prev_term = False
        for idx, (a, m, o) in enumerate(seq):
            if prev_term:
                if m in ('nop',) or m == 'udf':
                    continue
                starts.append(a)
                prev_term = False
            if m in TERMINATORS or (m == 'br' and o.startswith('x')):
                prev_term = True
            elif m == 'b' and not o.startswith('#'):
                prev_term = True
        for sg, sn, addr, sz, off in text:
            starts.append(addr)
    starts = sorted(set(starts))
    return md, starts, insns


class StrMap:
    def __init__(self, strings):
        self.starts = [(a, a + len(s)) for a, s in strings]
        self.starts.sort()
        self.addrs = [s for s, _ in self.starts]
        self.covered = set()
        for s, e in self.starts:
            self.covered.update(range(s, e))

    def at(self, addr):
        if addr not in self.covered:
            return None
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i >= 0 and self.starts[i][0] <= addr < self.starts[i][1]:
            return self.starts[i][0]
        return None


def xrefs(d, sects, smap, cmap):
    text = [s for s in sects if s[1] == '__text']
    out = []
    for sg, sn, addr, sz, off in text:
        data = d[off:off + sz]
        adrp = {}
        for i in range(sz // 4):
            w, = struct.unpack_from('<I', data, i * 4)
            a = addr + i * 4
            if (w & 0x9F000000) == 0x90000000:
                immlo = (w >> 29) & 3
                immhi = (w >> 5) & 0x7FFFF
                imm = ((immhi << 2) | immlo)
                if imm & (1 << 20):
                    imm -= (1 << 21)
                adrp[w & 31] = ((a >> 12) << 12) + (imm << 12)
                continue
            if (w & 0x7F000000) == 0x11000000:
                sh = (w >> 22) & 1
                imm12 = (w >> 10) & 0xFFF
                rn = (w >> 5) & 31
                rd = w & 31
                if rn in adrp:
                    tgt = adrp[rn] + (imm12 << (12 if sh else 0))
                    if tgt in smap.covered or tgt in cmap:
                        out.append((a, tgt))
                    adrp.pop(rd, None)
                continue
            if (w & 0xFFC00000) == 0xF9400000:
                imm12 = (w >> 10) & 0xFFF
                rn = (w >> 5) & 31
                rd = w & 31
                if rn in adrp:
                    tgt = adrp[rn] + imm12 * 8
                    if tgt in smap.covered or tgt in cmap:
                        out.append((a, tgt))
                    adrp.pop(rd, None)
                continue
            adrp.pop(w & 31, None)
    return out


def main():
    path = sys.argv[1]
    out_json = sys.argv[2]
    extra = {}
    if len(sys.argv) > 3:
        extra = json.load(open(sys.argv[3]))
    d, segs, sects, symtab = parse(path)
    sym = syms(d, symtab, sects)
    strs = cstrings(d, sects)
    saddr = {a: s for a, s in strs}
    cmap = const_ptr_map(d, sects, set(saddr))
    md, starts, insns = sweep(d, sects)
    smap = StrMap(strs)
    xr = xrefs(d, sects, smap, cmap)
    print(f'cstrings={len(strs)} const_ptrs={len(cmap)} function_starts={len(starts)} xrefs={len(xr)} symtab={len(sym)}')

    named = {}
    for xa, tgt in xr:
        sa = smap.at(tgt) or cmap.get(tgt) or smap.at(cmap.get(tgt, 0))
        txt = saddr.get(sa, '')
        cands = NAME_RX.findall(txt)
        for k in extra:
            if k in txt:
                cands.append(extra[k])
        if not cands:
            continue
        i = bisect.bisect_right(starts, xa) - 1
        if i < 0:
            continue
        fs = starts[i]
        nxt = starts[i + 1] if i + 1 < len(starts) else fs + 4
        nxt = starts[i + 1] if i + 1 < len(starts) else fs + 4
        size = nxt - fs
        if size < 8:
            continue
        prologue = None
        for a in range(fs, min(fs + 12, nxt), 4):
            e = insns.get(a)
            if not e:
                continue
            _, m, o = e
            t = f'{m} {o}'
            if any(t.startswith(p) for p in PROLOGUE_KINDS):
                prologue = t
                break
        if not prologue:
            continue
        for key in cands:
            cur = named.get(key)
            if cur is None or xa < cur['xref']:
                named[key] = {'name': key, 'rva': fs - 0x100000000, 'size': size,
                              'prologue': prologue, 'xref': xa - 0x100000000,
                              'string_rva': sa - 0x100000000}
    print(f'named functions: {len(named)}')
    with open(out_json, 'w') as f:
        json.dump({'starts': [s - 0x100000000 for s in starts],
                   'named': list(named.values()),
                   'symbols': [(s, v) for s, v, t, sec in sym]}, f)
    print('wrote', out_json)


if __name__ == '__main__':
    main()
