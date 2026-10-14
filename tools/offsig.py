import argparse
import bisect
import csv
import json
import re
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

K = 24
EXT = 96
SNAP = 0x2000
MASK = (1 << 64) - 1
BASE = 0x100000001B3
NUM = re.compile(r'(?<![A-Za-z0-9_])-?0x[0-9A-Fa-f]+')
DEC = re.compile(r'(?<![A-Za-z0-9_])-?\d+')
REGS = re.compile(r'\b(x\d{1,2}|w\d{1,2}|sp|wzr|xzr|[qdsv]\d{1,2}|[bshd]\d{1,2})\b')
NOISE = {'bti', 'nop', 'pacibsp', 'autibsp', 'paciasp', 'autiasp', 'hint', 'xpaclri'}
MASK_REGS = [False]
PROLOGUES = ('pacibsp', 'stp x29, x30, [sp', 'sub sp, sp, #')


class Img:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self.regions = []
        self.base = 0
        self._parse()

    def _parse(self):
        d = self.data
        if d[:4] == b'\x7fELF':
            self._elf()
        elif d[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
            self._macho()
        else:
            raise SystemExit(f'{self.path}: unknown format')

    def _elf(self):
        e_phoff, = struct.unpack_from('<Q', self.data, 0x20)
        e_phentsize, e_phnum = struct.unpack_from('<HH', self.data, 0x36)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags = struct.unpack_from('<II', self.data, off)
            p_offset, p_vaddr, _, p_filesz = struct.unpack_from('<QQQQ', self.data, off + 8)
            if p_type == 1 and p_filesz:
                self.regions.append((p_vaddr, p_offset, p_filesz, bool(p_flags & 1)))
        if self.regions:
            self.base = min(r[0] for r in self.regions)

    def _macho(self):
        d = self.data
        if d[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
            n, = struct.unpack_from('>I', d, 4)
            for i in range(n):
                cputype, _, off, _ = struct.unpack_from('>IIII', d, 8 + i * 20)
                if cputype == 0x0100000C:
                    d = d[off:]
                    self.data = d
                    break
        ncmds, = struct.unpack_from('<I', d, 16)
        p = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', d, p)
            if cmd == 0x19:
                vmaddr, _, fileoff, filesize, _, _, initprot = struct.unpack_from('<QQQQIIi', d, p + 24)
                if filesize:
                    self.regions.append((vmaddr, fileoff, filesize, bool(initprot & 4)))
            p += size
        if self.regions:
            self.base = min(r[0] for r in self.regions)

    def text(self):
        return [(v - self.base, o, s) for v, o, s, ex in self.regions if ex]


def norm(op):
    return DEC.sub('#', NUM.sub('#', op))


def tok_text(m, o):
    if m in NOISE:
        return None
    t = norm(o)
    if MASK_REGS[0]:
        t = REGS.sub('R', t)
    return f'{m} {t}'.rstrip() if m != '.byte' else f'.byte {o.replace(" ", "")}'


def mdcs():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    return md


class Code:
    def __init__(self, img, md, intern=None):
        self.regions = []
        self.prologues = []
        self.intern = {} if intern is None else intern
        for rva, off, size in img.text():
            ids = []
            addrs = []
            start = None
            for a, _, m, o in md.disasm_lite(img.data[off:off + size], rva):
                t = tok_text(m, o)
                if t is None:
                    continue
                i = self.intern.get(t)
                if i is None:
                    i = len(self.intern)
                    self.intern[t] = i
                if start is None:
                    start = a
                if t.startswith(PROLOGUES):
                    self.prologues.append(a)
                ids.append(i)
                addrs.append(a)
            if ids:
                self.regions.append((start, ids, addrs))
        self.prologues.sort()

    def window(self, rva, k, ext):
        for start, ids, addrs in self.regions:
            j = bisect.bisect_left(addrs, rva)
            if j >= len(ids) or addrs[j] - rva > 12:
                continue
            if j + k > len(ids):
                return None, None, None
            return (tuple(ids[j:j + k]),
                    (tuple(ids[j:j + ext]) if j + ext <= len(ids) else None),
                    addrs[j])
        return None, None, None

    def snap(self, rva, limit):
        i = bisect.bisect_right(self.prologues, rva)
        if i and self.prologues[i - 1] >= rva - limit:
            return self.prologues[i - 1]
        return None

    def scan(self, targets, k):
        found = {}
        p = 1
        for _ in range(k):
            p = (p * BASE) & MASK
        for start, ids, addrs in self.regions:
            cur = 0
            n = len(ids)
            for i in range(n):
                cur = ((cur * BASE) + ids[i] + 1) & MASK
                if i >= k:
                    cur = (cur - (ids[i - k] + 1) * p) & MASK
                if i < k - 1:
                    continue
                hit = targets.get(cur)
                if not hit:
                    continue
                j = i - k + 1
                for name, delta, w in hit:
                    if tuple(ids[j:j + k]) == w:
                        found.setdefault(name, []).append((abs(delta), delta, addrs[j]))
        return found


def win_hash(w):
    cur = 0
    for v in w:
        cur = ((cur * BASE) + v + 1) & MASK
    return cur


def load_table(path):
    with open(path) as f:
        txt = f.read()
    out = {}
    if path.endswith('.json'):
        for k, v in json.loads(txt).items():
            out[k] = int(v, 0) if isinstance(v, str) else int(v)
        return out
    if path.endswith('.csv'):
        for row in csv.reader(txt.splitlines()):
            if len(row) >= 2 and row[1].strip():
                try:
                    out[row[0].strip()] = int(row[1], 0)
                except ValueError:
                    pass
        return out
    for name, val in re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(0x[0-9A-Fa-f]+|\d+)', txt):
        out[name] = int(val, 0)
    return out


def run(old_img, new_img, table, k=K, ext=EXT, slide=SNAP):
    md = mdcs()
    old_code = Code(old_img, md)
    new_code = Code(new_img, md, intern=old_code.intern)
    exts = {}
    targets = {}
    for name, rva in table.items():
        w, e, _b = old_code.window(rva, k, ext)
        if w is None:
            continue
        targets.setdefault(win_hash(w), []).append((name, 0, w))
        exts[name] = e
    found = new_code.scan(targets, k)
    todo = [n for n in table if n not in found]
    if slide and todo:
        t2 = {}
        for name in todo:
            rva = table[name]
            for d in range(4, slide + 1, 4):
                for dd in (d, -d):
                    w, _e, _b = old_code.window(rva + dd, k, ext)
                    if w is None:
                        continue
                    t2.setdefault(win_hash(w), []).append((name, dd, w))
        for n, lst in new_code.scan(t2, k).items():
            found.setdefault(n, []).extend(lst)
    res = {}
    for name, rva in table.items():
        cands = found.get(name)
        if not cands:
            res[name] = (rva, None, 0, 'missing')
            continue
        cands.sort()
        delta = cands[0][1]
        same = [c for c in cands if c[1] == delta]
        addrs = list(dict.fromkeys(c[2] for c in same))
        e = exts.get(name)
        if len(addrs) > 1 and e is not None:
            keep = [c for c in addrs if new_code.window(c, ext, ext)[0] == e]
            if keep:
                addrs = keep
        if len(addrs) == 1:
            res[name] = (rva, addrs[0], delta, 'matched')
        else:
            res[name] = (rva, addrs, delta, 'ambiguous')
    return res


def resolve(res):
    anchors = sorted((v[0], v[1]) for v in res.values() if v[3] == 'matched' and isinstance(v[1], int))
    oa = [a for a, _ in anchors]
    for name, v in list(res.items()):
        if v[3] != 'ambiguous' or not isinstance(v[1], list):
            continue
        cands = sorted(c for c in v[1] if isinstance(c, int))
        i = bisect.bisect_left(oa, v[0])
        lo = anchors[i - 1][1] if i > 0 else None
        hi = anchors[i][1] if i < len(anchors) else None
        pick = None
        if lo is not None and hi is not None and oa:
            inside = [c for c in cands if lo < c < hi]
            if inside:
                t = (v[0] - anchors[i - 1][0]) / max(1, anchors[i][0] - anchors[i - 1][0])
                want = lo + t * (hi - lo)
                pick = min(inside, key=lambda c: abs(c - want))
        if pick is not None:
            res[name] = (v[0], pick, v[2], 'resolved')
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--table', required=True)
    ap.add_argument('--out', default='offsets_new.csv')
    ap.add_argument('--k', type=int, default=K)
    ap.add_argument('--ext', type=int, default=EXT)
    ap.add_argument('--slide', type=int, default=SNAP)
    ap.add_argument('--mask-regs', action='store_true')
    a = ap.parse_args()
    MASK_REGS[0] = a.mask_regs
    old_img, new_img = Img(a.old), Img(a.new)
    table = load_table(a.table)
    res = resolve(run(old_img, new_img, table, a.k, a.ext, a.slide))
    with open(a.out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['name', 'seed_rva_68250', 'drift_to_68279', 'old_aligned', 'new_rva_69252', 'status'])
        for name, v in sorted(res.items()):
            w.writerow([name, hex(v[0]), v[2], hex(v[0] + v[2]),
                        hex(v[1]) if isinstance(v[1], int) else '', v[3]])
    c = {}
    for v in res.values():
        c[v[3]] = c.get(v[3], 0) + 1
    print(f'old={a.old} new={a.new} table={len(table)} slide={hex(a.slide)}')
    print(' '.join(f'{k}={c[k]}' for k in sorted(c)))
    print(f'wrote {a.out}')


if __name__ == '__main__':
    main()
