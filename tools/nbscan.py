import bisect
import collections
import csv
import json
import re
import struct
import subprocess
import sys

sys.path.insert(0, 'tools')
import iosnames

MASK48 = 0x0000FFFFFFFFFFFF
NAME_RX = re.compile(r'[A-Za-z_][A-Za-z0-9_]{2,40}::[A-Za-z_~][A-Za-z0-9_]{1,40}')
SLUG_RX = re.compile(r'[^A-Za-z0-9]+')


def slug(s, n=40):
    return SLUG_RX.sub('_', s).strip('_')[:n]


def func_of(starts, addr):
    i = bisect.bisect_right(starts, addr) - 1
    return starts[i] if i >= 0 else None


def load(path):
    d, segs, sects, symtab = iosnames.parse(path)
    strs = iosnames.cstrings(d, sects)
    saddr = {a: s for a, s in strs}
    smap = iosnames.StrMap(strs)
    cmap = iosnames.const_ptr_map(d, sects, set(saddr))
    md, starts, insns = iosnames.sweep(d, sects)
    xr = iosnames.xrefs(d, sects, smap, cmap)
    seg_va = [v for k, (v, _, _, _) in segs.items() if k.startswith('__TEXT')]
    base = min(seg_va) if seg_va else (starts[0] & ~0xFFFF)
    return dict(d=d, sects=sects, segs=segs, strs=strs, saddr=saddr, smap=smap, cmap=cmap,
                starts=starts, insns=insns, xr=xr, symtab=symtab, base=base)


def string_at(ctx, tgt):
    return ctx['smap'].at(tgt) or ctx['cmap'].get(tgt)


def self_named(ctx):
    out = {}
    for xa, tgt in ctx['xr']:
        sa = string_at(ctx, tgt)
        if sa is None:
            continue
        txt = ctx['saddr'].get(sa)
        if not txt:
            continue
        cands = NAME_RX.findall(txt)
        if not cands:
            continue
        rva = func_of(ctx['starts'], xa)
        if rva is None:
            continue
        for c in cands:
            prev = out.get(c)
            if prev is None or rva < prev[0]:
                out[c] = (rva, txt)
    return out


def objc_stubs(ctx):
    d = ctx['d']
    mname = next((s for s in ctx['sects'] if s[1] == '__objc_methname'), None)
    stubs = next((s for s in ctx['sects'] if s[1] == '__objc_stubs'), None)
    if not (mname and stubs):
        return {}
    lo, hi = mname[2], mname[2] + mname[3]
    saddr, ssz, soff = stubs[2], stubs[3], stubs[4]

    def off(va):
        for sg, sn, a, z, o in ctx['sects']:
            if a <= va < a + z:
                return o + (va - a)
        return None

    def cstr(va):
        o = off(va)
        if o is None:
            return None
        e = d.find(b'\x00', o)
        if e < 0 or e - o > 200:
            return None
        try:
            return d[o:e].decode('utf8')
        except UnicodeDecodeError:
            return None

    out = {}
    i = 0
    while i < ssz:
        a = saddr + i
        w0, = struct.unpack_from('<I', d, soff + i)
        if (w0 & 0x9F000000) != 0x90000000:
            i += 4
            continue
        immlo = (w0 >> 29) & 3
        immhi = (w0 >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = ((a >> 12) << 12) + (imm << 12)
        reg = w0 & 31
        w1, = struct.unpack_from('<I', d, soff + i + 4)
        if (w1 & 0xFFC00000) == 0xF9400000 and ((w1 >> 5) & 31) == reg:
            slot = page + ((w1 >> 10) & 0xFFF) * 8
            so = off(slot)
            if so is not None and so + 8 <= len(d):
                v, = struct.unpack_from('<Q', d, so)
                v &= MASK48
                if lo <= v < hi:
                    s = cstr(v)
                    if s:
                        out[a] = ('objc::' + s.replace(':', '_'), 'objc_stub', s)
            i += 8
            continue
        i += 4
    return out


def ref_named(ctx, taken):
    best = {}
    for xa, tgt in ctx['xr']:
        sa = string_at(ctx, tgt)
        if sa is None:
            continue
        txt = ctx['saddr'].get(sa)
        if not txt or len(txt) < 8:
            continue
        rva = func_of(ctx['starts'], xa)
        if rva is None or rva in taken:
            continue
        cur = best.get(rva)
        if cur is None or len(txt) < len(cur[0]):
            best[rva] = (txt, sa)
    return {rva: ('ref_' + slug(t), 'string_ref', t) for rva, (t, _) in best.items()}


def mangled_named(ctx, taken):
    out = {}
    for sa, txt in ctx['saddr'].items():
        if not txt.startswith('_Z') or len(txt) < 8:
            continue
        xs = [xa for xa, tgt in ctx['xr'] if string_at(ctx, tgt) == sa]
        if not xs:
            continue
        rva = func_of(ctx['starts'], xs[0])
        if rva is None or rva in taken or rva in out:
            continue
        out[rva] = txt
    if not out:
        return {}
    p = subprocess.run(['c++filt', *out.values()], capture_output=True, text=True)
    dem = p.stdout.splitlines()
    res = {}
    for (rva, sym), dnm in zip(out.items(), dem):
        res[rva] = (dnm.split('(')[0].strip() or sym, 'mangled', sym)
    return res


def main():
    exe, out_prefix = sys.argv[1], sys.argv[2]
    ctx = load(exe)
    base = ctx['base']
    print('base=%#x starts=%d strings=%d xrefs=%d' % (base, len(ctx['starts']), len(ctx['strs']), len(ctx['xr'])))

    named = {}
    sn = self_named(ctx)
    for c, (rva, ev) in sn.items():
        named.setdefault(rva, (c, 'self_name', ev))
    print('self-named strings:', len(sn), '-> offsets:', sum(1 for v in named.values() if v[1] == 'self_name'))

    stubs = objc_stubs(ctx)
    for rva, (nm, kind, ev) in stubs.items():
        named.setdefault(rva, (nm, kind, ev))
    print('objc stubs named:', len(stubs))

    taken = set(named)
    refs = ref_named(ctx, taken)
    for rva, (nm, kind, ev) in refs.items():
        named.setdefault(rva, (nm, kind, ev))
    print('string-ref named:', len(refs))

    man = mangled_named(ctx, set(named) | set(refs))
    for rva, (nm, kind, ev) in man.items():
        named.setdefault(rva, (nm, kind, ev))
    print('mangled named:', len(man))

    rows = []
    for st in ctx['starts']:
        nm, kind, ev = named.get(st, ('sub_%08x' % (st - base), 'start', ''))
        rows.append((st - base, nm, kind, ev))
    for st, (nm, kind, ev) in stubs.items():
        rows.append((st - base, nm, kind, ev))
    rows.sort()
    with open(out_prefix + '.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['rva', 'name', 'kind', 'evidence'])
        for rva, nm, kind, ev in rows:
            w.writerow([hex(rva), nm, kind, ev])
    json.dump({'starts': [s - base for s in ctx['starts']],
               'named': [{'rva': rva, 'name': nm} for rva, nm, kind, ev in rows if kind != 'start']},
              open(out_prefix + '.json', 'w'))
    kinds = collections.Counter(k for _, _, k, _ in rows)
    print('total offsets exported:', len(rows), '| named:', len(rows) - kinds['start'])
    print('by kind:', dict(kinds))
    print('csv:', out_prefix + '.csv', '| json:', out_prefix + '.json')


if __name__ == '__main__':
    main()
