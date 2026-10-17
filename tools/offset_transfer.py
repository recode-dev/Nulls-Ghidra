#!/usr/bin/env python3
"""Binary-free, cross-platform offset transfer.

Transfers a named offsets map from build A onto build B using ONLY dump indices
(functions / fingerprints / classes / symbols). No reference binary, no target
binary: a map can travel Android <-> iOS and across versions of one platform.

Evidence, strongest first:
  1. class method slot   (classes.json)  - vtable/index order is ABI-stable
  2. float literals      (fingerprints)  - identical text on every platform
  3. integer literals    (fingerprints)  - absolute pointers filtered out
  4. field access profile(fingerprints)  - struct usage semantics
  5. call-graph degrees / size / loops / topology_role - structure
  6. exported symbol name (symbols.json) - exact anchor when present
  7. call-graph propagation - neighbours already matched disambiguate the rest

Field entries are re-derived on the target: source accessors are located via
the same matcher, then the layout shift voted by the matched accessors gives the
platform-correct member offset.
"""
import argparse
import collections
import json
import math
import os
import re

NAME_RE = re.compile(r'[^a-z0-9]')
FIELD_LIMIT = 0x20000


def parse_args():
    p = argparse.ArgumentParser(description='Transfer named offsets between builds using dump indices only (no binary)')
    p.add_argument('--map', required=True, dest='map_path', help='offsets map to transfer (name -> 0x..), any platform')
    p.add_argument('--source_index', default='', help='dump index of the build the map belongs to (defaults to --index_dir)')
    p.add_argument('--index_dir', required=True, help='dump index of the target build')
    p.add_argument('--min_score', type=float, default=0.50, help='acceptance score threshold (0..1)')
    p.add_argument('--margin', type=float, default=0.08, help='required lead of the best match over the runner-up')
    p.add_argument('--neighbor_weight', type=float, default=0.35, help='weight of the call-graph propagation bonus')
    p.add_argument('--max_candidates', type=int, default=1200, help='candidate cap per name')
    p.add_argument('--rounds', type=int, default=3, help='call-graph propagation rounds')
    p.add_argument('--filter', default='', help='restrict to names containing this substring')
    p.add_argument('--out', default='', help='resolved map output (JS constants, accepted entries only)')
    p.add_argument('--report', default='', help='markdown report output')
    return p.parse_args()


def read_text(src):
    if os.path.exists(src):
        with open(src, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return src


def read_json(path, default):
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return json.load(f)
    return default


def parse_map(text):
    out = {}
    for m in re.finditer(r'#define\s+([A-Za-z0-9_]+)\s+(0x[0-9a-fA-F]+)', text):
        out.setdefault(m.group(1), int(m.group(2), 16))
    for m in re.finditer(r'["\']?([A-Za-z0-9_:]{2,80})["\']?\s*[=:]\s*["\']?(0x[0-9a-fA-F]+|\d+)["\']?', text):
        raw = m.group(2)
        out.setdefault(m.group(1), int(raw, 16) if raw.lower().startswith('0x') else int(raw, 10))
    return out


def norm_field(x):
    try:
        return int(str(x), 16) if str(x).lower().startswith('0x') else int(str(x), 10)
    except ValueError:
        return None


def bucket(n):
    return int(math.log2(max(n, 0) + 1))


def norm_name(name):
    return NAME_RE.sub('', str(name).lower())


def sim(a, b):
    """Multiset Jaccard over two Counters."""
    if not a or not b:
        return 0.0
    inter = sum((a & b).values())
    union = sum((a | b).values())
    return inter / union if union else 0.0


class Build:
    def __init__(self, index_dir):
        self.dir = index_dir
        self.funcs = read_json(os.path.join(index_dir, 'functions.json'), {})
        self.fps = read_json(os.path.join(index_dir, 'fingerprints.json'), {})
        self.classes = read_json(os.path.join(index_dir, 'classes.json'), {})
        self.symbols = read_json(os.path.join(index_dir, 'symbols_out', 'symbols.json'), {})
        self.feat = {}
        self.slot = {}
        self.slot_by_addr = {}
        self.by_float = {}
        self.by_const = {}
        self.by_field = {}
        self.by_role = {}
        self.by_role_size = {}
        self.by_symbol = {}
        self.field_accessors = {}
        self._build()

    def _build(self):
        lo = hi = None
        for k in self.funcs:
            v = int(k, 16)
            lo = v if lo is None else min(lo, v)
            hi = v if hi is None else max(hi, v)
        self.code_lo, self.code_hi = (lo or 0), (hi or 0)
        self.image_base = 0
        for meta in self.funcs.values():
            if meta.get('address') and meta.get('offset'):
                self.image_base = int(meta['address'], 16) - int(meta['offset'], 16)
                break

        for klass, meta in self.classes.items():
            for idx, rva in enumerate(meta.get('methods', [])):
                addr = int(rva, 16)
                self.slot.setdefault((klass, idx), addr)
                self.slot_by_addr.setdefault(addr, (klass, idx))

        for rva, meta in self.fps.items():
            addr = int(rva, 16)
            fn = self.funcs.get(rva, {})
            floats = collections.Counter(str(x) for x in meta.get('float_constants', []))
            consts = collections.Counter()
            for x in meta.get('math_constants', []):
                try:
                    v = int(str(x), 16)
                except ValueError:
                    continue
                if self.is_address(v):
                    continue
                consts[v] += 1
            fields = collections.Counter()
            for x in meta.get('fields_accessed', []):
                v = norm_field(x)
                if v is None:
                    continue
                fields[v] += 1
                self.field_accessors.setdefault(v, set()).add(addr)
            self.feat[addr] = {
                'floats': floats,
                'consts': consts,
                'fields': fields,
                'role': meta.get('topology_role'),
                'size_b': bucket(meta.get('size') or fn.get('size_chars') or 1),
                'lines_b': bucket(meta.get('lines') or 1),
                'loops': meta.get('loops_count', 0),
                'in_b': bucket(len(fn.get('callers', []))),
                'out_b': bucket(len(fn.get('calls', []))),
                'sig': (fn.get('return_type', ''), fn.get('args', '')),
            }
            for f in floats:
                self.by_float.setdefault(f, []).append(addr)
            for c in consts:
                self.by_const.setdefault(c, []).append(addr)
            for f in fields:
                self.by_field.setdefault(f, []).append(addr)
            self.by_role.setdefault(self.feat[addr]['role'], []).append(addr)
            self.by_role_size.setdefault((self.feat[addr]['role'], self.feat[addr]['size_b']), []).append(addr)

        for rva, name in self.symbols.items():
            self.by_symbol.setdefault(norm_name(name), int(rva, 16))

    def in_code(self, v):
        return self.code_lo <= v <= self.code_hi

    def is_address(self, v):
        if self.code_lo <= v <= self.code_hi:
            return True
        return bool(self.image_base) and self.image_base + self.code_lo <= v <= self.image_base + self.code_hi

    def calls_of(self, addr, kind):
        return {int(x, 16) for x in self.funcs.get(hex(addr), {}).get(kind, [])}


class Matcher:
    def __init__(self, source, target, args):
        self.s, self.t, self.args = source, target, args
        self.memo = {}
        self.cand_memo = {}
        self.pairs = {}

    def _cands(self, src_addr):
        if src_addr in self.cand_memo:
            return self.cand_memo[src_addr]
        self.cand_memo[src_addr] = self._cands_uncached(src_addr)
        return self.cand_memo[src_addr]

    def _cands_uncached(self, src_addr):
        src = self.s.feat[src_addr]
        out = []
        for f in src['floats']:
            out.extend(self.t.by_float.get(f, ()))
        for c in src['consts']:
            out.extend(self.t.by_const.get(c, ()))
        for f in src['fields']:
            out.extend(self.t.by_field.get(f, ()))
        slot = self.s.slot_by_addr.get(src_addr)
        if slot and self.t.slot.get(slot) is not None:
            out.append(self.t.slot[slot])
        out.extend(self.t.by_role_size.get((src['role'], src['size_b']), ()))
        if not out:
            out = list(self.t.by_role.get(src['role'], ()))
        out = list(dict.fromkeys(out))
        cap = self.args.max_candidates
        if len(out) > cap:
            out.sort(key=lambda c: -self._cheap(src_addr, c))
            out = out[:cap]
        return out

    def _cheap(self, src_addr, cand):
        """Cheap prefilter so the cap keeps the plausible candidates."""
        a, b = self.s.feat[src_addr], self.t.feat[cand]
        v = 0.0
        if self.s.slot_by_addr.get(src_addr) and self.s.slot_by_addr.get(src_addr) == self.t.slot_by_addr.get(cand):
            v += 5.0
        if a['role'] == b['role']:
            v += 2.0
        if a['size_b'] == b['size_b']:
            v += 2.0
        if a['sig'] == b['sig']:
            v += 1.0
        if a['in_b'] == b['in_b']:
            v += 1.0
        if a['out_b'] == b['out_b']:
            v += 1.0
        if a['lines_b'] == b['lines_b']:
            v += 1.0
        if a['loops'] == b['loops']:
            v += 1.0
        return v

    def base_score(self, src_addr, cand):
        if src_addr not in self.s.feat or cand not in self.t.feat:
            return 0.0
        a, b = self.s.feat[src_addr], self.t.feat[cand]
        aslot, bslot = self.s.slot_by_addr.get(src_addr), self.t.slot_by_addr.get(cand)
        s = mx = 0.0
        mx += 3.0
        if aslot and aslot == bslot:
            s += 3.0
        mx += 0.6
        if a['sig'] == b['sig']:
            s += 0.6
        mx += 0.5
        if a['role'] == b['role']:
            s += 0.5
        mx += 0.8
        if a['size_b'] == b['size_b']:
            s += 0.8
        elif abs(a['size_b'] - b['size_b']) == 1:
            s += 0.3
        mx += 0.4
        if a['lines_b'] == b['lines_b']:
            s += 0.4
        mx += 2.0
        s += 2.0 * sim(a['floats'], b['floats'])
        mx += 2.0
        s += 2.0 * sim(a['consts'], b['consts'])
        mx += 1.5
        s += 1.5 * sim(a['fields'], b['fields'])
        mx += 0.5
        if a['in_b'] == b['in_b']:
            s += 0.5
        mx += 0.5
        if a['out_b'] == b['out_b']:
            s += 0.5
        mx += 0.3
        if a['loops'] == b['loops']:
            s += 0.3
        return s / mx

    def neighbors(self, src_addr, cand):
        best = 0.0
        for kind in ('callers', 'calls'):
            sset = self.s.calls_of(src_addr, kind)
            tset = self.t.calls_of(cand, kind)
            mapped = {self.pairs[x] for x in sset if x in self.pairs}
            if mapped:
                best = max(best, len(mapped & tset) / len(mapped))
        return best

    def graph_candidates(self, src_addr):
        """Target functions reachable through already matched code neighbours."""
        pool = set()
        for kind, back in (('calls', 'callers'), ('callers', 'calls')):
            for n in self.s.calls_of(src_addr, kind):
                m = self.pairs.get(n)
                if m is not None:
                    pool |= self.t.calls_of(m, back)
        return {c for c in pool if c in self.t.feat}

    def propagate(self, pending, rounds):
        """Resolve leftovers by forcing them onto matched neighbours' edge sets."""
        resolved = {}
        for _ in range(rounds):
            gained = 0
            for src_addr in sorted(pending):
                if src_addr in resolved or src_addr not in self.s.feat:
                    continue
                pool = self.graph_candidates(src_addr)
                if not pool:
                    continue
                scored = sorted(((self.base_score(src_addr, c) + 1.0 * self.neighbors(src_addr, c), c)
                                 for c in pool), key=lambda kv: (-kv[0], kv[1]))
                total, addr = scored[0]
                runner = scored[1][0] if len(scored) > 1 else 0.0
                if total >= self.args.min_score and (total - runner) >= self.args.margin:
                    resolved[src_addr] = (addr, total, len(scored))
                    self.pairs[src_addr] = addr
                    gained += 1
            if not gained:
                break
        return resolved

    def match(self, src_addr, use_neighbors=True):
        key = (src_addr, use_neighbors)
        if key in self.memo:
            return self.memo[key]
        if src_addr not in self.s.feat:
            self.memo[key] = ('NO-FUNCTION', None, 0, 'source address is not a function start')
            return self.memo[key]
        cands = self._cands(src_addr)
        if not cands:
            self.memo[key] = ('NO-CANDIDATES', None, 0, 'no target function shares any feature')
            return self.memo[key]
        scored = []
        for c in cands:
            base = self.base_score(src_addr, c)
            nb = self.neighbors(src_addr, c) if use_neighbors else 0.0
            scored.append((base + self.args.neighbor_weight * nb, c, base, nb))
        scored.sort(key=lambda kv: (-kv[0], kv[1]))
        total, addr, base, nb = scored[0]
        runner = scored[1][0] if len(scored) > 1 else 0.0
        ev = f'score {total:.3f} (base {base:.3f}, graph {nb:.2f}), candidates {len(scored)}'
        if total >= self.args.min_score and (total - runner) >= self.args.margin:
            self.memo[key] = ('RESOLVED', addr, len(scored), ev)
        elif total >= self.args.min_score * 0.8:
            self.memo[key] = ('SHORTLIST', addr, len(scored), ev)
        else:
            self.memo[key] = ('NO-MATCH', None, len(scored), ev)
        return self.memo[key]


def resolve_code(name, value, matcher, results):
    hit = matcher.t.by_symbol.get(norm_name(name))
    if hit is not None:
        results[name] = ('RESOLVED', hit, 1, 'exact symbol name found in the target index')
        return
    results[name] = matcher.match(value, use_neighbors=name in matcher.resolved_names)


def resolve_field(name, src_off, source, tgt, matcher):
    accessors = sorted(source.field_accessors.get(src_off, ()))
    if not accessors:
        return ('NO-ACCESSOR', None, 0, f'no function in the source index touches 0x{src_off:x}')
    dedicated = [a for a in accessors if sum(source.feat[a]['fields'].values()) <= 4] or accessors
    dedicated = sorted(dedicated, key=lambda a: -(len(source.feat[a]['floats']) + len(source.feat[a]['consts'])))[:16]
    mapped, deltas = {}, collections.Counter()
    for a in dedicated:
        status, addr, *_ = matcher.match(a)
        if status != 'RESOLVED' or addr is None:
            continue
        mapped[a] = addr
        for f in tgt.feat.get(addr, {}).get('fields', {}):
            deltas[f - src_off] += 1
    if not mapped:
        return ('NO-ACCESSOR-MAPPED', None, len(accessors),
                f'{len(accessors)} source accessor(s), none transferred to the target index')
    delta, votes = deltas.most_common(1)[0]
    agree = sum(1 for _, c in deltas.items() if c == votes)
    direct = sum(1 for a, t in mapped.items() if src_off in tgt.feat.get(t, {}).get('fields', {}))
    if delta == 0:
        return ('RESOLVED' if direct else 'SHORTLIST', src_off, len(mapped),
                f'offset unchanged: {direct}/{len(mapped)} transferred accessor(s) still touch 0x{src_off:x}')
    status = 'RESOLVED' if agree == 1 and votes >= 2 else 'SHORTLIST'
    return (status, src_off + delta, len(mapped),
            f'layout shift {delta:+#x} voted by {votes}/{len(mapped)} transferred accessor(s)')


def resolve_name(name, tgt):
    key = norm_name(name)
    if key in tgt.by_symbol:
        return ('RESOLVED', tgt.by_symbol[key], 1, 'exact symbol name found in the target index')
    near = [k for k in tgt.by_symbol if key and (key in k or k in key)]
    if len(near) == 1:
        return ('RESOLVED', tgt.by_symbol[near[0]], 1, f'symbol name contains "{name}"')
    return ('NOT-FOUND', None, len(near), 'no symbol counterpart in the target index')


def main():
    args = parse_args()
    names = dict(parse_map(read_text(args.map_path)))
    if args.filter:
        names = {n: v for n, v in names.items() if args.filter.lower() in n.lower()}

    source = Build(args.source_index or args.index_dir)
    tgt = Build(args.index_dir)
    matcher = Matcher(source, tgt, args)
    matcher.resolved_names = set()

    fields_req = {n: v for n, v in names.items() if 0 < v < FIELD_LIMIT}
    code_req = {n: v for n, v in names.items() if v >= FIELD_LIMIT and source.in_code(v)}
    name_only = {n: v for n, v in names.items() if n not in fields_req and n not in code_req}

    results = {}
    for name, value in sorted(code_req.items()):
        resolve_code(name, value, matcher, results)
        if results[name][0] == 'RESOLVED' and results[name][1] is not None:
            matcher.pairs[value] = results[name][1]
            matcher.resolved_names.add(name)
    for name, value in sorted(code_req.items()):
        if results[name][0] != 'RESOLVED':
            results[name] = matcher.match(value, use_neighbors=True)

    pending = {v for n, v in code_req.items() if results[n][0] != 'RESOLVED'}
    if pending and args.rounds:
        gained = matcher.propagate(pending, args.rounds)
        for name, value in sorted(code_req.items()):
            if value in gained:
                addr, total, cands = gained[value]
                results[name] = ('RESOLVED', addr, cands,
                                 f'call-graph propagation score {total:.3f}')

    for name, value in sorted(fields_req.items()):
        results[name] = resolve_field(name, value, source, tgt, matcher)
    for name, value in sorted(name_only.items()):
        results[name] = resolve_name(name, tgt)

    counts = collections.Counter(status for status, *_ in results.values())

    lines = ['# Offset transfer (binary-free)', '',
             f'- map: {os.path.basename(args.map_path)} ({len(names)} entries)',
             f'- source index: {source.dir}',
             f'- target index: {tgt.dir}',
             f'- code entries: {len(code_req)} | field entries: {len(fields_req)} | name-only: {len(name_only)}',
             f'- acceptance: score >= {args.min_score}, margin >= {args.margin}, '
             f'graph weight {args.neighbor_weight}', '',
             '| name | source | status | target | evidence |', '|---|---|---|---|---|']
    for name in sorted(results):
        status, addr, cands, ev = results[name]
        tgt_s = f'0x{addr:x}' if isinstance(addr, int) else '-'
        lines.append(f'| {name} | 0x{names[name]:x} | {status} | {tgt_s} | {ev} (candidates {cands}) |')
    lines += ['', '## Totals', '']
    for status in sorted(counts, key=lambda s: (-counts[s], s)):
        lines.append(f'- {status}: {counts[status]}')
    lines.append(f'- **transferred: {counts.get("RESOLVED", 0)}/{len(names)}**')

    report = '\n'.join(lines)
    print('\n'.join(lines[:9]))
    if args.report:
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write(report + '\n')
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write('export const offsets = {\n')
            for name in sorted(results):
                status, addr, *_ = results[name]
                if status == 'RESOLVED' and isinstance(addr, int):
                    f.write(f'    "{name}": 0x{addr:x},\n')
            f.write('};\n')
    print(f'\ntransferred {counts.get("RESOLVED", 0)}/{len(names)}')


if __name__ == '__main__':
    main()
