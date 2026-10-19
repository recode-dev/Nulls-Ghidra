#!/usr/bin/env python3
"""Blind cross-version porter: seed from evidence, grow the map by structural votes.

Global feature scoring cannot identify a function across a large version jump:
code generation, inlining and struct layout all drift, so every absolute feature
value moves.  What does not drift is the graph.  This tool therefore never ranks
the whole target image.  It builds seed pairs from hard evidence and grows the
mapping outward along call edges and vtable slots.

Seed evidence:
  1. demangled DWARF names of the source build (symbols.json);
  2. `Class::method` fragments inside target strings, credited to the code that
     references them (strings_xref_bin.json from blgraph.py).

Growth evidence, aggregated per round:
  * a source callee and a target callee under an already mapped pair vote for
    each other; same for callers, with a small weight for caller/callee crosses;
  * two vtables that already share mapped slots vote for every slot-aligned pair.

A candidate is accepted when its vote total clears --min-votes, beats its own
runner-up by --vote-margin, still looks plausible by profile (--min-profile), and
no other source votes for that target harder.

Outputs into the target index directory:
  pairs.json      source rva -> target rva, with method of derivation
  autoname.json   target rva -> proposed name, with evidence
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys

CLASS_METHOD = re.compile(r'\b([A-Z][A-Za-z0-9_]{2,48})::([A-Za-z_~][A-Za-z0-9_]{2,48})')


def parse_args():
    p = argparse.ArgumentParser(description='Port names and offsets between builds without hints')
    p.add_argument('--source', required=True, help='old index directory (with symbols)')
    p.add_argument('--target', required=True, help='new index directory')
    p.add_argument('--pairs', default='', help='write accepted pairs here, default <target>/pairs.json')
    p.add_argument('--autoname', default='', help='write names here, default <target>/autoname.json')
    p.add_argument('--eval', default='', help='json of known pairs to score the run against')
    p.add_argument('--seed', default='', help='extra seed pairs as json {old_rva: new_rva}')
    p.add_argument('--rounds', type=int, default=10, help='voting rounds over the graph')
    p.add_argument('--min-votes', type=float, default=0.30,
                   help='structural support to accept (votes are degree-normalised)')
    p.add_argument('--min-support', type=int, default=2,
                   help='independent mapped anchors that must vote for a pair')
    p.add_argument('--vote-margin', type=float, default=0.35,
                   help='required relative gap over the runner-up candidate')
    p.add_argument('--min-profile', type=float, default=0.20, help='minimum feature similarity')
    p.add_argument('--pw-source', type=int, default=0, help='pointer width of the source build (0=auto)')
    p.add_argument('--pw-target', type=int, default=0, help='pointer width of the target build (0=auto)')
    p.add_argument('--shortlist', action='store_true',
                   help='also rank target candidates for the asked functions and write shortlist.json')
    p.add_argument('--ask', default='', help='source names to shortlist, comma separated')
    p.add_argument('--top', type=int, default=5, help='shortlist depth')
    p.add_argument('--limit', type=int, default=400, help='targets kept after the cheap prefilter')
    p.add_argument('--wt-callee', type=float, default=1.0, help='weight of a callee/callee vote')
    p.add_argument('--wt-caller', type=float, default=0.8, help='weight of a caller/caller vote')
    p.add_argument('--wt-cross', type=float, default=0.2, help='weight of a caller/callee vote')
    p.add_argument('--wt-vtable', type=float, default=1.4, help='weight of a vtable slot vote')
    p.add_argument('--min-table-anchors', type=int, default=2,
                   help='mapped slots two tables must share before they vote')
    p.add_argument('--gap', type=float, default=-0.35, help='vtable alignment gap penalty')
    p.add_argument('--band', type=int, default=12, help='vtable alignment band width')
    p.add_argument('--max-tables', type=int, default=200, help='vtable pairs aligned per pass')
    p.add_argument('--max-pairs', type=int, default=3000,
                   help='cap on mapped pairs before the vote rounds stop')
    p.add_argument('--no-vtables', action='store_true', help='disable the vtable expansion stage')
    p.add_argument('--max-prod', type=int, default=25000,
                   help='skip a neighbour cross-product larger than this')
    p.add_argument('--quiet', action='store_true')
    return p.parse_args()


def load(path, name, default):
    full = os.path.join(path, name)
    if not os.path.exists(full):
        return default
    with open(full, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def to_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


def profile(entry, out, inn, pw=1):
    """Feature vector.  `pw` is the pointer width of the build: raw struct offsets
    are useless across a 32/64 bit jump, but offset/pw (the field's ordinal slot in
    the object) and the gaps between used fields survive it."""
    if not entry:
        return None
    fields = sorted(set(entry.get('field_offsets') or []))
    return {
        'bytes': entry.get('size_bytes') or 0,
        'chars': entry.get('size_chars') or 0,
        'loops': entry.get('loops') or 0,
        'branches': entry.get('branches') or 0,
        'switches': entry.get('switches') or 0,
        'args': entry.get('args') or 0,
        'out': len(out),
        'in': len(inn),
        'floats': set(entry.get('floats') or []),
        'consts': set(entry.get('consts') or []),
        'fields': set(fields),
        'words': {o // pw for o in fields},
        'rel': {(b - a) // pw for a, b in zip(fields, fields[1:])},
        'vcalls': set(entry.get('vcall_slots') or []),
    }


def jaccard(left, right):
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def ratio(left, right):
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return min(left, right) / max(left, right)


def deltas(values):
    ordered = sorted(values)
    return {b - a for a, b in zip(ordered, ordered[1:])}


def similarity(a, b):
    """Weighted mean over informative terms.

    An absent feature on both sides must not score: otherwise every pair of tiny
    functions collects free credit from floats/consts/vcalls and outranks a real
    match.  Terms that are empty on both sides are dropped and the weights of the
    remaining terms are renormalised.
    """
    if not a or not b:
        return 0.0
    cfg = [ratio(a[k], b[k]) for k in ('loops', 'branches', 'switches') if a[k] or b[k]]
    terms = [
        (0.16, ratio(a['bytes'], b['bytes'])) if a['bytes'] or b['bytes'] else None,
        (0.10, ratio(a['chars'], b['chars'])) if a['chars'] or b['chars'] else None,
        (0.14, sum(cfg) / len(cfg)) if cfg else None,
        (0.18, (ratio(a['out'], b['out']) + ratio(a['in'], b['in'])) / 2)
        if a['out'] or b['out'] or a['in'] or b['in'] else None,
        (0.10, jaccard(a['floats'], b['floats'])) if a['floats'] or b['floats'] else None,
        (0.06, jaccard(a['consts'], b['consts'])) if a['consts'] or b['consts'] else None,
        (0.12, jaccard(a['words'], b['words'])) if a['words'] or b['words'] else None,
        (0.08, jaccard(a['rel'], b['rel'])) if a['rel'] or b['rel'] else None,
        (0.12, jaccard(a['vcalls'], b['vcalls'])) if a['vcalls'] or b['vcalls'] else None,
    ]
    terms = [t for t in terms if t]
    if not terms:
        return 0.0
    total = sum(w * s for w, s in terms)
    return total / sum(w for w, _ in terms)


def guess_pw(functions, vtables):
    """Pointer width of a build: a Mach-O arm64 index carries addresses above 4G."""
    for key in list(vtables or {}) + list(functions or {}):
        value = to_int(key)
        if value and value > 0xFFFFFFFF:
            return 8
    entry = next(iter((functions or {}).values()), {})
    offsets = entry.get('field_offsets') or []
    if offsets and all(o % 8 == 0 for o in offsets):
        return 8
    return 4


def demangle(names):
    if not names:
        return {}
    payload = '\n'.join(names)
    try:
        done = subprocess.run(['c++filt'], input=payload, capture_output=True, text=True, check=True)
    except Exception:
        return {}
    return dict(zip(names, done.stdout.splitlines()))


def source_names(symbols, functions):
    """Map rva -> readable Class::method for the build that still has symbols."""
    raw = symbols.get('symbols') if isinstance(symbols, dict) else symbols
    raw = raw or {}
    mangled = [name for name in raw if name.startswith('_Z')]
    plain = demangle(mangled)
    by_rva = {}
    for name, value in raw.items():
        address = to_int(value)
        if address is None:
            continue
        key = f'0x{address:x}'
        entry = functions.get(key)
        if not entry:
            continue
        label = plain.get(name)
        if label:
            label = label.split('(')[0].strip()
        elif not name.startswith('_Z'):
            label = name
        else:
            continue
        if label:
            by_rva.setdefault(key, label)
    return by_rva


def target_names(strings_xref, functions, out, inn):
    """Propose rva -> Class::method from strings that mention it."""
    by_name = {}
    for text, owners in strings_xref.items():
        found = CLASS_METHOD.findall(text)
        if not found:
            continue
        for owner in owners:
            if owner not in functions:
                continue
            for cls, method in found:
                by_name.setdefault(owner, []).append((cls, method, text))
    result = {}
    for rva, hits in by_name.items():
        methods = {}
        for cls, method, text in hits:
            methods.setdefault((cls, method), []).append(text)
        (cls, method), best = max(methods.items(), key=lambda item: len(item[1]))
        result[rva] = {'name': f'{cls}::{method}', 'evidence': best[0][:120],
                       'ambiguous': len(methods) > 1}
    return result


def invert(edges):
    inv = {}
    for caller, callees in edges.items():
        for callee in callees:
            inv.setdefault(callee, []).append(caller)
    return inv


def table_slots(vtables, functions):
    """table rva -> {slot index: function rva}, keeping only real function slots."""
    by_table = {}
    for addr, entry in (vtables or {}).items():
        methods = entry.get('methods') or []
        kept = {}
        for position, target in enumerate(methods):
            if isinstance(target, dict):
                target = target.get('address') or target.get('target')
            if isinstance(target, str) and target in functions:
                kept[position] = target
        if kept:
            by_table[addr] = kept
    return by_table


def slot_membership(by_table):
    """function rva -> [(table rva, slot index), ...]"""
    out = {}
    for table, slots in by_table.items():
        for position, func in slots.items():
            out.setdefault(func, []).append((table, position))
    return out


def prefilter(a, pool, limit):
    """Cheap size/degree envelope so a shortlist does not rescore the whole image."""
    keep = []
    for key, b in pool.items():
        if not b:
            continue
        rb = b['bytes'] / a['bytes'] if a['bytes'] else (1.0 if not b['bytes'] else 0.0)
        if not 0.3 <= rb <= 3.2:
            continue
        ro = b['out'] / a['out'] if a['out'] else (1.0 if not b['out'] else 0.0)
        if not 0.2 <= ro <= 5.0:
            continue
        keep.append((key, b, rb, ro))
    if len(keep) > limit:
        keep.sort(key=lambda item: (abs(math.log2(item[2] or 0.5)) + abs(math.log2(item[3] or 0.5))))
        keep = keep[:limit]
    return keep


def write_shortlist(args, sfn, tfn, sname, tname, sprof, tprof, pairs):
    """Ranked candidates per requested function: propose, never claim."""
    wanted = [w.strip() for w in args.ask.split(',') if w.strip()]
    by_label = {}
    for rva, label in sname.items():
        by_label.setdefault(label, []).append(rva)
    sources = []
    for want in wanted:
        for rva in by_label.get(want, []):
            sources.append((rva, want))
    for rva in wanted:
        if rva in sfn:
            sources.append((rva, sname.get(rva, rva)))
    if args.eval:
        with open(args.eval, 'r', encoding='utf-8') as handle:
            for rva in json.load(handle):
                if rva in sfn:
                    sources.append((rva, sname.get(rva, rva)))
    if not sources:
        print('[!] --shortlist needs --ask names (or --eval sources); skipping')
        return
    payload = {}
    for rva, want in sources:
        a = sprof.get(rva)
        if not a:
            continue
        got = pairs.get(rva)
        order = []
        for key, b, _, _ in prefilter(a, tprof, args.limit):
            order.append((similarity(a, b), key))
        order.sort(reverse=True)
        top = [{'target': k, 'score': round(sc, 3), 'named': tname.get(k, {}).get('name')}
               for sc, k in order[:args.top]]
        rank = next((i + 1 for i, (_, k) in enumerate(order) if k == got), None)
        payload[f'{want} @ {rva}'] = {'paired': got, 'rank_of_pair': rank, 'candidates': top}
        print(f'    {want} @ {rva}: ' +
              ', '.join(f'{c["target"]}({c["score"]})' for c in top[:args.top]) +
              (f' | mapped={got} rank={rank}' if got else ' | unmapped'))
    path = os.path.join(args.target, 'shortlist.json')
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, indent=1, ensure_ascii=False)
    print(f'[+] -> {path}')


def main():
    args = parse_args()
    sfn = load(args.source, 'functions.json', {})
    tfn = load(args.target, 'functions.json', {})
    if not sfn or not tfn:
        raise SystemExit('[-] functions.json missing in one of the indexes')
    sedges = load(args.source, 'callgraph_bin.json', {}) or load(args.source, 'callgraph.json', {})
    tedges = load(args.target, 'callgraph_bin.json', {}) or load(args.target, 'callgraph.json', {})
    if not sedges or not tedges:
        raise SystemExit('[-] run blgraph.py first: callgraph_bin.json is required for propagation')
    sinv, tinv = invert(sedges), invert(tedges)

    sname = source_names(load(args.source, 'symbols.json', {}), sfn)
    txref = load(args.target, 'strings_xref_bin.json', {}) or load(args.target, 'strings_xref.json', {})
    tname = target_names(txref, tfn, tedges, tinv)

    s_tab = table_slots(load(args.source, 'vtables.json', {}), sfn)
    t_tab = table_slots(load(args.target, 'vtables.json', {}), tfn)
    s_slot, t_slot = slot_membership(s_tab), slot_membership(t_tab)

    spw = args.pw_source or guess_pw(sfn, load(args.source, 'vtables.json', {}))
    tpw = args.pw_target or guess_pw(tfn, load(args.target, 'vtables.json', {}))
    sprof = {k: profile(v, sedges.get(k) or {}, sinv.get(k) or [], spw) for k, v in sfn.items()}
    tprof = {k: profile(v, tedges.get(k) or {}, tinv.get(k) or [], tpw) for k, v in tfn.items()}
    if not args.quiet:
        print(f'[i] names s={len(sname)} t={len(tname)} vtables s={len(s_tab)} t={len(t_tab)} '
              f'ptr {spw}->{tpw} bit')

    pairs, how, used = {}, {}, set()

    def accept(source, target, method, score=1.0):
        if source in pairs or target in used:
            return False
        pairs[source] = target
        used.add(target)
        how[source] = {'method': method, 'score': round(score, 3)}
        return True

    # ---- seeds: target functions named by their own strings, matched to a DWARF symbol
    by_label = {}
    for rva, label in sname.items():
        by_label.setdefault(label, []).append(rva)
    for rva, info in tname.items():
        holders = by_label.get(info['name']) or []
        if len(holders) == 1 and not info['ambiguous']:
            accept(holders[0], rva, 'string-seed')

    if args.seed:
        with open(args.seed, 'r', encoding='utf-8') as handle:
            for source, target in json.load(handle).items():
                accept(source, target, 'given-seed')

    # ---- one anchor inside a class is enough to port the class: methods of a C++
    # class keep their relative vtable order across versions, so the two tables can
    # be aligned slot by slot even when inserts and removals shifted the indexes.
    # ---- grow the mapping by aggregated structural votes
    for round_no in range(1, max(1, args.rounds) + 1):
        if len(pairs) >= args.max_pairs:
            if not args.quiet:
                print(f'[!] pair budget {args.max_pairs} reached, stopping propagation')
            break
        cand, support = {}, {}

        def add(source, target, weight, anchor):
            if weight <= 0 or source in pairs or target in used or source == target:
                return
            bucket = cand.setdefault(source, {})
            bucket[target] = bucket.get(target, 0.0) + weight
            seen = support.setdefault((source, target), set())
            if anchor:
                seen.add(anchor)

        for index, (ps, pt) in enumerate(sorted(pairs.items())):
            outs_s, outs_t = sedges.get(ps) or {}, tedges.get(pt) or {}
            ins_s, ins_t = sinv.get(ps) or [], tinv.get(pt) or []
            # a hub sprays its vote over hundreds of pairs, so its contribution per
            # pair is scaled down by the size of the cross product it produces
            for group_s, group_t, base in ((outs_s, outs_t, args.wt_callee),
                                           (ins_s, ins_t, args.wt_caller),
                                           (ins_s, outs_t, args.wt_cross),
                                           (outs_s, ins_t, args.wt_cross)):
                if not group_s or not group_t or len(group_s) * len(group_t) > args.max_prod:
                    continue
                weight = base / (1.0 + math.log2(max(len(group_s) * len(group_t), 2) / 2.0))
                for u in group_s:
                    for v in group_t:
                        add(u, v, weight, index)

        tables = {}
        for ps, pt in pairs.items():
            for stable, si_ in s_slot.get(ps, ()):
                for ttable, tj in t_slot.get(pt, ()):
                    tables.setdefault((stable, ttable), []).append((si_, tj))
        for (stable, ttable), anchors in tables.items():
            if len(anchors) < args.min_table_anchors:
                continue
            slots_s, slots_t = s_tab.get(stable, {}), t_tab.get(ttable, {})
            for si_, tj in anchors:
                for position, source in slots_s.items():
                    target = slots_t.get(tj + position - si_)
                    if target:
                        add(source, target, args.wt_vtable, None)

        ranked = []
        for source, votes in cand.items():
            order = sorted(votes.items(), key=lambda item: (-item[1], item[0]))
            target, weight = order[0]
            if weight < args.min_votes:
                continue
            if len(support[(source, target)]) < args.min_support:
                continue
            if weight - (order[1][1] if len(order) > 1 else 0.0) < args.vote_margin * weight:
                continue
            psim = similarity(sprof.get(source), tprof.get(target))
            if psim < args.min_profile:
                continue
            ranked.append((weight, psim, source, target))

        # a target claimed by several sources at the same strength is not evidence
        claim = {}
        for weight, _, source, target in ranked:
            claim.setdefault(target, []).append((weight, source))
        clear = {target: picks[0][1] for target, picks in claim.items()
                 if len({src for w, src in picks if w == picks[0][0]}) == 1}

        grew = 0
        for weight, psim, source, target in sorted(ranked, key=lambda item: (item[0], item[1]),
                                                   reverse=True):
            if clear.get(target) != source:
                continue
            if accept(source, target, 'graph-vote', weight + psim):
                grew += 1
        if not args.quiet:
            print(f'[.] round {round_no}: pool={len(cand)} eligible={len(ranked)} '
                  f'accepted={grew} total={len(pairs)}')
        if not grew:
            break

    done_tables = set()

    def expand_tables():
        best = {}
        for ps, pt in pairs.items():
            for stable, si_ in s_slot.get(ps, ()):
                for ttable, tj in t_slot.get(pt, ()):
                    best.setdefault((stable, ttable), []).append((si_, tj))
        grew = 0
        # tables whose anchors agree on one pairing are the useful ones; process the
        # richest pairs first and stop at a hard budget so the stage stays tractable
        ordered = sorted(best.items(), key=lambda item: len(item[1]), reverse=True)
        for (stable, ttable), anchors in ordered[:args.max_tables]:
            if (stable, ttable) in done_tables:
                continue
            done_tables.add((stable, ttable))
            slots_s = [f for _, f in sorted(s_tab.get(stable, {}).items())]
            slots_t = [f for _, f in sorted(t_tab.get(ttable, {}).items())]
            if len(slots_s) < 2 or len(slots_t) < 2:
                continue
            if not 0.5 <= len(slots_t) / len(slots_s) <= 2.0:
                continue
            # banded Needleman-Wunsch: virtual method order is preserved, so only a
            # diagonal band around the proportional position can ever be real
            ratio_t = len(slots_t) / len(slots_s)
            neg = -1e9
            rows = [[neg] * (len(slots_t) + 1) for _ in range(len(slots_s) + 1)]
            back = [[0] * (len(slots_t) + 1) for _ in range(len(slots_s) + 1)]
            for i in range(len(slots_s) + 1):
                rows[i][0] = i * args.gap
            for j in range(len(slots_t) + 1):
                rows[0][j] = j * args.gap
            for i in range(1, len(slots_s) + 1):
                centre = i * ratio_t
                lo = max(1, int(centre - args.band))
                hi = min(len(slots_t), int(centre + args.band) + 1)
                source = slots_s[i - 1]
                prof_s = sprof.get(source)
                for j in range(lo, hi + 1):
                    best_score, move = neg, 0
                    if rows[i - 1][j - 1] > neg / 2:
                        best_score = rows[i - 1][j - 1] + similarity(prof_s, tprof.get(slots_t[j - 1]))
                        move = 0
                    if rows[i - 1][j] > neg / 2 and rows[i - 1][j] + args.gap > best_score:
                        best_score, move = rows[i - 1][j] + args.gap, 1
                    if rows[i][j - 1] > neg / 2 and rows[i][j - 1] + args.gap > best_score:
                        best_score, move = rows[i][j - 1] + args.gap, 2
                    if best_score > neg / 2:
                        rows[i][j], back[i][j] = best_score, move
            i, j = len(slots_s), len(slots_t)
            while i > 0 and j > 0:
                if rows[i][j] <= neg / 2:          # fell outside the band, walk back
                    i -= 1
                    continue
                move = back[i][j]
                if move == 0:
                    source, target = slots_s[i - 1], slots_t[j - 1]
                    psim = similarity(sprof.get(source), tprof.get(target))
                    if (source not in pairs and target not in used and psim >= args.min_profile):
                        if accept(source, target, 'vtable-align', psim):
                            grew += 1
                    i, j = i - 1, j - 1
                elif move == 1:
                    i -= 1
                else:
                    j -= 1
        return grew

    if not args.no_vtables:
        for _ in range(3):
            if not expand_tables():
                break

    if args.shortlist:
        write_shortlist(args, sfn, tfn, sname, tname, sprof, tprof, pairs)

    out_pairs = args.pairs or os.path.join(args.target, 'pairs.json')
    out_names = args.autoname or os.path.join(args.target, 'autoname.json')
    with open(out_pairs, 'w', encoding='utf-8') as handle:
        json.dump({k: {'target': v, **how[k]} for k, v in pairs.items()}, handle, indent=1,
                  ensure_ascii=False)
    named = {}
    for source, target in pairs.items():
        label = sname.get(source)
        if label:
            named[target] = {'name': label, 'source': source, 'method': how[source]['method']}
    with open(out_names, 'w', encoding='utf-8') as handle:
        json.dump(named, handle, indent=1, ensure_ascii=False)

    if not args.quiet:
        counted = {}
        for info in how.values():
            counted[info['method']] = counted.get(info['method'], 0) + 1
        print(f'[+] pairs={len(pairs)} named={len(named)} by={counted} '
              f'source_funcs={len(sfn)} target_funcs={len(tfn)}')
        print(f'[+] -> {out_pairs}, {out_names}')

    if args.eval:
        with open(args.eval, 'r', encoding='utf-8') as handle:
            truth = json.load(handle)
        hit1 = hit_any = miss = 0
        for source, wanted in truth.items():
            got = pairs.get(source)
            if got == wanted:
                hit1 += 1
            elif got:
                hit_any += 1
            else:
                miss += 1
            status = 'OK' if got == wanted else (f'wrong->{got}' if got else 'not found')
            print(f'    {sname.get(source, source):48s} {status}')
        total = len(truth)
        print(f'[=] eval exact={hit1}/{total} wrong={hit_any}/{total} missing={miss}/{total}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
