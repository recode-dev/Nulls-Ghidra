#!/usr/bin/env python3
import argparse
import csv
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import offsig


def open_in(path):
    return gzip.open(path, 'rt') if path.endswith('.gz') else open(path)


def load(path):
    with open_in(path) as f:
        d = json.load(f)
    intern = {t: i for i, t in enumerate(d['intern'])}
    entries = []
    for e in d['entries']:
        entries.append((e.get('id') or e['name'], e['name'], int(e['rva'], 16),
                        e.get('head', 0), tuple(e['span'])))
    return d['k'], d['ext'], d.get('version', ''), intern, entries


def starts_of(path):
    if not path:
        return None
    with open_in(path) as f:
        return set(json.load(f)['starts'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--patterns', required=True)
    ap.add_argument('--starts')
    ap.add_argument('--out', default='resolved.csv')
    ap.add_argument('--report')
    ap.add_argument('--require')
    ap.add_argument('--min-rate', type=float, default=0.0)
    ap.add_argument('--slide', type=int, default=0)
    a = ap.parse_args()

    k, ext, ver, intern, entries = load(a.patterns)
    img = offsig.Img(a.bin)
    code = offsig.Code(img, offsig.mdcs(), intern=intern)
    starts = starts_of(a.starts)

    primary = {}
    for eid, name, rva, head, span in entries:
        primary.setdefault(offsig.win_hash(span[:k]), []).append((eid, 0, span[:k]))
    found = code.scan(primary, k)

    res = {}
    for eid, name, rva, head, span in entries:
        cs = found.get(eid)
        if not cs:
            res[eid] = (rva, None, 0, 'missing')
            continue
        want = span[:ext] if len(span) >= ext else None
        targets = sorted({a for _, _, a in cs})
        if len(targets) > 1 and want is not None:
            keep = [t for t in targets if code.window(t, ext, ext)[0] == want]
            if keep:
                targets = keep
        if len(targets) > 1 and starts:
            keep = [t for t in targets if t - head in starts]
            if keep:
                targets = keep
        if len(targets) == 1:
            t = targets[0]
            verified = want is None or code.window(t, ext, ext)[0] == want
            res[eid] = (rva, t - head, (t - head) - rva, 'matched' if verified else 'weak')
        else:
            res[eid] = (rva, [t - head for t in targets], 0, 'ambiguous')

    res = offsig.resolve(res)
    names = {eid: name for eid, name, _r, _h, _s in entries}

    with open(a.out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['id', 'name', 'seed_rva', 'new_rva', 'drift', 'status'])
        for eid, v in sorted(res.items()):
            w.writerow([eid, names.get(eid, ''), hex(v[0]),
                        hex(v[1]) if isinstance(v[1], int) else '', v[2], v[3]])

    counts = {}
    for v in res.values():
        counts[v[3]] = counts.get(v[3], 0) + 1
    good = counts.get('matched', 0) + counts.get('weak', 0)
    rate = good / max(1, len(res))
    print('bin=%s patterns=%s (%s) entries=%d' % (a.bin, a.patterns, ver, len(res)))
    print(' '.join('%s=%d' % (n, counts[n]) for n in sorted(counts)))
    print('rate=%.4f (matched+weak) -> %s' % (rate, a.out))

    if a.report:
        with open(a.report, 'w') as f:
            f.write('# resolve `%s` against `%s`\n\n' % (ver, os.path.basename(a.bin)))
            f.write('| status | count |\n|---|---|\n')
            for n in sorted(counts):
                f.write('| %s | %d |\n' % (n, counts[n]))
            f.write('\n**rate %.4f** of %d entries\n' % (rate, len(res)))
            for st in ('ambiguous', 'missing'):
                lst = sorted(eid for eid, v in res.items() if v[3] == st)
                f.write('\n## %s (%d)\n\n' % (st, len(lst)))
                for eid in lst[:500]:
                    f.write('- `%s`\n' % eid)

    fail = []
    if a.require and not os.path.exists(a.require):
        print('require list %s not found, skipped' % a.require)
    elif a.require:
        want = [l.strip() for l in open(a.require) if l.strip() and not l.startswith('#')]
        for n in want:
            v = res.get(n)
            if v is None:
                hit = [eid for eid, nm, _r, _h, _s in entries if nm == n]
                v = res.get(hit[0]) if hit else None
            if v is None or v[3] not in ('matched', 'weak'):
                fail.append(n)
        if fail:
            print('required anchors lost: %d' % len(fail))
            for n in fail[:20]:
                print('  %s' % n)
    if a.min_rate and rate < a.min_rate:
        fail.append('rate %.4f < %.4f' % (rate, a.min_rate))
    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
