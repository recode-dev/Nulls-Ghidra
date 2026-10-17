#!/usr/bin/env python3
import argparse
import json
import os
import struct
import sys
import urllib.parse
import urllib.request
import zlib

UA = {'User-Agent': 'curl/8'}
META = 'https://archive.org/metadata/%s'
NODE = 'https://%s/%s/%s'


def head(url, a, b):
    r = urllib.request.Request(url, headers=dict(UA, Range='bytes=%d-%d' % (a, b)))
    with urllib.request.urlopen(r, timeout=180) as f:
        return f.read()


def item(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as f:
        return json.load(f)


def resolve(ident):
    d = item(META % ident)
    srv = (d.get('workable_servers') or [d['server']])[0]
    files = d['files']
    big = max((f for f in files if f['name'].lower().endswith(('.ipa', '.zip'))),
              key=lambda f: int(f.get('size', 1)))
    return (NODE % (srv, urllib.parse.quote(d['dir'].lstrip('/'), safe='/'),
                    urllib.parse.quote(big['name'], safe='')),
            int(big['size']), big['name'])


def z64(extra):
    p = 0
    while p + 4 <= len(extra):
        hid, hsz = struct.unpack_from('<HH', extra, p)
        if hid == 1:
            return extra[p + 4:p + 4 + hsz]
        p += 4 + hsz
    return b''


def pick(cd, want, suffix):
    p = 0
    rows = []
    while p + 46 <= len(cd) and cd[p:p + 4] == b'PK\x01\x02':
        csz, usz = struct.unpack_from('<II', cd, p + 20)
        nlen, elen, clen = struct.unpack_from('<HHH', cd, p + 28)
        lho, = struct.unpack_from('<I', cd, p + 42)
        name = cd[p + 46:p + 46 + nlen].decode('utf-8', 'replace')
        if 0xFFFFFFFF in (csz, usz, lho):
            d = z64(cd[p + 46 + nlen:p + 46 + nlen + elen])
            vals = list(struct.unpack_from('<%dQ' % (len(d) // 8), d, 0))
            order = [k for k, v in (('usz', usz), ('csz', csz), ('lho', lho)) if v == 0xFFFFFFFF]
            if len(vals) < len(order):
                sys.exit('zip64 extra truncated for %s' % name)
            for k, v in zip(order, vals):
                if k == 'usz':
                    usz = v
                elif k == 'csz':
                    csz = v
                else:
                    lho = v
        rows.append((name, lho, csz, usz))
        p += 46 + nlen + elen + clen
    if want:
        hit = [r for r in rows if r[0].endswith(want)]
        if hit:
            return hit[0]
    macho = [r for r in rows if r[0].endswith(suffix) and '/Frameworks/' not in r[0]]
    if macho:
        return max(macho, key=lambda r: r[3])
    return max(rows, key=lambda r: r[3])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--item')
    ap.add_argument('--url')
    ap.add_argument('--size', type=int, default=0)
    ap.add_argument('--entry', default='')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    if not a.item and not a.url:
        sys.exit('need --item or --url')

    if a.url:
        url, size, fname = a.url, a.size, os.path.basename(a.url)
        if not size:
            r = urllib.request.Request(url, headers=dict(UA, Range='bytes=0-0'))
            with urllib.request.urlopen(r, timeout=60) as f:
                size = int(f.headers['Content-Range'].split('/')[-1])
    else:
        url, size, fname = resolve(a.item)
    print('file %s (%d bytes)\nnode %s' % (fname, size, url))
    tail = head(url, max(0, size - 131072), size - 1)
    i = tail.rfind(b'PK\x05\x06')
    if i < 0:
        sys.exit('no EOCD')
    cd_size, cd_off = struct.unpack_from('<II', tail, i + 12)
    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        sys.exit('zip64 central directory not supported')
    cd = head(url, cd_off, cd_off + cd_size - 1)
    name, lho, csz, usz = pick(cd, a.entry, '.app')
    print('entry %s csz=%d usz=%d lho=%d' % (name, csz, usz, lho))
    hdr = head(url, lho, lho + 29)
    nlen, elen = struct.unpack_from('<HH', hdr, 26)
    if nlen:
        hdr = head(url, lho, lho + 29 + nlen)
    method, = struct.unpack_from('<H', hdr, 8)
    off = lho + 30 + nlen + elen
    data = head(url, off, off + csz - 1)
    raw = zlib.decompress(data, -15) if method == 8 else data
    if len(raw) != usz:
        sys.exit('short read %d != %d' % (len(raw), usz))
    open(a.out, 'wb').write(raw)
    print('wrote %s %d bytes %s' % (a.out, len(raw), raw[:4].hex()))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write('EXEC=%s\n' % a.out)


if __name__ == '__main__':
    main()
