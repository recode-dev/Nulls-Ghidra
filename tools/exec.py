#!/usr/bin/env python3

import argparse
import struct
import sys
import urllib.request
import zlib

UA = {'User-Agent': 'curl/8'}


def head(url, start, end):
    request = urllib.request.Request(url, headers=dict(UA, Range='bytes=%d-%d' % (start, end)))
    with urllib.request.urlopen(request, timeout=180) as f:
        return f.read()


def content_size(url):
    request = urllib.request.Request(url, headers=dict(UA, Range='bytes=0-0'))
    with urllib.request.urlopen(request, timeout=60) as f:
        length = f.headers.get('Content-Range')
    if not length or '/' not in length:
        return 0
    return int(length.split('/')[-1])


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
            data = z64(cd[p + 46 + nlen:p + 46 + nlen + elen])
            values = list(struct.unpack_from('<%dQ' % (len(data) // 8), data, 0))
            order = [key for key, value in (('usz', usz), ('csz', csz), ('lho', lho))
                     if value == 0xFFFFFFFF]
            if len(values) < len(order):
                sys.exit(f'[-] zip64 extra truncated for {name}')
            for key, value in zip(order, values):
                if key == 'usz':
                    usz = value
                elif key == 'csz':
                    csz = value
                else:
                    lho = value
        rows.append((name, lho, csz, usz))
        p += 46 + nlen + elen + clen
    if not rows:
        sys.exit('[-] empty central directory')
    if want:
        hit = [row for row in rows if row[0].endswith(want)]
        if hit:
            return hit[0]
    binaries = [row for row in rows if row[0].endswith(suffix) and '/Frameworks/' not in row[0]]
    if binaries:
        return max(binaries, key=lambda row: row[3])
    return max(rows, key=lambda row: row[3])


def main():
    ap = argparse.ArgumentParser(description='Extract one entry from a remote zip over HTTP ranges')
    ap.add_argument('--url', required=True, help='direct link to the archive')
    ap.add_argument('--size', type=int, default=0, help='archive size, probed with a range request when omitted')
    ap.add_argument('--entry', default='', help='exact suffix of the entry to extract')
    ap.add_argument('--out', required=True, help='path for the extracted file')
    args = ap.parse_args()

    size = args.size or content_size(args.url)
    if not size:
        sys.exit('[-] server does not report the archive size, pass --size')
    print(f'archive {args.url} ({size} bytes)')

    tail = head(args.url, max(0, size - 131072), size - 1)
    index = tail.rfind(b'PK\x05\x06')
    if index < 0:
        sys.exit('[-] end of central directory not found')
    cd_size, cd_off = struct.unpack_from('<II', tail, index + 12)
    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        sys.exit('[-] zip64 central directory not supported')

    cd = head(args.url, cd_off, cd_off + cd_size - 1)
    name, lho, csz, usz = pick(cd, args.entry, '.app')
    print(f'entry {name} csz={csz} usz={usz} lho={lho}')

    header = head(args.url, lho, lho + 29)
    nlen, elen = struct.unpack_from('<HH', header, 26)
    if nlen:
        header = head(args.url, lho, lho + 29 + nlen)
    method, = struct.unpack_from('<H', header, 8)
    offset = lho + 30 + nlen + elen
    raw = head(args.url, offset, offset + csz - 1)
    data = zlib.decompress(raw, -15) if method == 8 else raw
    if len(data) != usz:
        sys.exit(f'[-] short read {len(data)} != {usz}')

    with open(args.out, 'wb') as f:
        f.write(data)
    print(f'[+] {args.out} {len(data)} bytes')


if __name__ == '__main__':
    main()
