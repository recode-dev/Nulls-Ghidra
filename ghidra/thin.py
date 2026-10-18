#!/usr/bin/env python3
import struct
import sys

FAT32 = 0xcafebabe
FAT64 = 0xcafebabf
ARM64 = 0x0100000c


def main():
    if len(sys.argv) < 3:
        raise SystemExit('usage: thin.py <in> <out>')
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, 'rb') as handle:
        data = handle.read()
    if len(data) < 8:
        raise SystemExit('[-] too small')
    magic = struct.unpack('>I', data[:4])[0]
    if magic not in (FAT32, FAT64):
        with open(dst, 'wb') as handle:
            handle.write(data)
        print(f'[+] thin copy {len(data)} bytes')
        return
    wide = magic == FAT64
    count = struct.unpack('>I', data[4:8])[0]
    step = 32 if wide else 20
    chosen = None
    for index in range(count):
        pos = 8 + index * step
        if pos + step > len(data):
            break
        cpu = struct.unpack('>I', data[pos:pos + 4])[0]
        if wide:
            off, size = struct.unpack('>QQ', data[pos + 8:pos + 24])
        else:
            off, size = struct.unpack('>II', data[pos + 8:pos + 16])
        if cpu == ARM64 and chosen is None:
            chosen = (off, size)
    if chosen is None:
        raise SystemExit('[-] no arm64 slice')
    off, size = chosen
    if off + size > len(data):
        raise SystemExit('[-] slice out of bounds')
    with open(dst, 'wb') as handle:
        handle.write(data[off:off + size])
    print(f'[+] thin arm64 slice {size} bytes')


if __name__ == '__main__':
    main()
