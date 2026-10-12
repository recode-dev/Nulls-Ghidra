#!/usr/bin/env python3
"""Переносит имена функций из файла паттернов на другой бинарь.

Паттерны берутся в формате `- `Имя` — `hex`` (первые байты функции).
Адреса не используются: имя ставится там, где нашлись эти байты.

Запуск:
  python3 apply_patterns.py v36_patterns.md target.so --out-dir out
  python3 apply_patterns.py v36_patterns.md target.so --starts starts.txt --out-dir out

starts.txt — список адресов начал функций (по одному в строке, hex или dec),
например из `r2 -q -c 'aaa' -c 'afl~[0]' target.so` или `nm`.
Если он есть, совпадения вне начал функций отбрасываются.

--emit-patterns FILE пишет паттерны, снятые уже с целевого бинаря по найденным
адресам: их можно положить в symbols/<версия>/patterns.md и дальше матчиться
без угадывания.

На выходе в out-dir:
  renames.r2       команды для radare2: afn <имя> @ 0x<адрес>
  ApplyPatternNames.java  скрипт для Ghidra (Script Manager / -postScript)
  report.md        статистика + список неоднозначных/ненайденных
"""

import argparse
import collections
import os
import re
import struct
import sys

ISO = re.compile(r"^- `(.+?)` — `([0-9a-fA-F]+)`\s*$", re.M)


def parse_patterns(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for name, hexs in ISO.findall(text):
        try:
            out.append((name, bytes.fromhex(hexs)))
        except ValueError:
            pass
    return out


def parse_starts(path):
    addrs = {}
    if not path:
        return addrs
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{6,}\b", line)
        if not m:
            continue
        try:
            addrs[int(m.group(0), 0)] = True
        except ValueError:
            pass
    return addrs


def segments(data):
    segs = []
    if data[:4] == b"\x7fELF":
        is64 = data[4] == 2
        if is64:
            phoff, = struct.unpack_from("<Q", data, 0x20)
            entsize, n = struct.unpack_from("<HH", data, 0x36)
        else:
            phoff, = struct.unpack_from("<I", data, 0x1C)
            entsize, n = struct.unpack_from("<HH", data, 0x2A)
        for i in range(n):
            off = phoff + i * entsize
            if off + 32 > len(data):
                break
            if struct.unpack_from("<I", data, off)[0] != 1:
                continue
            if is64:
                f, v, sz = struct.unpack_from("<QQQ", data, off + 8)
            else:
                f, v, sz = struct.unpack_from("<III", data, off + 4)
            segs.append((f, v, sz))
        return segs
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (0xFEEDFACF, 0xFEEDFACE):
        off = 4 if magic == 0xFEEDFACF else 4  # только 64-битные thin-бинарники
        if magic != 0xFEEDFACF:
            return segs
        ncmds, = struct.unpack_from("<I", data, 16)
        p = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", data, p)
            if cmd == 0x19:
                v, sz, f, fsz = struct.unpack_from("<QQQQ", data, p + 24)
                segs.append((f, v, fsz))
            p += size
        return segs
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        n, = struct.unpack_from(">I", data, 4)
        for i in range(n):
            base = 8 + i * 20
            cputype, _, off, size = struct.unpack_from(">IIII", data, base)
            if cputype == 0x0100000C:
                sub = data[off:off + size]
                for f, v, sz in segments(sub):
                    segs.append((off + f, v, sz))
                break
        return segs
    return segs


def off_to_addr(segs, off):
    for f, v, sz in segs:
        if f <= off < f + sz:
            return v + (off - f)
    return None


def safe_name(name):
    base = name.split("(")[0].strip()
    base = base.replace("::", "__").replace("~", "_dtor_").replace(" ", "_")
    base = re.sub(r"[^A-Za-z0-9_]", "_", base)
    base = re.sub(r"_{2,}", "_", base).strip("_")
    if not base:
        base = "sub"
    if base[0].isdigit():
        base = "_" + base
    return base[:120]


def find_all(data, needle):
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("patterns")
    ap.add_argument("binary")
    ap.add_argument("--starts")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--min-len", type=int, default=0)
    ap.add_argument("--emit-patterns", dest="emit_patterns")
    args = ap.parse_args()

    rows = parse_patterns(args.patterns)
    data = open(args.binary, "rb").read()
    segs = segments(data)
    starts = parse_starts(args.starts)
    print(f"паттернов: {len(rows)}, бинарь: {len(data)} байт, "
          f"сегментов: {len(segs)}, начал функций: {len(starts)}", file=sys.stderr)

    if args.min_len:
        rows = [(n, p) for n, p in rows if len(p) >= args.min_len]

    ok, ambiguous, missing, outside = [], [], [], []

    for name, pat in rows:
        offs = find_all(data, pat)
        if not offs:
            missing.append(name)
            continue
        addrs = []
        for off in offs:
            a = off_to_addr(segs, off) if segs else off
            if a is None:
                continue
            if starts and a not in starts:
                if not addrs:
                    outside.append(name)
                continue
            addrs.append(a)
        addrs = sorted(set(addrs))
        if len(addrs) == 1:
            ok.append((addrs[0], name, offs[0]))
        elif len(addrs) > 1:
            ambiguous.append((name, addrs))
        else:
            missing.append(name)

    os.makedirs(args.out_dir, exist_ok=True)
    used = set()
    pairs = []
    for addr, name, _off in sorted(ok):
        nm = safe_name(name)
        while nm in used:
            nm += "_1"
        used.add(nm)
        pairs.append((addr, nm))

    with open(os.path.join(args.out_dir, "renames.r2"), "w", encoding="utf-8") as fh:
        for addr, nm in pairs:
            fh.write(f"f {nm} @ 0x{addr:x}\n")
            fh.write(f"afn {nm} @ 0x{addr:x}\n")

    java = [
        "import ghidra.app.script.GhidraScript;",
        "import ghidra.program.model.address.Address;",
        "import ghidra.program.model.listing.Function;",
        "import ghidra.program.model.symbol.SourceType;",
        "",
        "public class ApplyPatternNames extends GhidraScript {",
        "",
        "    private static final String[] RENAMES = new String[] {",
    ]
    for addr, nm in pairs:
        java.append(f'        "{addr:x}:{nm}",')
    java += [
        "    };",
        "",
        "    @Override",
        "    public void run() throws Exception {",
        "        int applied = 0;",
        "        int skipped = 0;",
        "        for (String entry : RENAMES) {",
        "            int sep = entry.indexOf(':');",
        "            long addr = Long.parseLong(entry.substring(0, sep), 16);",
        "            String name = entry.substring(sep + 1);",
        "            try {",
        "                Address a = currentProgram.getAddressFactory()",
        "                        .getDefaultAddressSpace().getAddress(addr);",
        "                Function f = currentProgram.getFunctionManager().getFunctionAt(a);",
        "                if (f != null) {",
        "                    f.setName(name, SourceType.USER_DEFINED);",
        "                }",
        "                else {",
        "                    currentProgram.getSymbolTable().createLabel(a, name,",
        "                            SourceType.USER_DEFINED);",
        "                }",
        "                applied++;",
        "            }",
        "            catch (Exception e) {",
        "                skipped++;",
        "            }",
        "        }",
        "        println(\"applied \" + applied + \" of \" + RENAMES.length",
        "                + \", skipped \" + skipped);",
        "    }",
        "}",
    ]
    with open(os.path.join(args.out_dir, "ApplyPatternNames.java"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(java) + "\n")

    if args.emit_patterns:
        with open(args.emit_patterns, "w", encoding="utf-8") as fh:
            fh.write("# паттерны, снятые с целевого бинаря\n\n")
            for addr, name, off in sorted(ok, key=lambda x: x[2]):
                chunk = data[off:off + 32]
                if len(chunk) < 16:
                    continue
                fh.write(f"- `{name}` — `{chunk.hex()}`\n")
        print(f"паттерны целевого бинаря: {args.emit_patterns}", file=sys.stderr)

    total = len(rows)
    with open(os.path.join(args.out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("# Пренос имён по паттернам\n\n")
        fh.write(f"- паттернов в файле: {total}\n")
        fh.write(f"- однозначно найдено: {len(ok)}\n")
        fh.write(f"- неоднозначно (несколько мест): {len(ambiguous)}\n")
        fh.write(f"- не найдено: {len(missing)}\n")
        fh.write(f"- найдено только вне начал функций: {len(outside)}\n")
        fh.write(f"- ABI-догадка: {'ELF(32/64)' if data[:4] == b'\\x7fELF' else 'Mach-O'}\n")
        fh.write("\n## Неоднозначные\n\n")
        for name, addrs in sorted(ambiguous)[:400]:
            fh.write(f"- `{name}` — {', '.join('0x%x' % a for a in addrs[:6])}"
                     f"{' …' if len(addrs) > 6 else ''}\n")
        fh.write("\n## Не найдены (первые 400)\n\n")
        for name in sorted(missing)[:400]:
            fh.write(f"- `{name}`\n")
        fh.write("\n## Найдены только не на старте функции (первые 200)\n\n")
        for name in sorted(outside)[:200]:
            fh.write(f"- `{name}`\n")

    print(f"однозначно: {len(ok)}, неоднозначно: {len(ambiguous)}, "
          f"не найдено: {len(missing)}, вне начал функций: {len(outside)}")
    print(f"готово: {args.out_dir}/renames.r2, ApplyPatternNames.java, report.md")


if __name__ == "__main__":
    main()
