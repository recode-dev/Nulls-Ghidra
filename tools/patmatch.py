#!/usr/bin/env python3
import argparse
import os
import re
import struct
import sys

PAT = re.compile(r"^- `(.+?)` — `([0-9a-fA-F]+)`\s*$", re.M)


def parse(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for n, h in PAT.findall(txt):
        try:
            out.append((n, bytes.fromhex(h)))
        except ValueError:
            pass
    return out


def starts_of(path):
    s = {}
    if not path:
        return s
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{6,}\b", line)
        if not m:
            continue
        try:
            s[int(m.group(0), 0)] = 1
        except ValueError:
            pass
    return s


def segs(data):
    out = []
    if data[:4] == b"\x7fELF":
        is64 = data[4] == 2
        if is64:
            phoff, = struct.unpack_from("<Q", data, 0x20)
            esz, n = struct.unpack_from("<HH", data, 0x36)
        else:
            phoff, = struct.unpack_from("<I", data, 0x1C)
            esz, n = struct.unpack_from("<HH", data, 0x2A)
        for i in range(n):
            o = phoff + i * esz
            if o + 32 > len(data):
                break
            if struct.unpack_from("<I", data, o)[0] != 1:
                continue
            if is64:
                f, v, sz = struct.unpack_from("<QQQ", data, o + 8)
            else:
                f, v, sz = struct.unpack_from("<III", data, o + 4)
            out.append((f, v, sz))
        return out
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:
        ncmd, = struct.unpack_from("<I", data, 16)
        p = 32
        for _ in range(ncmd):
            c, size = struct.unpack_from("<II", data, p)
            if c == 0x19:
                v, _vs, f, fsz = struct.unpack_from("<QQQQ", data, p + 24)
                out.append((f, v, fsz))
            p += size
        return out
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        n, = struct.unpack_from(">I", data, 4)
        for i in range(n):
            base = 8 + i * 20
            cputype, _st, off, size = struct.unpack_from(">IIII", data, base)
            if cputype == 0x0100000C:
                for f, v, sz in segs(data[off:off + size]):
                    out.append((off + f, v, sz))
                break
    return out


def va(seg, off):
    for f, v, sz in seg:
        if f <= off < f + sz:
            return v + (off - f)
    return None


def safe(name):
    s = name.split("(")[0].strip().replace("::", "__").replace("~", "_dtor_")
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    s = re.sub(r"_{2,}", "_", s).strip("_")
    if not s:
        s = "sub"
    if s[0].isdigit():
        s = "_" + s
    return s[:120]


def hits(data, needle):
    out = []
    i = 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            return out
        out.append(i)
        i += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("patterns")
    ap.add_argument("binary")
    ap.add_argument("--starts")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--emit-patterns")
    a = ap.parse_args()

    rows = parse(a.patterns)
    data = open(a.binary, "rb").read()
    seg = segs(data)
    starts = starts_of(a.starts)
    print("patterns %d starts %d" % (len(rows), len(starts)), file=sys.stderr)

    ok = []
    amb = []
    miss = []
    for name, pat in rows:
        offs = hits(data, pat)
        if not offs:
            miss.append(name)
            continue
        addrs = []
        for o in offs:
            x = va(seg, o) if seg else o
            if x is None:
                continue
            if starts and x not in starts:
                continue
            addrs.append(x)
        addrs = sorted(set(addrs))
        if len(addrs) == 1:
            ok.append((addrs[0], name, offs[0]))
        elif addrs:
            amb.append(name)
        else:
            miss.append(name)

    os.makedirs(a.out_dir, exist_ok=True)
    used = set()
    pairs = []
    for addr, name, _o in sorted(ok):
        nm = safe(name)
        while nm in used:
            nm += "_1"
        used.add(nm)
        pairs.append((addr, nm))

    with open(os.path.join(a.out_dir, "renames.r2"), "w", encoding="utf-8") as fh:
        for addr, nm in pairs:
            fh.write("f %s @ 0x%x\n" % (nm, addr))
            fh.write("afn %s @ 0x%x\n" % (nm, addr))

    java = ["import ghidra.app.script.GhidraScript;",
            "import ghidra.program.model.address.Address;",
            "import ghidra.program.model.listing.Function;",
            "import ghidra.program.model.symbol.SourceType;",
            "",
            "public class Rename extends GhidraScript {",
            "    private static final String[] N = new String[] {"]
    for addr, nm in pairs:
        java.append('        "%x:%s",' % (addr, nm))
    java += ["    };",
             "    public void run() throws Exception {",
             "        int ok = 0;",
             "        for (String e : N) {",
             "            int i = e.indexOf(':');",
             "            long a = Long.parseLong(e.substring(0, i), 16);",
             "            String n = e.substring(i + 1);",
             "            try {",
             "                Address ad = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);",
             "                Function f = currentProgram.getFunctionManager().getFunctionAt(ad);",
             "                if (f != null) { f.setName(n, SourceType.USER_DEFINED); }",
             "                else { currentProgram.getSymbolTable().createLabel(ad, n, SourceType.USER_DEFINED); }",
             "                ok++;",
             "            } catch (Exception x) { }",
             "        }",
             "        println(\"renamed \" + ok + \" of \" + N.length);",
             "    }",
             "}"]
    with open(os.path.join(a.out_dir, "Rename.java"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(java) + "\n")

    if a.emit_patterns:
        with open(a.emit_patterns, "w", encoding="utf-8") as fh:
            for addr, name, o in sorted(ok, key=lambda x: x[2]):
                chunk = data[o:o + 32]
                if len(chunk) >= 16:
                    fh.write("- `%s` — `%s`\n" % (name, chunk.hex()))

    with open(os.path.join(a.out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("total %d\n\nunique %d\n\nambiguous %d\n\nmissing %d\n\n" % (len(rows), len(ok), len(amb), len(miss)))
        fh.write("## ambiguous\n\n")
        for n in sorted(amb)[:400]:
            fh.write("- `%s`\n" % n)
        fh.write("\n## missing\n\n")
        for n in sorted(miss)[:400]:
            fh.write("- `%s`\n" % n)

    print("unique %d ambiguous %d missing %d" % (len(ok), len(amb), len(miss)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
