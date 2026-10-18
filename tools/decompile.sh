#!/usr/bin/env bash
set -uo pipefail

BIN=${BIN:-binary}
BUDGET=${BUDGET:-18000}
PHASE=${PHASE:-all}
PROJ=${R2PROJ:-r2proj}
CODE=${CODE_OUT:-decompiled.c}
ENG=${ENGINE_OUT:-engine.txt}
LOG=${R2_LOG:-r2.log}
R2=${R2BIN:-r2}

O=(-e scr.color=0 -e bin.relocs.apply=true -e r2ghidra.casts=true -e r2ghidra.linelen=200 -e r2ghidra.fixups=true)

kill_at() {
  local b=$1
  shift
  "$@" &
  local p=$!
  ( sleep "$b"; kill -INT "$p" 2>/dev/null; sleep 20; kill -9 "$p" 2>/dev/null ) >/dev/null 2>&1 &
  local w=$!
  wait "$p"
  local r=$?
  kill "$w" 2>/dev/null
  return $r
}

[ -s "$BIN" ] || { echo "[-] missing $BIN"; exit 1; }

IMPORTS=${IMPORTS_OUT:-imports.json}
NAMES=${NAMES_OUT:-names.r2}
SIGS=${SIG_DB:-}

"$R2" "${O[@]}" -q -c isj -c q "$BIN" > .isj 2>> "$LOG" || { echo "[-] isj export failed"; exit 1; }
python3 tools/binary.py --symbols "$BIN" > .syms.json 2>> "$LOG" || { echo "[-] chained fixups export failed"; exit 1; }
python3 - "$IMPORTS" "$NAMES" "$SIGS" <<'PY' || { echo "[-] symbol table build failed"; exit 1; }
import json, re, sys

rows = {k: v for k, v in json.load(open('.syms.json')).items() if isinstance(v, int)}
raw = open('.isj', errors='ignore').read()
syms = json.loads(raw[raw.index('['):raw.rindex(']') + 1])
for s in syms:
    name = s.get('name') or ''
    addr = s.get('vaddr') or 0
    if name.startswith('sym.imp.') and addr:
        name = name[8:].lstrip('_')
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', name):
            rows.setdefault(name, addr)
if sys.argv[3]:
    rows.update({k: v for k, v in json.load(open(sys.argv[3])).items() if isinstance(v, int)})
json.dump(rows, open(sys.argv[1], 'w'))
with open(sys.argv[2], 'w') as f:
    for name, addr in rows.items():
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,180}', name):
            f.write(f'af {name} @ {addr}; afn {name} @ {addr}\n')
print(f'symbols {len(rows)}')
PY

NI=()
[ -s "$NAMES" ] && NI=(-i "$PWD/$NAMES")

AE=0
if [ -f .ae ]; then AE=$(cat .ae); fi

if [ "$PHASE" = all ] || [ "$PHASE" = analyze ]; then
  if [ -f "$PROJ" ]; then
    echo "project cached"
  else
    AM=$((BUDGET / 3))
    S=$(date +%s)
    kill_at "$AM" "$R2" "${O[@]}" "${NI[@]}" -q -c aaa \
      -c "Ps $PWD/$PROJ" "$BIN" > analyze.log 2>&1
    AE=$(( $(date +%s) - S ))
    echo "$AE" > .ae
    echo "analyze ${AE}s"
    if [ ! -f "$PROJ" ]; then
      tail -20 analyze.log 2>/dev/null
      echo "[-] project save failed"
      exit 1
    fi
  fi
fi
[ "$PHASE" = analyze ] && exit 0

rm -f "$CODE" "$LOG" "$ENG"
: > "$LOG"

watch() {
  local b=$1 out=$2 i=0 mb n
  while [ "$i" -lt "$b" ]; do
    sleep 60
    i=$((i + 60))
    mb=$(( $(wc -c < "$out" 2>/dev/null || echo 0) / 1048576 ))
    n=$(grep -c '^{$' "$out" 2>/dev/null || echo 0)
    echo "dump ${i}s ${mb}MB ${n:-0} funcs"
  done
}

dump() {
  local b=$1 c=$2 out=$3
  echo "dump start $c budget ${b}s"
  watch "$b" "$out" &
  local w=$!
  kill_at "$b" "$R2" "${O[@]}" "${NI[@]}" -q -p "$PWD/$PROJ" -c "$c" "$BIN" > "$out" 2>> "$LOG"
  local r=$?
  kill "$w" 2>/dev/null
  return $r
}

REST=$((BUDGET - AE))
[ "$REST" -lt 300 ] && REST=300
MAIN=$((REST * 4 / 5))
FALL=$((REST - MAIN))

S=$(date +%s)
dump "$MAIN" 'pdg @@f' "$CODE"
RP=$?
NB=$(grep -c '^{$' "$CODE" 2>/dev/null || true)
ENGINE=pdg
RC=none
if [ "${NB:-0}" -lt 5 ]; then
  ENGINE=pdc
  echo "pdg empty -> pdc"
  dump "$FALL" 'pdc @@f' "$CODE"
  RC=$?
fi
EL=$(( $(date +%s) - S ))

TRIM=$(python3 - "$CODE" <<'PY'
import sys

path = sys.argv[1]
text = open(path, encoding='utf-8', errors='ignore').read()
start = text.rfind('\n{\n')
if start < 0:
    print(0)
    raise SystemExit
depth = 0
index = start + 1
quote = ''
while index < len(text):
    char = text[index]
    if quote:
        if char == '\\':
            index += 2
            continue
        if char == quote:
            quote = ''
    elif char in '"\'':
        quote = char
    elif char == '{':
        depth += 1
    elif char == '}':
        depth -= 1
    index += 1
if depth > 0:
    gap = text.rfind('\n\n', 0, start)
    header = text[gap + 2:start].strip() if gap >= 0 else ''
    cut = gap + 1 if header and '\n' not in header else start
    open(path, 'w', encoding='utf-8').write(text[:cut])
    print(1)
else:
    print(0)
PY
) || { echo "[-] decompiled.c is not readable"; exit 1; }

{
  echo "engine=$ENGINE"
  echo "pdg_rc=$RP"
  echo "pdc_rc=$RC"
  echo "pdg_bodies=${NB:-0}"
  echo "truncated=$TRIM"
  echo "r2=${R2V:-?}"
  echo "budget=$BUDGET"
  echo "analyze_s=$AE"
  echo "pdg_budget_s=$MAIN"
  echo "pdc_budget_s=$FALL"
  echo "dump_s=$EL"
  echo "bin=$(basename "$BIN")"
  echo "bin_bytes=$(wc -c < "$BIN" | tr -d ' ')"
  echo "code_bytes=$(wc -c < "$CODE" | tr -d ' ')"
  echo "code_lines=$(wc -l < "$CODE" | tr -d ' ')"
} > "$ENG"
cat "$ENG"
