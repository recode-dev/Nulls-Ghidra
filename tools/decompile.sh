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
STALL=${STALL:-600}

O=(-e scr.color=0 -e bin.relocs.apply=true -e r2ghidra.casts=true -e r2ghidra.linelen=200 -e r2ghidra.fixups=true)

kill_at() {
  local b=$1
  shift
  "$@" &
  local p=$!
  echo "$p" > .r2pid
  ( sleep "$b"; kill -INT "$p" 2>/dev/null; sleep 20; kill -9 "$p" 2>/dev/null ) >/dev/null 2>&1 &
  local w=$!
  wait "$p" 2>/dev/null
  local r=$?
  kill "$w" 2>/dev/null
  rm -f .r2pid
  return $r
}

[ -s "$BIN" ] || { echo "[-] missing $BIN"; exit 1; }

IMPORTS=${IMPORTS_OUT:-imports.json}
SYMBOLS=${SYMBOLS_OUT:-symbols.json}

AE=0
if [ -f .ae ]; then AE=$(cat .ae); fi

if [ "$PHASE" = all ] || [ "$PHASE" = analyze ]; then
  if [ -f "$PROJ" ]; then
    echo "project cached"
  else
    AM=$((BUDGET / 3))
    S=$(date +%s)
    kill_at "$AM" "$R2" "${O[@]}" -q -c aaa \
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

AFLJ=""
if [ -s "$PROJ" ] && command -v "$R2" >/dev/null 2>&1; then
  kill_at "${AFLJ_BUDGET:-300}" "$R2" "${O[@]}" -q -p "$PWD/$PROJ" -c aflj -c q "$BIN" > .aflj 2>> "$LOG" || true
  [ -s .aflj ] && AFLJ=.aflj
fi

python3 tools/imports.py --bin "$BIN" --out "$SYMBOLS" --map "$IMPORTS" --aflj "$AFLJ" 2>> "$LOG" \
  || { echo "[-] symbol export failed"; exit 1; }
[ "$PHASE" = names ] && exit 0

rm -f "$CODE" "$LOG" "$ENG"
: > "$LOG"

watch() {
  local b=$1 out=$2 i=0 mb n last
  while [ "$i" -lt "$b" ]; do
    sleep 60
    i=$((i + 60))
    mb=$(( $(wc -c < "$out" 2>/dev/null || echo 0) / 1048576 ))
    n=$(grep -c '^{$' "$out" 2>/dev/null || true)
    if [ "$mb" -eq 0 ]; then
      last=$(tail -1 "$LOG" 2>/dev/null | tr -d '\r' | cut -c1-140)
      echo "dump ${i}s 0MB r2: ${last:-silent}"
      if [ "$i" -ge "$STALL" ] && [ -s .r2pid ]; then
        echo "[-] no output for ${i}s, stopping r2"
        tail -20 "$LOG" 2>/dev/null
        touch .stall
        kill -INT "$(cat .r2pid)" 2>/dev/null
        sleep 10
        kill -9 "$(cat .r2pid)" 2>/dev/null
        return
      fi
    else
      echo "dump ${i}s ${mb}MB ${n:-0} funcs"
    fi
  done
}

dump() {
  local b=$1 c=$2 out=$3
  echo "dump start $c budget ${b}s"
  rm -f .stall
  watch "$b" "$out" &
  local w=$!
  kill_at "$b" "$R2" "${O[@]}" -q -p "$PWD/$PROJ" -c "$c" "$BIN" > "$out" 2>> "$LOG"
  local r=$?
  kill "$w" 2>/dev/null
  if [ -f .stall ]; then
    return 2
  fi
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
if [ "$RP" = 2 ] || [ "${NB:-0}" -eq 0 ]; then
  echo "[-] pdg produced no functions"
  tail -30 "$LOG" 2>/dev/null
  exit 1
fi
ENGINE=pdg
RC=none
MERGED=0
if [ "${NB:-0}" -lt 5 ]; then
  echo "pdg sparse -> pdc for the missing functions"
  dump "$FALL" 'pdc @@f' "$CODE.pdc"
  RC=$?
  COUNTS=$(python3 - "$CODE" "$CODE.pdc" <<'PY'
import re, sys

block = re.compile(r'(?m)^(?=[^\n]*\bfcn\.[0-9a-f]+\s*\()')
name = re.compile(r'fcn\.([0-9a-f]+)')


def blocks(path):
    text = open(path, encoding='utf-8', errors='ignore').read()
    starts = [match.start() for match in block.finditer(text)]
    rows = []
    for index, begin in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        body = text[begin:end]
        found = name.search(body)
        rows.append((found.group(1) if found else '', body))
    return rows


primary = blocks(sys.argv[1])
extra = blocks(sys.argv[2])
known = {key for key, _body in primary if key}
merged = list(primary)
added = 0
for key, body in extra:
    if key and key in known:
        continue
    merged.append((key, body))
    added += 1
with open(sys.argv[1], 'w', encoding='utf-8') as handle:
    for _key, body in merged:
        handle.write(body if body.endswith('\n') else body + '\n')
print(len(primary), len(extra), added)
PY
) || { echo "[-] pdc merge failed"; exit 1; }
  read -r KEPT DUMPED ADDED <<< "$COUNTS"
  MERGED=$ADDED
  rm -f "$CODE.pdc"
  echo "merge kept ${KEPT} pdg bodies, added ${ADDED} of ${DUMPED} pdc bodies"
  ENGINE=pdg+pdc
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
  echo "pdc_merged=$MERGED"
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
