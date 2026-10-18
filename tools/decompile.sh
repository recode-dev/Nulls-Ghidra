#!/usr/bin/env bash
set -uo pipefail

BIN=${BIN:-binary}
BUDGET=${BUDGET:-18000}
PHASE=${PHASE:-all}
CODE=${CODE_OUT:-decompiled.c}
ENG=${ENGINE_OUT:-engine.txt}
LOG=${R2_LOG:-r2.log}
RAW=${RAW_OUT:-r2.out}
AFLJ=${AFLJ_OUT:-.aflj}
R2=${R2BIN:-r2}
STALL=${STALL:-900}

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

watch() {
  local b=$1 i=0 bytes prev=-1 idle=0 n last
  while [ "$i" -lt "$b" ]; do
    sleep 60
    i=$((i + 60))
    bytes=$(wc -c < "$RAW" 2>/dev/null || echo 0)
    n=$(grep -c '^{$' "$RAW" 2>/dev/null || true)
    last=$(tail -1 "$LOG" 2>/dev/null | tr -d '\r' | cut -c1-80)
    marks=$(grep -c '@@AFLJ@@\|@@DUMP@@' "$RAW" 2>/dev/null || true)
    echo "dump ${i}s $((bytes / 1048576))MB ${n:-0} funcs marks=${marks:-0} ${last:+| $last}"
    if [ "$bytes" -eq "$prev" ]; then
      idle=$((idle + 60))
    else
      idle=0
    fi
    prev=$bytes
    if [ "$idle" -ge "$STALL" ] && [ -s .r2pid ]; then
      echo "[-] no output for ${idle}s, stopping r2"
      tail -20 "$LOG" 2>/dev/null
      touch .stall
      kill -INT "$(cat .r2pid)" 2>/dev/null
      sleep 10
      kill -9 "$(cat .r2pid)" 2>/dev/null
      return
    fi
  done
}

session() {
  local b=$1 cmd=$2
  echo "session $cmd budget ${b}s"
  rm -f .stall "$RAW"
  watch "$b" &
  local w=$!
  if [ "$cmd" = names ]; then
    kill_at "$b" "$R2" "${O[@]}" -q -c aaa -c '?e @@AFLJ@@' -c aflj "$BIN" > "$RAW" 2>> "$LOG"
  else
    kill_at "$b" "$R2" "${O[@]}" -q -c aaa -c '?e @@AFLJ@@' -c aflj \
      -c '?e @@DUMP@@' -c "$cmd" "$BIN" > "$RAW" 2>> "$LOG"
  fi
  local r=$?
  kill "$w" 2>/dev/null
  [ -f .stall ] && return 2
  return $r
}

split_raw() {
  python3 - "$RAW" "$1" "$2" <<'PY'
import sys

raw = open(sys.argv[1], encoding='utf-8', errors='ignore').read()
_head, _sep, rest = raw.partition('@@AFLJ@@')
aflj, _mark, code = rest.partition('@@DUMP@@')
open(sys.argv[3], 'w', encoding='utf-8').write(aflj.strip())
open(sys.argv[2], 'w', encoding='utf-8').write(code)
PY
}

[ -s "$BIN" ] || { echo "[-] missing $BIN"; exit 1; }

IMPORTS=${IMPORTS_OUT:-imports.json}
SYMBOLS=${SYMBOLS_OUT:-symbols.json}

rm -f "$CODE" "$ENG" "$LOG" "$AFLJ" "$RAW"
: > "$LOG"

S=$(date +%s)
session "$BUDGET" "$([ "$PHASE" = names ] && echo names || echo 'pdg @@f')"
RP=$?

if [ "$PHASE" = names ]; then
  split_raw /dev/null "$AFLJ"
  python3 tools/imports.py --bin "$BIN" --out "$SYMBOLS" --map "$IMPORTS" --aflj "$AFLJ" 2>> "$LOG" \
    || { echo "[-] symbol export failed"; exit 1; }
  exit 0
fi

split_raw "$CODE" "$AFLJ"
python3 tools/imports.py --bin "$BIN" --out "$SYMBOLS" --map "$IMPORTS" --aflj "$AFLJ" 2>> "$LOG" \
  || { echo "[-] symbol export failed"; exit 1; }

NB=$(grep -c '^{$' "$CODE" 2>/dev/null || true)
if [ "$RP" = 2 ] || [ "${NB:-0}" -eq 0 ]; then
  echo "[-] pdg produced no functions"
  tail -30 "$LOG" 2>/dev/null
  exit 1
fi

ENGINE=pdg
RC=none
MERGED=0
FALL=$((BUDGET / 5))
[ "$FALL" -lt 300 ] && FALL=300
if [ "${NB:-0}" -lt 5 ]; then
  echo "pdg sparse -> pdc for the missing functions"
  session "$FALL" 'pdc @@f'
  RC=$?
  split_raw "$CODE.pdc" /dev/null
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
  echo "pdc_budget_s=$FALL"
  echo "dump_s=$EL"
  echo "bin=$(basename "$BIN")"
  echo "bin_bytes=$(wc -c < "$BIN" | tr -d ' ')"
  echo "code_bytes=$(wc -c < "$CODE" | tr -d ' ')"
  echo "code_lines=$(wc -l < "$CODE" | tr -d ' ')"
} > "$ENG"
cat "$ENG"
