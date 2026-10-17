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

[ -s "$BIN" ] || { echo "missing $BIN"; exit 1; }

IMPORTS=${IMPORTS_OUT:-imports.json}
NAMES=${NAMES_OUT:-names.r2}
SIGS=${SIG_DB:-}

"$R2" "${O[@]}" -q -c isj -c q "$BIN" > .isj 2>/dev/null || : > .isj
python3 - "$IMPORTS" "$NAMES" "$SIGS" <<'PY'
import json, re, sys
rows = {}
try:
    raw = open('.isj', errors='ignore').read()
    syms = json.loads(raw[raw.index('['):raw.rindex(']') + 1])
except Exception:
    syms = []
for s in syms:
    name = s.get('name') or ''
    addr = s.get('vaddr') or 0
    if name.startswith('sym.imp.') and addr:
        name = name[8:].lstrip('_')
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', name):
            rows[name] = addr
if sys.argv[3]:
    try:
        rows.update({k: v for k, v in json.load(open(sys.argv[3])).items() if isinstance(v, int)})
    except Exception as exc:
        print(f'sig db skipped: {exc}')
json.dump(rows, open(sys.argv[1], 'w'))
with open(sys.argv[2], 'w') as f:
    for name, addr in rows.items():
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
  if [ "${R2_GHIDRA:-1}" = 0 ] && [ "$c" = 'pdg @@f' ]; then return 1; fi
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
ENV_ENG=pdg
RC=none
if [ "${NB:-0}" -lt 5 ]; then
  ENV_ENG=pdc
  echo "pdg empty -> pdc"
  dump "$FALL" 'pdc @@f' "$CODE"
  RC=$?
fi
EL=$(( $(date +%s) - S ))

{
  echo "engine=$ENV_ENG"
  echo "pdg_rc=$RP"
  echo "pdc_rc=$RC"
  echo "pdg_bodies=${NB:-0}"
  echo "r2=${R2V:-?}"
  echo "plugin=${R2_GHIDRA:-?}"
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
