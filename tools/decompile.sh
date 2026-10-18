#!/usr/bin/env bash
set -uo pipefail

BIN=${BIN:-binary}
BUDGET=${BUDGET:-18000}
PHASE=${PHASE:-all}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}
CODE=${CODE_OUT:-decompiled.c}
ENG=${ENGINE_OUT:-engine.txt}
LOG=${GHIDRA_LOG:-ghidra.log}
FUNCS=${FUNCS_OUT:-index_data/funcs.json}
NAMES=${NAMES_OUT:-names.tsv}
THIN=${THIN_OUT:-binary.thin}
GHIDRA_HOME=${GHIDRA_HOME:-$HOME/ghidra}
HEADLESS=$GHIDRA_HOME/support/analyzeHeadless
SCRIPTS=$(cd "$(dirname "$0")/.." && pwd)/ghidra
PROJ=${PROJECT_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ghidra_ng_project}
IMPORTS=${IMPORTS_OUT:-index_data/imports.json}
SYMBOLS=${SYMBOLS_OUT:-index_data/symbols.json}
export MAXMEM=${MAXMEM:-8G}
SHARD_MEM=${SHARD_MAXMEM:-3G}

[ "$JOBS" -ge 1 ] 2>/dev/null || JOBS=1

[ -s "$BIN" ] || { echo "[-] missing $BIN"; exit 1; }
[ -f "$SCRIPTS/Dump.java" ] || { echo "[-] missing $SCRIPTS/Dump.java"; exit 1; }

mkdir -p index_data
rm -f "$LOG"
: > "$LOG"

python3 "$SCRIPTS/thin.py" "$BIN" "$THIN" || { echo "[-] thin failed"; exit 1; }

python3 tools/imports.py --bin "$BIN" --out "$SYMBOLS" --map "$IMPORTS" --names "$NAMES" 2>> "$LOG" \
  || { echo "[-] symbol export failed"; exit 1; }

[ "$PHASE" = names ] && exit 0

[ -x "$HEADLESS" ] || { echo "[-] missing $HEADLESS"; exit 1; }

rm -f "$FUNCS" "$ENG" "$CODE" "$CODE".part*
rm -rf "$PROJ" "$PROJ".shard*

mkdir -p "$PROJ"

S=$(date +%s)
timeout -s INT --kill-after=60 "$BUDGET" "$HEADLESS" \
  "$PROJ" ng \
  -import "$THIN" \
  -scriptPath "$SCRIPTS" \
  -preScript Dump.java pre \
  -postScript Dump.java names "$PWD/$CODE" "$PWD/$FUNCS" "$PWD/$NAMES" \
  -analysisTimeoutPerFile "$BUDGET" >> "$LOG" 2>&1
RC=$?
ANAL=$(( $(date +%s) - S ))
echo "analysis rc=$RC ${ANAL}s"

TOTAL=$(python3 - "$FUNCS" <<'PY'
import json
import sys

try:
    print(len(json.load(open(sys.argv[1], encoding='utf-8'))))
except Exception:
    print(0)
PY
)

if [ "${TOTAL:-0}" -le 0 ]; then
  echo "[-] no functions"
  tail -30 "$LOG" 2>/dev/null
  exit 1
fi

PROG=$(basename "$THIN")
S=$(date +%s)
PIDS=()

for k in $(seq 0 $((JOBS - 1))); do
  A=$(( TOTAL * k / JOBS ))
  B=$(( TOTAL * (k + 1) / JOBS ))
  [ "$B" -le "$A" ] && continue
  cp -R "$PROJ" "$PROJ.shard$k" 2>/dev/null
  (
    MAXMEM=$SHARD_MEM timeout -s INT --kill-after=60 "$BUDGET" "$HEADLESS" \
      "$PROJ.shard$k" ng \
      -process "$PROG" \
      -noanalysis \
      -scriptPath "$SCRIPTS" \
      -postScript Dump.java shard "$PWD/$CODE.part$k" "$PWD/$FUNCS" "$PWD/$NAMES" "$A" "$B" \
      > "$LOG.shard$k" 2>&1
    echo $? > "$PWD/.shard$k.rc"
  ) &
  PIDS+=("$!")
done

for pid in "${PIDS[@]}"; do
  wait "$pid"
done

FAILED=0
for k in $(seq 0 $((JOBS - 1))); do
  [ -f "$CODE.part$k" ] || continue
  [ -s "$CODE.part$k" ] || { FAILED=1; continue; }
  rc=$(cat "$PWD/.shard$k.rc" 2>/dev/null || echo 1)
  [ "$rc" = 0 ] || FAILED=$rc
done

if [ "$FAILED" != 0 ]; then
  echo "[-] shard failed, retry sequentially"
  for k in $(seq 0 $((JOBS - 1))); do
    A=$(( TOTAL * k / JOBS ))
    B=$(( TOTAL * (k + 1) / JOBS ))
    [ "$B" -le "$A" ] && continue
    rc=$(cat "$PWD/.shard$k.rc" 2>/dev/null || echo 1)
    [ "$rc" = 0 ] && [ -s "$CODE.part$k" ] && continue
    echo "retry shard $k"
    MAXMEM=$SHARD_MEM timeout -s INT --kill-after=60 "$BUDGET" "$HEADLESS" \
      "$PROJ.shard$k" ng \
      -process "$PROG" \
      -noanalysis \
      -scriptPath "$SCRIPTS" \
      -postScript Dump.java shard "$PWD/$CODE.part$k" "$PWD/$FUNCS" "$PWD/$NAMES" "$A" "$B" \
      >> "$LOG" 2>&1
    rc=$?
    [ "$rc" = 0 ] && [ -s "$CODE.part$k" ] || { echo "[-] shard $k failed rc=$rc"; tail -20 "$LOG"; exit 1; }
  done
fi

: > "$CODE"
for k in $(seq 0 $((JOBS - 1))); do
  [ -s "$CODE.part$k" ] && cat "$CODE.part$k" >> "$CODE"
done

DUMP=$(( $(date +%s) - S ))
NB=$(grep -c '^{$' "$CODE" 2>/dev/null || true)

rm -f "$CODE".part* .shard*.rc
rm -rf "$PROJ" "$PROJ".shard*

if [ "${NB:-0}" -eq 0 ]; then
  echo "[-] ghidra produced no functions"
  tail -30 "$LOG" 2>/dev/null
  exit 1
fi

GV=$(grep -m1 '^application.version=' "$GHIDRA_HOME/Ghidra/application.properties" 2>/dev/null | cut -d= -f2)

{
  echo "engine=ghidra"
  echo "analysis_rc=$RC"
  echo "shards=$JOBS"
  echo "functions=$TOTAL"
  echo "bodies=${NB:-0}"
  echo "ghidra=${GV:-?}"
  echo "budget=$BUDGET"
  echo "analysis_s=$ANAL"
  echo "dump_s=$DUMP"
  echo "bin=$(basename "$BIN")"
  echo "bin_bytes=$(wc -c < "$BIN" | tr -d ' ')"
  echo "code_bytes=$(wc -c < "$CODE" | tr -d ' ')"
  echo "code_lines=$(wc -l < "$CODE" | tr -d ' ')"
} > "$ENG"
cat "$ENG"
