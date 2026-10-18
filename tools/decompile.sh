#!/usr/bin/env bash
set -uo pipefail

BIN=${BIN:-binary}
BUDGET=${BUDGET:-18000}
PHASE=${PHASE:-all}
CODE=${CODE_OUT:-decompiled.c}
ENG=${ENGINE_OUT:-engine.txt}
LOG=${GHIDRA_LOG:-ghidra.log}
AFLJ=${AFLJ_OUT:-.aflj}
THIN=${THIN_OUT:-binary.thin}
GHIDRA_HOME=${GHIDRA_HOME:-$HOME/ghidra}
HEADLESS=$GHIDRA_HOME/support/analyzeHeadless
SCRIPTS=$(cd "$(dirname "$0")/.." && pwd)/ghidra
PROJ=${PROJECT_DIR:-$PWD/.ghidra_project}
IMPORTS=${IMPORTS_OUT:-imports.json}
SYMBOLS=${SYMBOLS_OUT:-symbols.json}
export MAXMEM=${MAXMEM:-8G}

[ -s "$BIN" ] || { echo "[-] missing $BIN"; exit 1; }
[ -x "$HEADLESS" ] || { echo "[-] missing $HEADLESS"; exit 1; }
[ -f "$SCRIPTS/Dump.java" ] || { echo "[-] missing $SCRIPTS/Dump.java"; exit 1; }

MODE=all
[ "$PHASE" = names ] && MODE=names

rm -f "$LOG" "$AFLJ" "$ENG" "$THIN"
[ "$MODE" = all ] && rm -f "$CODE"
: > "$LOG"

python3 "$SCRIPTS/thin.py" "$BIN" "$THIN" || { echo "[-] thin failed"; exit 1; }

S=$(date +%s)
timeout -s INT --kill-after=60 "$BUDGET" "$HEADLESS" \
  "$PROJ" ng \
  -import "$THIN" \
  -scriptPath "$SCRIPTS" \
  -postScript Dump.java "$CODE" "$AFLJ" "$MODE" \
  -analysisTimeoutPerFile "$BUDGET" \
  -deleteProject >> "$LOG" 2>&1
RC=$?
EL=$(( $(date +%s) - S ))
echo "headless rc=$RC ${EL}s mode=$MODE"
tail -5 "$LOG" 2>/dev/null

python3 tools/imports.py --bin "$BIN" --out "$SYMBOLS" --map "$IMPORTS" --aflj "$AFLJ" 2>> "$LOG" \
  || { echo "[-] symbol export failed"; exit 1; }

[ "$MODE" = names ] && exit 0

NB=$(grep -c '^{$' "$CODE" 2>/dev/null || true)
if [ "${NB:-0}" -eq 0 ]; then
  echo "[-] ghidra produced no functions"
  tail -30 "$LOG" 2>/dev/null
  exit 1
fi

GV=$(grep -m1 '^application.version=' "$GHIDRA_HOME/Ghidra/application.properties" 2>/dev/null | cut -d= -f2)

{
  echo "engine=ghidra"
  echo "headless_rc=$RC"
  echo "bodies=${NB:-0}"
  echo "ghidra=${GV:-?}"
  echo "budget=$BUDGET"
  echo "dump_s=$EL"
  echo "bin=$(basename "$BIN")"
  echo "bin_bytes=$(wc -c < "$BIN" | tr -d ' ')"
  echo "code_bytes=$(wc -c < "$CODE" | tr -d ' ')"
  echo "code_lines=$(wc -l < "$CODE" | tr -d ' ')"
} > "$ENG"
cat "$ENG"
