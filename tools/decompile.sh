#!/usr/bin/env bash
set -uo pipefail

BIN="${BIN:-brawl_bin}"
BUDGET="${BUDGET:-18000}"
PHASE="${PHASE:-all}"
PROJ="${R2PROJ:-r2proj}"
CODE_OUT="${CODE_OUT:-decompiled.c}"
META_OUT="${META_OUT:-functions.json}"
ENGINE_OUT="${ENGINE_OUT:-engine.txt}"
R2="${R2BIN:-r2}"
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="${R2_LOG:-r2.log}"

R2OPTS=(
  -e scr.color=0
  -e bin.relocs.apply=true
  -e r2ghidra.casts=true
  -e r2ghidra.linelen=200
  -e r2ghidra.fixups=true
)

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

budget_kill() {
  local budget="$1"
  shift
  "$@" &
  local pid=$!
  ( sleep "$budget"; kill -INT "$pid" 2>/dev/null; sleep 20; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  local w=$!
  wait "$pid"
  local rc=$?
  kill "$w" 2>/dev/null
  return $rc
}

[ -s "$BIN" ] || { echo "нет бинаря: $BIN"; exit 1; }

ANALYZE_ELAPSED=0
if [ -f .analyze_elapsed ]; then
  ANALYZE_ELAPSED="$(cat .analyze_elapsed)"
fi

type_flags() {
  if [ -d types ]; then
    find types -name '*.h' | sort | while IFS= read -r h; do printf 'to %s\n' "$h"; done > types.r2
    while IFS= read -r line; do
      [ -n "$line" ] && R2OPTS+=(-c "$line")
    done < types.r2
    log "типов: $(grep -c . types.r2 || true)"
  fi
}

json_renames() {
  if [ -d symbols ] && [ -n "$(find symbols -name '*.json' | head -1)" ]; then
    python3 "$HERE/symbols_from_json.py" symbols "$BIN"
  fi
}

pattern_renames() {
  if [ ! -d patterns ]; then
    return 0
  fi
  local files
  files="$(find patterns -name '*.md' | sort)"
  [ -n "$files" ] || return 0
  printf '%s\n' "$files" | while IFS= read -r f; do cat "$f"; done > patterns_all.md
  log "паттернов из файлов: $(printf '%s\n' "$files" | wc -l | tr -d ' ')"
  if [ -f "$PROJ" ]; then
    "$R2" "${R2OPTS[@]}" -q -p "$PWD/$PROJ" -c 'afl~[0]' "$BIN" > starts.txt 2>/dev/null || true
  fi
  python3 "$HERE/apply_patterns.py" patterns_all.md "$BIN" \
    --starts starts.txt --out-dir out_patterns \
    --emit-patterns "out_patterns/patterns_new.md" 2>&1 | tail -3
  [ -f out_patterns/renames.r2 ] && cat out_patterns/renames.r2
  return 0
}

if [ "$PHASE" = "all" ] || [ "$PHASE" = "analyze" ]; then
  if [ -f "$PROJ" ]; then
    log "проект уже есть: $PROJ (анализ пропускаю)"
  else
    ANALYZE_MAX=$((BUDGET / 3))
    log "анализ (до ${ANALYZE_MAX}s) -> $PROJ"
    type_flags
    : > renames_pre.r2
    json_renames >> renames_pre.r2
    local_args=()
    if [ -s renames_pre.r2 ]; then
      local_args=(-i "$PWD/renames_pre.r2")
    fi
    START=$(date +%s)
    budget_kill "$ANALYZE_MAX" "$R2" "${R2OPTS[@]}" -q ${local_args[@]+"${local_args[@]}"} \
      -c 'aaa' -c "Ps $PWD/$PROJ" "$BIN" > analyze.log 2>&1
    RC=$?
    ANALYZE_ELAPSED=$(( $(date +%s) - START ))
    printf '%s\n' "$ANALYZE_ELAPSED" > .analyze_elapsed
    log "анализ rc=$RC, ${ANALYZE_ELAPSED}s"
    tail -3 analyze.log 2>/dev/null || true
    [ -f "$PROJ" ] || { echo "проект $PROJ не сохранился"; tail -30 analyze.log 2>/dev/null; exit 1; }
    du -h "$PROJ" 2>/dev/null || true
  fi
fi

if [ "$PHASE" = "analyze" ]; then
  exit 0
fi

if [ -f "$PROJ" ]; then
  "$R2" "${R2OPTS[@]}" -q -p "$PWD/$PROJ" -c 'aflj' "$BIN" > "$META_OUT" 2>/dev/null
  log "функций в бинаре: $(python3 -c "import json,sys;print(len(json.load(open('$META_OUT'))))" 2>/dev/null || echo '?')"
fi

REMAIN=$((BUDGET - ANALYZE_ELAPSED))
[ "$REMAIN" -lt 300 ] && REMAIN=300
MAIN=$((REMAIN * 4 / 5))
FALLBACK=$((REMAIN - MAIN))

: > renames.r2
pattern_renames >> renames.r2
json_renames >> renames.r2
RENAME_ARGS=()
if [ -s renames.r2 ]; then
  RENAME_ARGS=(-i "$PWD/renames.r2")
  log "имён к применению: $(( $(grep -c . renames.r2) / 2 ))"
fi

rm -f "$CODE_OUT" "$LOG" "$ENGINE_OUT"
: > "$LOG"

run_dump() {
  local budget="$1" cmd="$2" out="$3" rc
  if [ -n "${R2_GHIDRA:-}" ] && [ "$R2_GHIDRA" = "0" ] && [ "$cmd" = "pdg @@f" ]; then
    return 1
  fi
  budget_kill "$budget" "$R2" "${R2OPTS[@]}" -q -p "$PWD/$PROJ" -c "$cmd" ${RENAME_ARGS[@]+"${RENAME_ARGS[@]}"} "$BIN" > "$out" 2>> "$LOG"
  rc=$?
  return $rc
}

START=$(date +%s)
log "декомпиляция: pdg (до ${MAIN}s)"
run_dump "$MAIN" 'pdg @@f' "$CODE_OUT"
RC_PDG=$?
BODIES_PDG=$(grep -c '^{$' "$CODE_OUT" 2>/dev/null || true)
log "pdg rc=$RC_PDG, $(wc -c < "$CODE_OUT" | tr -d ' ') байт, тел: ${BODIES_PDG:-0}"

RC_PDC=none
ENGINE=pdg
if [ "${BODIES_PDG:-0}" -lt 5 ]; then
  ENGINE=pdc
  log "r2ghidra не отдал код — падаю на встроенный pdc"
  run_dump "$FALLBACK" 'pdc @@f' "$CODE_OUT"
  RC_PDC=$?
  log "pdc rc=$RC_PDC, $(wc -c < "$CODE_OUT" | tr -d ' ') байт"
fi
ELAPSED=$(( $(date +%s) - START ))

{
  echo "engine=$ENGINE"
  echo "pdg_exit_code=$RC_PDG"
  echo "pdc_exit_code=$RC_PDC"
  echo "pdg_function_bodies=${BODIES_PDG:-0}"
  echo "r2_version=${R2V:-unknown}"
  echo "r2_path=$R2"
  echo "ghidra_plugin=${R2_GHIDRA:-unknown}"
  echo "budget_seconds=$BUDGET"
  echo "analyze_elapsed_seconds=$ANALYZE_ELAPSED"
  echo "pdg_budget_seconds=$MAIN"
  echo "pdc_budget_seconds=$FALLBACK"
  echo "elapsed_seconds=$ELAPSED"
  echo "binary=$BIN"
  echo "binary_bytes=$(wc -c < "$BIN" | tr -d ' ')"
  echo "code_bytes=$(wc -c < "$CODE_OUT" | tr -d ' ')"
  echo "code_lines=$(wc -l < "$CODE_OUT" | tr -d ' ')"
  echo "renames_applied=$(( $(grep -c . renames.r2 2>/dev/null || echo 0) / 2 ))"
  echo "finished_at=$(date -u +%FT%TZ)"
} > "$ENGINE_OUT"

cat "$ENGINE_OUT"
