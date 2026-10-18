#!/usr/bin/env bash
set -euo pipefail

VER=${GHIDRA_VERSION:-12.1.4}
STAMP=${GHIDRA_STAMP:-20260921}
DIR=${GHIDRA_HOME:-$HOME/ghidra}
ZIP=ghidra_${VER}_PUBLIC_${STAMP}.zip
URL=${GHIDRA_URL:-https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${VER}_build/$ZIP}

if [ ! -x "$DIR/support/analyzeHeadless" ]; then
  TMP=$(mktemp -d)
  curl -fL --retry 5 --retry-delay 5 --retry-all-errors -o "$TMP/$ZIP" "$URL"
  unzip -q "$TMP/$ZIP" -d "$TMP/out"
  mkdir -p "$DIR"
  cp -R "$TMP/out/ghidra_${VER}_PUBLIC/." "$DIR/"
  rm -rf "$TMP"
fi

[ -x "$DIR/support/analyzeHeadless" ] || { echo "[-] ghidra install failed"; exit 1; }

JAVA=${JAVA_BIN:-}
if [ -z "$JAVA" ]; then
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then JAVA=$JAVA_HOME/bin/java; else JAVA=$(command -v java || true); fi
fi
[ -n "$JAVA" ] && [ -x "$JAVA" ] || { echo "[-] java 21 required"; exit 1; }

V=$("$JAVA" -version 2>&1 | head -1)
GV=$(grep -m1 '^application.version=' "$DIR/Ghidra/application.properties" | cut -d= -f2)
echo "ghidra ${GV:-$VER}"
echo "java $V"

if [ -n "${GITHUB_ENV:-}" ]; then
  echo "GHIDRA_HOME=$DIR" >> "$GITHUB_ENV"
  echo "MAXMEM=${MAXMEM:-8G}" >> "$GITHUB_ENV"
fi
