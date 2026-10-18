#!/usr/bin/env bash
set -euo pipefail

URL=${BINARY_URL:-}
OUT=${OUT_BIN:-binary}
CACHE=${BIN_CACHE_DIR:-bin_cache}

[ -n "$URL" ] || { echo "[-] BINARY_URL is empty"; exit 1; }

is_html() {
  head -c 1024 "$1" | grep -qi '<!doctype html\|<html'
}

file_format() {
  local magic
  magic=$(head -c 8 "$1" | od -An -tx1 | tr -d ' \n')
  case "$magic" in
    cffaedfe*|cefaedfe*|cafebabe*|bebafeca*) echo macho ;;
    7f454c460101*) echo elf32 ;;
    7f454c460201*) echo elf64 ;;
    *) echo unknown ;;
  esac
}

DRIVE_ID=$(printf '%s' "$URL" | sed -nE 's#.*drive\.google\.com/(file/d/|open\?id=|uc\?[^ ]*id=)([^/?&]+).*#\2#p')
LOC=$URL
if [ -n "$DRIVE_ID" ]; then
  LOC="https://drive.google.com/uc?export=download&id=$DRIVE_ID"
fi
echo "[+] $LOC"

mkdir -p "$CACHE"
if [ -s "$CACHE/binary" ]; then
  CACHED=$(file_format "$CACHE/binary")
  WANT=${EXPECT_FORMAT:-auto}
  if [ "$WANT" != auto ] && [ "$CACHED" != "$WANT" ]; then
    echo "[+] cached $CACHED, expected $WANT, refetch"
    rm -f "$CACHE/binary"
  fi
fi
if [ ! -s "$CACHE/binary" ]; then
  if ! curl -fL --retry 5 --retry-delay 5 --retry-all-errors --max-time 1800 -A "Mozilla/5.0" \
    -c "$CACHE/cookies.txt" -o "$CACHE/binary" "$LOC"; then
    rm -f "$CACHE/binary"
    echo "[-] download failed $LOC"
    exit 1
  fi
  if is_html "$CACHE/binary"; then
    ACTION=$(grep -oE 'action="https://drive\.usercontent\.google\.com/download[^"]*"' "$CACHE/binary" \
      | head -1 | sed -e 's/^action="//' -e 's/"$//' || true)
    ARGS=$(grep -oE '<input type="hidden" name="[^"]+" value="[^"]*"' "$CACHE/binary" 2>/dev/null \
      | sed -E 's/.*name="([^"]+)" value="([^"]*)".*/\1=\2/' | paste -sd'&' - || true)
    if [ -n "$ACTION" ] && [ -n "$ARGS" ]; then
      curl -fL -b "$CACHE/cookies.txt" -A "Mozilla/5.0" -o "$CACHE/binary" "$ACTION?$ARGS"
    else
      CONFIRM=$(grep -oE 'confirm=[0-9A-Za-z_-]+' "$CACHE/binary" | head -1 | cut -d= -f2 || true)
      if [ -z "$CONFIRM" ]; then
        rm -f "$CACHE/binary"
        echo "[-] drive returned an html page instead of a file"
        exit 1
      fi
      curl -fL -b "$CACHE/cookies.txt" -A "Mozilla/5.0" -o "$CACHE/binary" "$LOC&confirm=$CONFIRM"
    fi
  fi
fi

if is_html "$CACHE/binary"; then
  rm -f "$CACHE/binary"
  echo "[-] drive returned an html page: $LOC"
  exit 1
fi
FORMAT=$(file_format "$CACHE/binary")
EXPECT=${EXPECT_FORMAT:-auto}
if [ "$FORMAT" = unknown ]; then
  rm -f "$CACHE/binary"
  echo "[-] unknown format: $(head -c 8 "$CACHE/binary" | od -An -tx1 | tr -d ' \n')"
  exit 1
fi
if [ "$EXPECT" != auto ] && [ "$FORMAT" != "$EXPECT" ]; then
  rm -f "$CACHE/binary"
  echo "[-] expected $EXPECT, got $FORMAT"
  exit 1
fi
echo "[+] format $FORMAT"

cp -f "$CACHE/binary" "$OUT"
SIZE=$(wc -c < "$OUT" | tr -d ' ')
VER=$(shasum -a 256 "$OUT" | cut -c1-12)
echo "[+] $OUT $SIZE bytes ver $VER"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "VER=$VER" >> "$GITHUB_OUTPUT"
  echo "FORMAT=$FORMAT" >> "$GITHUB_OUTPUT"
fi
