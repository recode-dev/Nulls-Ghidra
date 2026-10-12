#!/usr/bin/env bash
set -euo pipefail

URL_IN="${BINARY_URL:-}"
OUT_BIN="${OUT_BIN:-brawl_bin}"
CACHE_DIR="${IPA_CACHE_DIR:-ipa_cache}"
VERSION_FILE="${VERSION_FILE:-version.txt}"

if [ -n "$URL_IN" ]; then
  LOC="$URL_IN"
else
  LOC=$(curl -sIL -A "Mozilla/5.0" "https://dnull.xyz/latest_bs_i" \
    | grep -i "^location:" | tail -1 | awk '{print $2}' | tr -d '\r\n')
fi
[ -n "$LOC" ] || { echo "не удалось получить ссылку на ipa"; exit 1; }

VER=$(basename "$LOC" | sed -E 's/.*nb_([0-9][0-9.]*)_.*/\1/')
case "$VER" in
  *.ipa|*/*|"") VER=unknown ;;
esac
echo "ipa: $LOC"
echo "версия: $VER"
printf '%s\n' "$VER" > "$VERSION_FILE"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "URL=$LOC" >> "$GITHUB_OUTPUT"
  echo "VER=$VER" >> "$GITHUB_OUTPUT"
fi

if [ "${RESOLVE_ONLY:-0}" = "1" ]; then
  echo "только разрешение ссылки (RESOLVE_ONLY)"
  exit 0
fi

mkdir -p "$CACHE_DIR"
if [ ! -s "$CACHE_DIR/bs.ipa" ]; then
  curl -fL --retry 5 --retry-delay 5 --retry-all-errors --max-time 1800 \
    -A "Mozilla/5.0" -o "$CACHE_DIR/bs.ipa.part" "$LOC"
  mv -f "$CACHE_DIR/bs.ipa.part" "$CACHE_DIR/bs.ipa"
fi
test -s "$CACHE_DIR/bs.ipa"
file "$CACHE_DIR/bs.ipa" || true

WORK="${EXTRACT_DIR:-extract}"
rm -rf "$WORK"
mkdir -p "$WORK"
unzip -oq "$CACHE_DIR/bs.ipa" -d "$WORK"

APP_DIR=$(find "$WORK/Payload" -maxdepth 1 -type d -name "*.app" | head -n1)
[ -n "$APP_DIR" ] || { echo "в ipa нет Payload/*.app"; ls -la "$WORK"; exit 1; }
echo "app: $APP_DIR"

EXEC_NAME=""
if [ -f "$APP_DIR/Info.plist" ]; then
  EXEC_NAME=$(python3 -c "import plistlib,sys;print(plistlib.load(open(sys.argv[1],'rb')).get('CFBundleExecutable','') or '')" "$APP_DIR/Info.plist")
fi
echo "CFBundleExecutable: ${EXEC_NAME:-<нет>}"

rm -f "$OUT_BIN"
if [ -n "$EXEC_NAME" ] && [ -f "$APP_DIR/$EXEC_NAME" ]; then
  cp -f "$APP_DIR/$EXEC_NAME" "$OUT_BIN"
fi

if [ ! -s "$OUT_BIN" ]; then
  for f in "$APP_DIR"/*; do
    [ -f "$f" ] || continue
    case "$f" in
      *.dylib|*.png|*.jpg|*.jpeg|*.plist|*.car|*.ttf|*.otf|*.json|*.txt|*.gz|*.zip|*.mp3|*.wav) continue ;;
    esac
    if file "$f" | grep -q "Mach-O" && otool -hv "$f" 2>/dev/null | grep -q "EXECUTE"; then
      cp -f "$f" "$OUT_BIN"
      break
    fi
  done
fi

if [ ! -s "$OUT_BIN" ]; then
  for f in "$APP_DIR"/*; do
    [ -f "$f" ] || continue
    if file "$f" | grep -q "Mach-O"; then
      cp -f "$f" "$OUT_BIN"
      break
    fi
  done
fi

[ -s "$OUT_BIN" ] || { echo "Mach-O исполняемый файл не найден в $APP_DIR"; ls -la "$APP_DIR"; exit 1; }
file "$OUT_BIN"
wc -c < "$OUT_BIN"
