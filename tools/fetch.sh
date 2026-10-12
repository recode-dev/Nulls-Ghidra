#!/usr/bin/env bash
set -euo pipefail

URL=${BINARY_URL:-}
OUT=${OUT_BIN:-brawl_bin}
CACHE=${IPA_CACHE_DIR:-ipa_cache}
VERFILE=${VERSION_FILE:-version.txt}

if [ -n "$URL" ]; then
  LOC=$URL
else
  LOC=$(curl -sIL -A "Mozilla/5.0" https://dnull.xyz/latest_bs_i \
    | grep -i '^location:' | tail -1 | awk '{print $2}' | tr -d '\r\n')
fi
[ -n "$LOC" ] || { echo "no ipa url"; exit 1; }

VER=$(basename "$LOC" | sed -E 's/.*nb_([0-9][0-9.]*)_.*/\1/')
case "$VER" in *.ipa|*/*|"") VER=unknown ;; esac
echo "ipa $LOC"
echo "ver $VER"
echo "$VER" > "$VERFILE"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "URL=$LOC" >> "$GITHUB_OUTPUT"
  echo "VER=$VER" >> "$GITHUB_OUTPUT"
fi
[ "${RESOLVE_ONLY:-0}" = 1 ] && exit 0

mkdir -p "$CACHE"
if [ ! -s "$CACHE/bs.ipa" ]; then
  curl -fL --retry 5 --retry-delay 5 --max-time 1800 -A "Mozilla/5.0" \
    -o "$CACHE/bs.ipa" "$LOC"
fi

WORK=${EXTRACT_DIR:-extract}
rm -rf "$WORK"
mkdir -p "$WORK"
unzip -oq "$CACHE/bs.ipa" -d "$WORK"

APP=$(find "$WORK/Payload" -maxdepth 1 -type d -name '*.app' | head -1)
[ -n "$APP" ] || { echo "no app bundle"; exit 1; }
echo "app $APP"

find "$APP" -type f > /tmp/cand.txt
: > /tmp/macho.txt
while IFS= read -r f; do
  case "$f" in
    *.png|*.jpg|*.jpeg|*.plist|*.car|*.ttf|*.otf|*.json|*.txt|*.gz|*.zip|*.mp3|*.wav|*.mp4|*.assets|*.resource|*.bundle|*.unity3d) continue ;;
  esac
  file "$f" 2>/dev/null | grep -q Mach-O || continue
  echo "$(wc -c < "$f" | tr -d ' ') $f" >> /tmp/macho.txt
done < /tmp/cand.txt
sort -rn /tmp/macho.txt 2>/dev/null | head -5

EXEC=""
if [ -f "$APP/Info.plist" ]; then
  EXEC=$(python3 -c "import plistlib,sys;print(plistlib.load(open(sys.argv[1],'rb')).get('CFBundleExecutable','') or '')" "$APP/Info.plist" 2>/dev/null || true)
fi

rm -f "$OUT"
PICK=""
if [ -n "$EXEC" ] && [ -f "$APP/$EXEC" ] && file "$APP/$EXEC" 2>/dev/null | grep -q Mach-O; then
  PICK="$APP/$EXEC"
  echo "pick exec $EXEC"
elif [ -s /tmp/macho.txt ]; then
  PICK=$(sort -rn /tmp/macho.txt | head -1 | cut -d' ' -f2-)
  echo "pick largest mach-o"
fi

if [ -n "$PICK" ] && [ -f "$PICK" ]; then
  cp -f "$PICK" "$OUT"
fi

[ -s "$OUT" ] || { echo "no mach-o found"; exit 1; }

SIZE=$(wc -c < "$OUT" | tr -d ' ')
echo "bin $OUT $SIZE"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "BINSIZE=$SIZE" >> "$GITHUB_OUTPUT"
fi
