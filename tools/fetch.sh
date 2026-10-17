#!/usr/bin/env bash
set -euo pipefail

URL=${BINARY_URL:-}
OUT=${OUT_BIN:-binary}
CACHE=${IPA_CACHE_DIR:-ipa_cache}
VERFILE=${VERSION_FILE:-version.txt}

loc_redirect() {
  curl -sIL --max-time 30 --retry 3 --retry-delay 5 --retry-all-errors -A "Mozilla/5.0" "$1" 2>/dev/null \
    | tr -d '\r' | awk 'tolower($1) == "location:" { l = $2 } END { if (l != "") print l }'
}

loc_page() {
  curl -sL --max-time 30 --retry 3 --retry-delay 5 --retry-all-errors -A "Mozilla/5.0" "$1" 2>/dev/null \
    | grep -oE "https?://[^\"'<> ]+\.ipa" | head -1
}

if [ -n "$URL" ]; then
  LOC=$URL
  DRIVE_ID=$(printf '%s' "$URL" | sed -nE 's#.*drive\.google\.com/file/d/([^/?]+).*#\1#p')
  if [ -n "$DRIVE_ID" ]; then
    LOC="https://drive.google.com/uc?export=download&id=$DRIVE_ID"
  fi
else
  LOC=""
  for SRC in ${SOURCE_URLS:-}; do
    for _ in 1 2 3; do
      LOC=$(loc_redirect "$SRC" || true)
      case "$LOC" in *.ipa|*.zip) break ;; esac
      LOC=$(loc_page "$SRC" || true)
      case "$LOC" in *.ipa|*.zip) break ;; esac
      LOC=""
      sleep 5
    done
    if [ -n "$LOC" ]; then break; fi
    echo "resolve failed $SRC"
  done
fi
[ -n "$LOC" ] || { echo "no archive url; pass BINARY_URL or SOURCE_URLS"; exit 1; }

VER=$(basename "$LOC" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
[ -n "$VER" ] || VER=unknown
echo "ipa $LOC"
echo "ver $VER"
echo "$VER" > "$VERFILE"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "URL=$LOC" >> "$GITHUB_OUTPUT"
  echo "VER=$VER" >> "$GITHUB_OUTPUT"
fi
[ "${RESOLVE_ONLY:-0}" = 1 ] && exit 0

mkdir -p "$CACHE"
if [ ! -s "$CACHE/archive" ]; then
  if ! curl -fL --retry 5 --retry-delay 5 --retry-all-errors --max-time 1800 -A "Mozilla/5.0" \
    -c "$CACHE/cookies.txt" -o "$CACHE/archive" "$LOC"; then
    echo "download failed $LOC"
    exit 1
  fi
  if file -b "$CACHE/archive" | grep -qiE 'HTML'; then
    ACTION=$(grep -oE 'action="https://drive\.usercontent\.google\.com/download[^"]*"' "$CACHE/archive" \
      | head -1 | sed -e 's/^action="//' -e 's/"$//' || true)
    ARGS=$(grep -oE '<input type="hidden" name="[^"]+" value="[^"]*"' "$CACHE/archive" 2>/dev/null \
      | sed -E 's/.*name="([^"]+)" value="([^"]*)".*/\1=\2/' | paste -sd'&' - || true)
    if [ -n "$ACTION" ] && [ -n "$ARGS" ]; then
      curl -fL -b "$CACHE/cookies.txt" -A "Mozilla/5.0" -o "$CACHE/archive" "$ACTION?$ARGS"
    else
      CONFIRM=$(grep -oE 'confirm=[0-9A-Za-z_-]+' "$CACHE/archive" | head -1 | cut -d= -f2 || true)
      if [ -n "$CONFIRM" ]; then
        curl -fL -b "$CACHE/cookies.txt" -A "Mozilla/5.0" -o "$CACHE/archive" "$LOC&confirm=$CONFIRM"
      fi
    fi
  fi
  if file -b "$CACHE/archive" | grep -qiE 'HTML'; then
    echo "download returned an HTML page instead of a file: $LOC"
    exit 1
  fi
fi

WORK=${EXTRACT_DIR:-extract}
rm -rf "$WORK"
mkdir -p "$WORK"
if file -b "$CACHE/archive" | grep -qE 'Mach-O'; then
  cp "$CACHE/archive" "$WORK/direct.bin"
else
  unzip -oq "$CACHE/archive" -d "$WORK"
fi

ROOT="$WORK"
APP=$(find "$WORK/Payload" -maxdepth 1 -type d -name '*.app' 2>/dev/null | head -1 || true)
if [ -n "$APP" ]; then
  ROOT="$APP"
  echo "app $APP"
fi

CANDS="$WORK/candidates.txt"
BINARIES="$WORK/binaries.txt"
find "$ROOT" -type f > "$CANDS"
: > "$BINARIES"
while IFS= read -r f; do
  case "$f" in
    *.png|*.jpg|*.jpeg|*.plist|*.car|*.ttf|*.otf|*.json|*.txt|*.gz|*.zip|*.mp3|*.wav|*.mp4|*.assets|*.resource|*.bundle|*.unity3d|*.dex|*.xml) continue ;;
  esac
  DESC=$(file -b "$f" 2>/dev/null || true)
  case "$DESC" in
    *Mach-O*) echo "$(wc -c < "$f" | tr -d ' ') $f" >> "$BINARIES" ;;
  esac
done < "$CANDS"
sort -rn "$BINARIES" 2>/dev/null | head -5

EXEC=""
if [ -f "$ROOT/Info.plist" ]; then
  EXEC=$(python3 -c "import plistlib,sys;print(plistlib.load(open(sys.argv[1],'rb')).get('CFBundleExecutable','') or '')" "$ROOT/Info.plist" 2>/dev/null || true)
  if [ "$VER" = unknown ]; then
    IV=$(python3 -c "import plistlib,sys;d=plistlib.load(open(sys.argv[1],'rb'));print(d.get('CFBundleShortVersionString') or d.get('CFBundleVersion') or '')" "$ROOT/Info.plist" 2>/dev/null || true)
    if [ -n "$IV" ]; then
      VER=$IV
      echo "$VER" > "$VERFILE"
      echo "ver $VER (Info.plist)"
    fi
  fi
fi

rm -f "$OUT"
PICK=""
if [ -n "$EXEC" ] && [ -f "$ROOT/$EXEC" ] && file -b "$ROOT/$EXEC" 2>/dev/null | grep -qE 'Mach-O'; then
  PICK="$ROOT/$EXEC"
  echo "pick exec $EXEC"
elif [ -s "$BINARIES" ]; then
  PICK=$(sort -rn "$BINARIES" | head -1 | cut -d' ' -f2-)
  echo "pick largest binary"
fi

if [ -n "$PICK" ] && [ -f "$PICK" ]; then
  cp -f "$PICK" "$OUT"
fi

[ -s "$OUT" ] || { echo "no mach-o found"; exit 1; }

SIZE=$(wc -c < "$OUT" | tr -d ' ')
echo "bin $OUT $SIZE"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "BINSIZE=$SIZE" >> "$GITHUB_OUTPUT"
  echo "VER=$VER" >> "$GITHUB_OUTPUT"
fi
