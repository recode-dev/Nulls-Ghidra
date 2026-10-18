#!/usr/bin/env bash
set -euo pipefail

URL=${BINARY_URL:-}
OUT=${OUT_BIN:-binary}
CACHE=${IPA_CACHE_DIR:-ipa_cache}

[ -n "$URL" ] || { echo "[-] BINARY_URL is empty"; exit 1; }

DRIVE_ID=$(printf '%s' "$URL" | sed -nE 's#.*drive\.google\.com/(file/d/|open\?id=|uc\?[^ ]*id=)([^/?&]+).*#\2#p')
LOC=$URL
if [ -n "$DRIVE_ID" ]; then
  LOC="https://drive.google.com/uc?export=download&id=$DRIVE_ID"
fi
echo "[+] $LOC"

mkdir -p "$CACHE"
if [ ! -s "$CACHE/archive" ]; then
  if ! curl -fL --retry 5 --retry-delay 5 --retry-all-errors --max-time 1800 -A "Mozilla/5.0" \
    -c "$CACHE/cookies.txt" -o "$CACHE/archive" "$LOC"; then
    echo "[-] download failed $LOC"
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
      [ -n "$CONFIRM" ] || { echo "[-] drive confirmation form not found"; exit 1; }
      curl -fL -b "$CACHE/cookies.txt" -A "Mozilla/5.0" -o "$CACHE/archive" "$LOC&confirm=$CONFIRM"
    fi
  fi
  if file -b "$CACHE/archive" | grep -qiE 'HTML'; then
    echo "[-] download returned an HTML page: $LOC"
    exit 1
  fi
fi

WORK=${EXTRACT_DIR:-extract}
rm -rf "$WORK"
mkdir -p "$WORK"
ROOT=$WORK
if file -b "$CACHE/archive" | grep -qE 'Mach-O'; then
  cp "$CACHE/archive" "$WORK/direct.bin"
else
  unzip -oq "$CACHE/archive" -d "$WORK" || { echo "[-] unzip failed"; exit 1; }
  APP=$(find "$WORK/Payload" -maxdepth 1 -type d -name '*.app' 2>/dev/null | head -1 || true)
  if [ -n "$APP" ]; then
    ROOT=$APP
    echo "[+] app $APP"
  fi
fi

find "$ROOT" -type f > "$WORK/candidates.txt"
: > "$WORK/binaries.txt"
while IFS= read -r f; do
  case "$f" in
    *.png|*.jpg|*.jpeg|*.plist|*.car|*.ttf|*.otf|*.json|*.txt|*.gz|*.zip|*.mp3|*.wav|*.mp4|*.assets|*.resource|*.bundle|*.unity3d|*.dex|*.xml) continue ;;
  esac
  case "$(file -b "$f" 2>/dev/null || true)" in
    *Mach-O*) echo "$(wc -c < "$f" | tr -d ' ') $f" >> "$WORK/binaries.txt" ;;
  esac
done < "$WORK/candidates.txt"

EXEC=""
VER=""
if [ -f "$ROOT/Info.plist" ]; then
  META=$(python3 - "$ROOT/Info.plist" <<'PY'
import plistlib, sys

data = plistlib.load(open(sys.argv[1], 'rb'))
print(data.get('CFBundleExecutable') or '')
print(data.get('CFBundleShortVersionString') or data.get('CFBundleVersion') or '')
PY
) || true
  EXEC=$(printf '%s\n' "$META" | sed -n 1p)
  VER=$(printf '%s\n' "$META" | sed -n 2p)
fi

PICK=""
if [ -n "$EXEC" ] && [ -f "$ROOT/$EXEC" ] && file -b "$ROOT/$EXEC" 2>/dev/null | grep -qE 'Mach-O'; then
  PICK="$ROOT/$EXEC"
  echo "[+] exec $EXEC"
elif [ -s "$WORK/binaries.txt" ]; then
  PICK=$(sort -rn "$WORK/binaries.txt" | head -1 | cut -d' ' -f2-)
  echo "[+] largest mach-o"
fi

rm -f "$OUT"
[ -z "$PICK" ] || cp -f "$PICK" "$OUT"
[ -s "$OUT" ] || { echo "[-] no mach-o found"; exit 1; }

[ -n "$VER" ] || VER=$(shasum -a 256 "$OUT" | cut -c1-12)
SIZE=$(wc -c < "$OUT" | tr -d ' ')
echo "[+] $OUT $SIZE bytes ver $VER"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "VER=$VER" >> "$GITHUB_OUTPUT"
fi
