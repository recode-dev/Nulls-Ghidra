#!/usr/bin/env bash
set -euo pipefail

DYLIB=${1:?usage: mkfw.sh <gadget.dylib> [outdir]}
OUT=${2:-.}
VER=${FRIDA_VERSION:-unknown}
SCRIPT=${SCRIPT_PATH:-updated/script_69_252.js}
CS=${CODE_SIGNING:-optional}
FW="$OUT/FridaGadget.framework"
ID='@executable_path/Frameworks/FridaGadget.framework/FridaGadget'

rm -rf "$FW"
mkdir -p "$FW"
cp "$DYLIB" "$FW/FridaGadget"
chmod 755 "$FW/FridaGadget"

cat > "$FW/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>FridaGadget</string>
    <key>CFBundleIdentifier</key>
    <string>re.frida.gadget</string>
    <key>CFBundleName</key>
    <string>FridaGadget</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>$VER</string>
    <key>CFBundleVersion</key>
    <string>$VER</string>
    <key>MinimumOSVersion</key>
    <string>11.0</string>
</dict>
</plist>
PLIST

cat > "$FW/FridaGadget.config" <<CFG
{
  "interaction": {
    "type": "script",
    "path": "$SCRIPT",
    "on_change": "reload"
  },
  "runtime": "qjs",
  "code_signing": "$CS"
}
CFG

if command -v install_name_tool >/dev/null 2>&1; then
  install_name_tool -id "$ID" "$FW/FridaGadget"
  echo "id -> $ID"
fi

if command -v ldid >/dev/null 2>&1; then
  ldid -S "$FW/FridaGadget"
  echo "signed: ldid"
elif command -v codesign >/dev/null 2>&1; then
  codesign -f -s - "$FW/FridaGadget"
  echo "signed: codesign ad-hoc"
else
  echo "warn: no ldid/codesign here"
fi

if command -v codesign >/dev/null 2>&1; then
  codesign -dvv "$FW/FridaGadget" 2>&1 | grep -E "Signature|Identifier|Format" || true
fi

ls -la "$FW"
