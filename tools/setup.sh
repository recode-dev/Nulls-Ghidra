#!/usr/bin/env bash
set -euo pipefail

WANT=${R2_VERSION:-6.2.4}
REPO=${PLUGIN_REPO:-https://github.com/radareorg/r2ghidra/releases/download}
OS=$(uname -s)
ARCH=$(uname -m)

if [ -z "$(command -v r2 || true)" ]; then
  if [ "$OS" = Darwin ]; then
    if [ "$ARCH" = arm64 ]; then PKG=radare2-arm64-$WANT.pkg; else PKG=radare2-$WANT.pkg; fi
    if curl -fL --retry 5 -o /tmp/r2.pkg "https://github.com/radareorg/radare2/releases/download/$WANT/$PKG" \
       && sudo installer -pkg /tmp/r2.pkg -target /; then
      :
    else
      brew install radare2
    fi
  else
    if [ "$ARCH" = aarch64 ]; then DEB=radare2_${WANT}_arm64.deb; else DEB=radare2_${WANT}_amd64.deb; fi
    curl -fL --retry 5 -o /tmp/r2.deb "https://github.com/radareorg/radare2/releases/download/$WANT/$DEB"
    sudo apt-get install -y /tmp/r2.deb
  fi
fi

R2=$(command -v r2 || echo /usr/local/bin/r2)
[ -x "$R2" ] || { echo "r2 install failed"; exit 1; }
V=$("$R2" -v | head -1 | awk '{print $2}')
[ -n "$V" ] || V=$WANT
PD=$("$R2" -HR2_USER_PLUGINS)
mkdir -p "$PD"

G=0
if ls "$PD" 2>/dev/null | grep -q '^core_ghidra'; then G=1; fi
if [ "$G" = 0 ]; then
  if [ "$OS" = Darwin ]; then
    if [ "$ARCH" = arm64 ]; then A=darwin-arm-64; else A=darwin-x86-64; fi
  else
    if [ "$ARCH" = aarch64 ]; then A=linux-arm-64; else A=linux-x86-64; fi
  fi
  if curl -fL --retry 5 -o /tmp/gh.zip "$REPO/$V/r2ghidra-$V-$A.zip"; then
    rm -rf /tmp/gh
    mkdir -p /tmp/gh
    unzip -q /tmp/gh.zip -d /tmp/gh
    if [ -d /tmp/gh/plugins ]; then cp -R /tmp/gh/plugins/. "$PD/"; else cp -R /tmp/gh/. "$PD/"; fi
    G=1
  fi
fi
[ "$G" = 1 ] || { echo "[-] r2ghidra plugin install failed"; exit 1; }

echo "r2 $V plugin $G"
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "R2V=$V" >> "$GITHUB_ENV"
fi
