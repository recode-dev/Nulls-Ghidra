#!/usr/bin/env bash
set -euo pipefail

R2_WANT="${R2_VERSION:-6.2.4}"
PLUGIN_REPO="${PLUGIN_REPO:-https://github.com/radareorg/r2ghidra/releases/download}"

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

install_r2() {
  if [ "$UNAME_S" = "Darwin" ]; then
    case "$UNAME_M" in
      arm64) PKG="radare2-arm64-${R2_WANT}.pkg" ;;
      *)     PKG="radare2-${R2_WANT}.pkg" ;;
    esac
    if curl -fL --retry 5 --retry-delay 5 -o /tmp/r2.pkg \
        "https://github.com/radareorg/radare2/releases/download/${R2_WANT}/${PKG}"; then
      if ! sudo installer -pkg /tmp/r2.pkg -target /; then
        echo "пакет не встал, ставлю через brew"
        brew install radare2
      fi
    else
      echo "пакета нет, ставлю через brew"
      brew install radare2
    fi
  else
    case "$UNAME_M" in
      aarch64|arm64) DEB="radare2_${R2_WANT}_arm64.deb" ;;
      *)             DEB="radare2_${R2_WANT}_amd64.deb" ;;
    esac
    curl -fL --retry 5 --retry-delay 5 -o /tmp/r2.deb \
      "https://github.com/radareorg/radare2/releases/download/${R2_WANT}/${DEB}"
    sudo apt-get install -y /tmp/r2.deb
  fi
}

R2BIN="$(command -v r2 || true)"
if [ -z "$R2BIN" ] || [ ! -x "$R2BIN" ]; then
  install_r2
  R2BIN="$(command -v r2 || echo /usr/local/bin/r2)"
fi
[ -x "$R2BIN" ] || { echo "r2 не установился"; exit 1; }
"$R2BIN" -v | head -1
R2V="$("$R2BIN" -v | head -1 | awk '{print $2}')"
[ -n "$R2V" ] || R2V="$R2_WANT"

PLUGDIR="$("$R2BIN" -HR2_USER_PLUGINS)"
mkdir -p "$PLUGDIR"
echo "plugin dir: $PLUGDIR"

HAVE_PLUGIN=0
if ls "$PLUGDIR" 2>/dev/null | grep -q "^core_ghidra"; then
  HAVE_PLUGIN=1
fi

if [ "$HAVE_PLUGIN" = 0 ] && [ "${SKIP_PLUGIN:-0}" != "1" ]; then
  case "$UNAME_S" in
    Darwin)
      case "$UNAME_M" in
        arm64) ASSET="darwin-arm-64" ;;
        *)     ASSET="darwin-x86-64" ;;
      esac
      ;;
    *)
      case "$UNAME_M" in
        aarch64|arm64) ASSET="linux-arm-64" ;;
        *)             ASSET="linux-x86-64" ;;
      esac
      ;;
  esac
  URL="${PLUGIN_REPO}/${R2V}/r2ghidra-${R2V}-${ASSET}.zip"
  echo "r2ghidra: $URL"
  if curl -fL --retry 5 --retry-delay 5 -o /tmp/r2ghidra.zip "$URL"; then
    rm -rf /tmp/r2ghidra
    mkdir -p /tmp/r2ghidra
    unzip -q /tmp/r2ghidra.zip -d /tmp/r2ghidra
    if [ -d /tmp/r2ghidra/plugins ]; then
      cp -R /tmp/r2ghidra/plugins/. "$PLUGDIR/"
    else
      cp -R /tmp/r2ghidra/. "$PLUGDIR/"
    fi
    HAVE_PLUGIN=1
  else
    echo "::warning::r2ghidra ${R2V} не найден — останется встроенный декомпилятор r2"
  fi
fi

ls -la "$PLUGDIR" || true
if [ -n "${1:-}" ] && [ -f "$1" ]; then
  "$R2BIN" -q -c 'pdg?' "$1" 2>&1 | head -3 || true
fi

if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "R2BIN=$R2BIN"
    echo "R2V=$R2V"
    echo "R2_PLUGDIR=$PLUGDIR"
    echo "R2_GHIDRA=$HAVE_PLUGIN"
  } >> "$GITHUB_ENV"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "R2V=$R2V"
    echo "GHIDRA=$HAVE_PLUGIN"
  } >> "$GITHUB_OUTPUT"
fi
