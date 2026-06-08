#!/usr/bin/env bash
# NPorter one-command remote installer.
#
#   curl -fsSL https://raw.githubusercontent.com/xjoker-dev/NPorter/main/get.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/xjoker-dev/NPorter/main/get.sh | sudo bash -s -- --now
#
# All options are forwarded to install.sh unchanged:
#   --enable       Enable nporter.service at boot.
#   --start        Start nporter.service after installation.
#   --now          Enable and start nporter.service immediately.
#   --no-systemd   Do not install the systemd unit.
set -euo pipefail

REPO="xjoker-dev/NPorter"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

die() { echo "error: $*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "NPorter only runs on Linux"
[ "$(id -u)" = "0" ]        || die "must run as root (prefix with: sudo)"

case "$(uname -m)" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *)       die "unsupported architecture: $(uname -m)" ;;
esac

TARBALL="nporter-linux-${ARCH}.tar.gz"
CHECKSUM="${TARBALL}.sha256"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${TARBALL} ..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$TMPDIR/$TARBALL"  "${BASE_URL}/${TARBALL}"
    curl -fsSL -o "$TMPDIR/$CHECKSUM" "${BASE_URL}/${CHECKSUM}"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMPDIR/$TARBALL"  "${BASE_URL}/${TARBALL}"
    wget -qO "$TMPDIR/$CHECKSUM" "${BASE_URL}/${CHECKSUM}"
else
    die "curl or wget is required"
fi

echo "Verifying checksum ..."
cd "$TMPDIR"
sha256sum -c "$CHECKSUM"

echo "Extracting ..."
tar -xzf "$TARBALL"

echo "Running installer ..."
bash "$TMPDIR/install.sh" "$@"
