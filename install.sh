#!/usr/bin/env bash
# NPorter installer. Run as root on the target Linux host.
#
#   sudo ./install.sh [--enable] [--start|--now] [--no-systemd] [path-to-nporter-binary]
#
# Installs the binary to /etc/nporter/nporter, symlinks /usr/local/bin/nporter,
# creates a default config if missing, and installs the systemd unit. It does
# NOT enable or start the service — review your config and rules first.
set -euo pipefail

PREFIX=/etc/nporter
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC=
INSTALL_SYSTEMD=1
ENABLE_SERVICE=0
START_SERVICE=0
UNIT_INSTALLED=0

usage() {
    cat <<EOF
Usage: sudo ./install.sh [options] [path-to-nporter-binary]

Options:
  --enable       Enable nporter.service at boot.
  --start        Start nporter.service after installation.
  --now          Enable and start nporter.service.
  --no-systemd   Do not install the systemd unit.
  -h, --help     Show this help.

Runtime requirements:
  - Linux host with nftables/netfilter NAT kernel support.
  - root/CAP_NET_ADMIN for apply/daemon operations.
  - systemd is optional, only needed for service installation.
  - The nft CLI package is not required by NPorter at runtime.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --enable)
            ENABLE_SERVICE=1
            ;;
        --start)
            START_SERVICE=1
            ;;
        --now)
            ENABLE_SERVICE=1
            START_SERVICE=1
            ;;
        --no-systemd)
            INSTALL_SYSTEMD=0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -n "$BIN_SRC" ]; then
                echo "error: multiple binary paths provided" >&2
                usage >&2
                exit 2
            fi
            BIN_SRC="$1"
            ;;
    esac
    shift
done
if [ "$#" -gt 0 ]; then
    if [ -n "$BIN_SRC" ] || [ "$#" -gt 1 ]; then
        echo "error: multiple binary paths provided" >&2
        usage >&2
        exit 2
    fi
    BIN_SRC="$1"
fi
BIN_SRC="${BIN_SRC:-$HERE/nporter}"

if [ "$(uname -s)" != "Linux" ]; then
    echo "error: NPorter must be installed on Linux" >&2
    exit 1
fi
if [ "$(id -u)" != 0 ]; then
    echo "error: must run as root" >&2
    exit 1
fi
if [ ! -f "$BIN_SRC" ]; then
    echo "error: nporter binary not found at $BIN_SRC" >&2
    usage >&2
    exit 1
fi
if [ -L "$PREFIX/nporter.toml" ]; then
    echo "error: refusing symlinked config: $PREFIX/nporter.toml" >&2
    exit 1
fi

install -d -m 0750 "$PREFIX"
chown root:root "$PREFIX"
chmod 0750 "$PREFIX"
install -m 0755 "$BIN_SRC" "$PREFIX/nporter"
install -d -m 0755 /usr/local/bin
ln -sf "$PREFIX/nporter" /usr/local/bin/nporter

if [ ! -f "$PREFIX/nporter.toml" ]; then
    "$PREFIX/nporter" --config "$PREFIX/nporter.toml" list >/dev/null
    echo "created default config: $PREFIX/nporter.toml"
fi
chmod 0600 "$PREFIX/nporter.toml"

if [ "$INSTALL_SYSTEMD" = 1 ]; then
    if [ -f "$HERE/systemd/nporter.service" ]; then
        if command -v systemctl >/dev/null 2>&1; then
            install -m 0644 "$HERE/systemd/nporter.service" /etc/systemd/system/nporter.service
            systemctl daemon-reload
            UNIT_INSTALLED=1
            echo "installed systemd unit: nporter.service"
        else
            echo "warning: systemctl not found; systemd unit was not installed" >&2
        fi
    else
        echo "warning: systemd/nporter.service not found; systemd unit was not installed" >&2
    fi
fi

if [ "$ENABLE_SERVICE" = 1 ] || [ "$START_SERVICE" = 1 ]; then
    if [ "$UNIT_INSTALLED" != 1 ]; then
        echo "error: --enable/--start require an installed systemd unit" >&2
        exit 1
    fi
fi
if [ "$ENABLE_SERVICE" = 1 ]; then
    systemctl enable nporter
fi
if [ "$START_SERVICE" = 1 ]; then
    systemctl start nporter
fi

echo
echo "NPorter installed. Version: $("$PREFIX/nporter" --version)"
echo "Runtime package dependencies: none for the release binary (nft CLI not required)."
echo "Next steps:"
echo "  nporter tui                              # manage rules interactively"
echo "  nporter add ... && nporter apply"
if [ "$UNIT_INSTALLED" = 1 ]; then
    echo "  systemctl enable --now nporter           # apply on boot + run resident daemon"
    echo "  journalctl -u nporter -f                 # view daemon logs"
else
    echo "  nporter daemon                           # run the resident daemon manually"
fi
