#!/usr/bin/env bash
# Build the netlink backend and run real nftables CLI tests inside a privileged
# Linux container (throwaway). Exercises apply/observe/incremental reconcile
# against an actual kernel — the path that cannot be tested on macOS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_IMAGE="${RUST_IMAGE:-rust:1}"
SCRIPT='
set -e
command -v nft >/dev/null || { apt-get update -qq && apt-get install -y -qq clang libclang-dev linux-libc-dev nftables >/dev/null 2>&1; }
cargo build 2>&1 | tail -1
BIN=/work/target-container/debug/nporter
C="$BIN --config /tmp/n.toml"
$C add ssh --listen-port 10022 --target-ip 192.0.2.11 --target-port 22 >/dev/null
$C add web6 --listen-ip :: --listen-port 8080 --target-ip fd00::1 --target-port 80 >/dev/null
echo "apply#1:               $($C apply)"
$C set ssh --target-port 2222 >/dev/null
echo "ssh port change:       $($C apply)   (expect deleted=5 added=5 kept=6)"
$C masquerade web6 --enabled false >/dev/null
echo "web6 masq off:         $($C apply)   (expect deleted=1 kept=10)"
$C delete ssh >/dev/null; $C delete web6 >/dev/null
echo "delete all:            $($C apply)   (expect kept=1 base)"
echo "kernel dnat/masq left: $(nft list table inet nporter | grep -cE "dnat|masquerade")  (expect 0)"
'
docker run --rm --privileged \
  -v "$ROOT":/work -w /work \
  -e CARGO_TARGET_DIR=/work/target-container \
  "$RUST_IMAGE" bash -c "$SCRIPT"
