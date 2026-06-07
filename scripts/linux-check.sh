#!/usr/bin/env bash
# Compile-check (and optionally test) the Linux netlink backend inside a
# container, since rustables needs Linux kernel headers + libclang that aren't
# available when building natively on macOS.
#
# Usage: scripts/linux-check.sh [build|test]   (default: build)
set -euo pipefail
ACTION="${1:-build}"
case "$ACTION" in
  build|test|check|clippy) ;;
  *)
    echo "usage: scripts/linux-check.sh [build|test|check|clippy]" >&2
    exit 2
    ;;
esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_IMAGE="${RUST_IMAGE:-rust:1}"
docker run --rm \
  -v "$ROOT":/work -w /work \
  -e CARGO_TARGET_DIR=/work/target-linux \
  "$RUST_IMAGE" bash -c "
    if ! command -v clang >/dev/null; then
      apt-get update -qq && apt-get install -y -qq clang libclang-dev linux-libc-dev >/dev/null 2>&1
    fi
    cargo ${ACTION}
  "
