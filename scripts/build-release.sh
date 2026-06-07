#!/usr/bin/env bash
# Build static Linux musl release binaries inside Linux containers.
# rustables uses bindgen against Linux kernel headers, so macOS hosts build via
# Docker instead of native cross-compilation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_IMAGE="${RUST_IMAGE:-rust:1}"

build_one() {
  local arch="$1"
  local platform="$2"
  local target="$3"

  docker run --rm --platform "$platform" \
    -v "$ROOT":/work -w /work \
    -e CARGO_TARGET_DIR=/work/target-linux \
    -e NPORTER_BUILD_TARGET="$target" \
    "$RUST_IMAGE" bash -c '
      set -e
      if ! command -v clang >/dev/null || ! command -v musl-gcc >/dev/null; then
        apt-get update -qq
        apt-get install -y -qq clang libclang-dev linux-libc-dev musl-tools musl-dev >/dev/null 2>&1
      fi
      rustup target add "$NPORTER_BUILD_TARGET" >/dev/null 2>&1 || true
      cargo build --release --target "$NPORTER_BUILD_TARGET"
    '
  echo "ARTIFACT[$arch]: target-linux/$target/release/nporter"
}

case "${1:-all}" in
  amd64)
    build_one amd64 linux/amd64 x86_64-unknown-linux-musl
    ;;
  arm64)
    build_one arm64 linux/arm64 aarch64-unknown-linux-musl
    ;;
  all)
    build_one amd64 linux/amd64 x86_64-unknown-linux-musl
    build_one arm64 linux/arm64 aarch64-unknown-linux-musl
    ;;
  *)
    echo "usage: $0 [amd64|arm64|all]" >&2
    exit 2
    ;;
esac
