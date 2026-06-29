#!/usr/bin/env bash
# Build local Docker images pour les décompilateurs.
#
# Usage:
#   ./build.sh                    # tous les décompilateurs, arm64 + amd64
#   ./build.sh ghidra             # ghidra seulement, arm64 + amd64
#   ./build.sh ghidra arm64       # ghidra arm64 seulement
#   ./build.sh all amd64          # tous, amd64 seulement
#
# Images produites : pof-<decompiler>:<arch>  (ex: pof-ghidra:arm64)
# Note : retdec est amd64-only — arm64 ignoré automatiquement.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

ALL_DECOMPILERS=(ghidra retdec angr)
ALL_ARCHS=(arm64 amd64)

TARGET_DECOMPILER="${1:-all}"
TARGET_ARCH="${2:-all}"

if [ "$TARGET_DECOMPILER" = "all" ]; then
  DECOMPILERS=("${ALL_DECOMPILERS[@]}")
else
  DECOMPILERS=("$TARGET_DECOMPILER")
fi

if [ "$TARGET_ARCH" = "all" ]; then
  ARCHS=("${ALL_ARCHS[@]}")
else
  ARCHS=("$TARGET_ARCH")
fi

BUILT=()
SKIPPED=()

for d in "${DECOMPILERS[@]}"; do
  for arch in "${ARCHS[@]}"; do
    if [ "$d" = "retdec" ] && [ "$arch" = "arm64" ]; then
      echo "-- retdec/arm64 ignoré (binaire pré-compilé amd64-only)"
      SKIPPED+=("retdec/arm64")
      continue
    fi

    echo ""
    echo "==> Build pof-$d:$arch  (platform=linux/$arch)"
    if [ "$arch" = "amd64" ] && [ "$(uname -m)" != "x86_64" ]; then
      echo "    (cross-build via QEMU — peut prendre plusieurs minutes)"
    fi

    docker buildx build \
      --platform "linux/$arch" \
      --load \
      -t "pof-$d:$arch" \
      -f "docker/decompilers/$d/Dockerfile" \
      .

    echo "✓ pof-$d:$arch OK"
    BUILT+=("pof-$d:$arch")
  done
done

echo ""
echo "=============================="
echo "Images construites :"
for img in "${BUILT[@]}"; do echo "  $img"; done
if [ ${#SKIPPED[@]} -gt 0 ]; then
  echo "Ignorés :"
  for s in "${SKIPPED[@]}"; do echo "  $s"; done
fi
