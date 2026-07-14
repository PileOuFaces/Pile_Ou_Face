#!/usr/bin/env bash
# Teste les images Docker locales des décompilateurs.
#
# Usage:
#   ./test.sh                     # tous les décompilateurs, arm64 + amd64
#   ./test.sh ghidra              # ghidra seulement, arm64 + amd64
#   ./test.sh ghidra arm64        # ghidra arm64 seulement
#   ./test.sh all amd64           # tous, amd64 seulement
#
# Prérequis : avoir buildé les images avec build.sh
# Binaire de test : ../../../example/rootme1.elf (x86 32-bit ELF)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOKE_SCRIPT="$REPO_ROOT/docker/decompilers/smoke-test.sh"
BINARY="$REPO_ROOT/../example/rootme1.elf"

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

if [ ! -f "$BINARY" ]; then
  echo "Binaire de test introuvable : $BINARY"
  echo "Placer un ELF dans $(dirname "$BINARY")/"
  exit 1
fi

PASS=()
FAIL=()
SKIP=()

for d in "${DECOMPILERS[@]}"; do
  for arch in "${ARCHS[@]}"; do
    IMAGE="pof-$d:$arch"

    if [ "$d" = "retdec" ] && [ "$arch" = "arm64" ]; then
      SKIP+=("$d/$arch (amd64-only)")
      continue
    fi

    if ! docker image inspect "$IMAGE" &>/dev/null; then
      echo ""
      echo "-- $d/$arch : image absente, build d'abord avec build.sh"
      SKIP+=("$d/$arch (image absente)")
      continue
    fi

    echo ""
    echo "==> Test $d/$arch"

    # 1. Smoke --list
    echo -n "   --list ... "
    LIST_OUT=$(docker run --rm --network none --platform "linux/$arch" \
      "$IMAGE" /opt/pof-venv/bin/python -m backends.static.decompile --list --provider local \
      2>/dev/null)
    if echo "$LIST_OUT" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); sys.exit(0 if '$d' in d else 1)" 2>/dev/null; then
      echo "OK"
    else
      echo "FAIL"
      echo "$LIST_OUT"
      FAIL+=("$d/$arch --list")
      continue
    fi

    # 2. Décompilation avec rootme1.elf
    echo -n "   decompile ... "
    BIN_DIR="$(dirname "$BINARY")"
    BIN_NAME="$(basename "$BINARY")"
    DECOMP_OUT=$(docker run --rm --network none --platform "linux/$arch" \
      -v "$BIN_DIR:/work:ro" \
      "$IMAGE" /opt/pof-venv/bin/python -m backends.static.decompile \
      --provider local --decompiler "$d" --binary "/work/$BIN_NAME" \
      2>/dev/null)
    if echo "$DECOMP_OUT" | python3 -c "
import sys, json
r = json.loads(sys.stdin.read())
code = r.get('code') or ''
err  = r.get('error') or ''
if err: sys.exit(err)
if len(code) < 10: sys.exit('code trop court')
" 2>/dev/null; then
      CHARS=$(echo "$DECOMP_OUT" | python3 -c "import sys,json; print(len(json.loads(sys.stdin.read()).get('code','')))")
      echo "OK ($CHARS chars)"
      PASS+=("$d/$arch")
    else
      ERR=$(echo "$DECOMP_OUT" | python3 -c "import sys,json; r=json.loads(sys.stdin.read()); print(r.get('error','?'))" 2>/dev/null || echo "?")
      echo "FAIL — $ERR"
      FAIL+=("$d/$arch: $ERR")
    fi
  done
done

echo ""
echo "=============================="
if [ ${#PASS[@]} -gt 0 ]; then
  echo "PASS :"
  for r in "${PASS[@]}"; do echo "  ✓ $r"; done
fi
if [ ${#SKIP[@]} -gt 0 ]; then
  echo "SKIP :"
  for r in "${SKIP[@]}"; do echo "  - $r"; done
fi
if [ ${#FAIL[@]} -gt 0 ]; then
  echo "FAIL :"
  for r in "${FAIL[@]}"; do echo "  ✗ $r"; done
  exit 1
fi
echo "Tous les tests passés."
