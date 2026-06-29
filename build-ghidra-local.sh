#!/bin/bash
set -e
cd "$(dirname "$0")"
docker buildx build --platform linux/arm64 --load -t pof-ghidra-local:arm64 -f docker/decompilers/ghidra/Dockerfile .
