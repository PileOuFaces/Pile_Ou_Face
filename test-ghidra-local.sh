#!/bin/bash
set -e
IMAGE="pof-ghidra-local:arm64"
ELF="/Users/leoteissier/Projets/Pile_Ou_Face/example/rootme1.elf"

echo "==> Smoke test (--list)"
docker run --rm --network none "$IMAGE" /opt/pof-venv/bin/python -m backends.static.decompile --list --provider local

echo ""
echo "==> Décompilation réelle ($ELF)"
docker run --rm --network none -v "$(dirname "$ELF"):/work:ro" "$IMAGE" \
  /opt/pof-venv/bin/python3 /opt/pof/decompile.py --binary "/work/$(basename "$ELF")" \
  | python3 -c "
import sys, json
r = json.loads(sys.stdin.read())
for fn in r[:3]:
    if fn.get('error'):
        print('ERROR:', fn['error'])
    else:
        print('OK:', fn['name'], '-', len(fn.get('code', '')), 'chars')
"
