#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh <image> <decompiler> [platform] }"
DECOMPILER="${2:?usage: smoke-test.sh <image> <decompiler> [platform] }"
RUNTIME_PLATFORM="${3:-}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

docker_run_base=(docker run --rm --network none --hostname localhost)
if [ -n "$RUNTIME_PLATFORM" ]; then
  docker_run_base+=(--platform "$RUNTIME_PLATFORM")
fi

extract_json() {
  local file_path="$1"
  python3 - "$file_path" <<'PY'
import json
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").strip()
if not text:
    raise SystemExit("stdout vide")

try:
    data = json.loads(text)
except Exception:
    lines = text.splitlines()
    data = None
    for index in range(len(lines)):
        candidate = "\n".join(lines[index:]).strip()
        if not candidate:
            continue
        try:
            data = json.loads(candidate)
            break
        except Exception:
            continue
    if data is None:
        raise SystemExit("aucun JSON valide trouve dans stdout")

print(json.dumps(data))
PY
}

print_failure_context() {
  local stdout_file="$1"
  local stderr_file="$2"
  echo "----- stdout -----"
  cat "$stdout_file" || true
  echo "----- stderr -----"
  cat "$stderr_file" || true
}

assert_backend_listed() {
  local json_file="$1"
  local decompiler="$2"
  python3 - "$json_file" "$decompiler" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
decompiler = sys.argv[2]

if decompiler not in payload:
    raise SystemExit(f"backend absent du JSON: {decompiler}")
if payload[decompiler] is not True:
    raise SystemExit(f"backend non disponible dans l'image: {decompiler} -> {payload[decompiler]!r}")

print(f"✅ --list OK pour {decompiler}")
PY
}

assert_function_decompile() {
  local json_file="$1"
  local decompiler="$2"
  python3 - "$json_file" "$decompiler" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
decompiler = sys.argv[2]

if payload.get("error") not in (None, "", "null"):
    raise SystemExit(f"erreur backend: {payload.get('error')}")
if payload.get("decompiler") != decompiler:
    raise SystemExit(f"backend inattendu: {payload.get('decompiler')!r}")

code = str(payload.get("code") or "").strip()
if len(code) < 12:
    raise SystemExit("pseudo-C trop court ou vide")
if not any(marker in code for marker in ("return", "add", "main")):
    raise SystemExit("pseudo-C inattendu: aucun marqueur attendu")

print(f"✅ decompilation fonctionnelle OK pour {decompiler}")
PY
}

assert_full_decompile() {
  local json_file="$1"
  local decompiler="$2"
  python3 - "$json_file" "$decompiler" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
decompiler = sys.argv[2]

if payload.get("error") not in (None, "", "null"):
    raise SystemExit(f"erreur backend: {payload.get('error')}")
if payload.get("decompiler") != decompiler:
    raise SystemExit(f"backend inattendu: {payload.get('decompiler')!r}")

functions = payload.get("functions")
if not isinstance(functions, list) or len(functions) < 2:
    raise SystemExit("decompilation complete trop courte")
joined = "\n".join(str(item.get("code") or "") for item in functions if isinstance(item, dict))
if not any(marker in joined for marker in ("add", "main", "return")):
    raise SystemExit("pseudo-C complet inattendu")

print(f"✅ decompilation complete OK pour {decompiler}")
PY
}

echo "==> Smoke test image=$IMAGE decompiler=$DECOMPILER platform=${RUNTIME_PLATFORM:-native}"

LIST_STDOUT="$TMPDIR/list.stdout"
LIST_STDERR="$TMPDIR/list.stderr"
if ! "${docker_run_base[@]}" "$IMAGE" \
  /opt/pof-venv/bin/python -m backends.static.decompile --list --provider local \
  >"$LIST_STDOUT" 2>"$LIST_STDERR"; then
  print_failure_context "$LIST_STDOUT" "$LIST_STDERR"
  exit 1
fi
extract_json "$LIST_STDOUT" >"$TMPDIR/list.json" || {
  print_failure_context "$LIST_STDOUT" "$LIST_STDERR"
  exit 1
}
assert_backend_listed "$TMPDIR/list.json" "$DECOMPILER"

case "$DECOMPILER" in
  ghidra|retdec|angr)
    cat >"$TMPDIR/sample.c" <<'C'
#include <stdio.h>
__attribute__((noinline)) int add(int a, int b) { return a + b; }
int main(void) { return add(2, 3); }
C
    cc -O0 -g -fno-inline -o "$TMPDIR/sample.bin" "$TMPDIR/sample.c"

    FUNC_STDOUT="$TMPDIR/function.stdout"
    FUNC_STDERR="$TMPDIR/function.stderr"
    if ! "${docker_run_base[@]}" -v "$TMPDIR:/input:ro" "$IMAGE" \
      /opt/pof-venv/bin/python -m backends.static.decompile \
      --provider local \
      --decompiler "$DECOMPILER" \
      --binary /input/sample.bin \
      --addr 0x0 \
      --func-name add \
      >"$FUNC_STDOUT" 2>"$FUNC_STDERR"; then
      print_failure_context "$FUNC_STDOUT" "$FUNC_STDERR"
      exit 1
    fi
    extract_json "$FUNC_STDOUT" >"$TMPDIR/function.json" || {
      print_failure_context "$FUNC_STDOUT" "$FUNC_STDERR"
      exit 1
    }
    assert_function_decompile "$TMPDIR/function.json" "$DECOMPILER"

    FULL_STDOUT="$TMPDIR/full.stdout"
    FULL_STDERR="$TMPDIR/full.stderr"
    if ! "${docker_run_base[@]}" -v "$TMPDIR:/input:ro" "$IMAGE" \
      /opt/pof-venv/bin/python -m backends.static.decompile \
      --provider local \
      --decompiler "$DECOMPILER" \
      --binary /input/sample.bin \
      --full \
      >"$FULL_STDOUT" 2>"$FULL_STDERR"; then
      print_failure_context "$FULL_STDOUT" "$FULL_STDERR"
      exit 1
    fi
    extract_json "$FULL_STDOUT" >"$TMPDIR/full.json" || {
      print_failure_context "$FULL_STDOUT" "$FULL_STDERR"
      exit 1
    }
    assert_full_decompile "$TMPDIR/full.json" "$DECOMPILER"
    ;;
  *)
    echo "ℹ️ smoke test fonctionnel non requis pour $DECOMPILER"
    ;;
esac
