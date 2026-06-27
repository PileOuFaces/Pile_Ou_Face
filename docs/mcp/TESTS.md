# Tests MCP

Ce document regroupe les commandes de test du serveur MCP.

## 1. Tests unitaires

Lancer les tests MCP, bridge Ollama et providers IA :

```bash
python3 -m pytest \
  backends/static/tests/test_mcp_server.py \
  backends/static/tests/test_ollama_bridge.py \
  backends/static/tests/test_mcp_ai_provider.py
```

Attendu :

- tous les tests passent ;
- les tests providers utilisent des flux SSE simules et ne demandent aucune cle API.

## 2. Tests extension

```bash
cd extension
npm run build
npm run typecheck
npm test
```

La suite couvre notamment :

- le forwarding NDJSON Ollama et cloud ;
- les compteurs de tokens finaux ;
- la persistance du modele ;
- le contexte IA genere depuis une instruction `.disasm.asm`.

## 3. Smoke test stdio

Verifier la boucle protocolaire `initialize` + `tools/list` :

```bash
python3 - <<'PY'
import json, subprocess

p = subprocess.Popen(
    ["python3", "backends/mcp/server.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

def send(req):
    body = json.dumps(req).encode("utf-8")
    frame = f"Content-Length: {len(body)}\\r\\n\\r\\n".encode("ascii") + body
    p.stdin.write(frame)
    p.stdin.flush()

    header = b""
    while b"\\r\\n\\r\\n" not in header:
        b = p.stdout.read(1)
        if not b:
            raise RuntimeError("EOF")
        header += b

    lines = header.split(b"\\r\\n")
    content_length = None
    for line in lines:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break
    if content_length is None:
        raise RuntimeError("Missing Content-Length")

    payload = p.stdout.read(content_length)
    return json.loads(payload.decode("utf-8"))

r1 = send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
r2 = send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

print("init_ok =", "result" in r1)
print("tools_count =", len(r2.get("result", {}).get("tools", [])))

p.terminate()
p.wait(timeout=2)
PY
```

Attendu :

- `init_ok = True`
- `tools_count = 49` (ou plus si de nouveaux tools ont ete ajoutes)
