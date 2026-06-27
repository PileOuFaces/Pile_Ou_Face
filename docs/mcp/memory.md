# MCP Memory - Pile ou Face

Ce fichier sert de contexte rapide pour un agent qui utilise le serveur MCP de ce repo.

## Projet

- Nom: `Pile ou Face`
- Domaine: reverse engineering dans VS Code (ELF, PE, Mach-O)
- Stack principale: extension VS Code (JS) + backend Python

## MCP (etat actuel)

- Transport: `stdio`
- Protocole: JSON-RPC 2.0
- Methodes: `initialize`, `notifications/initialized`, `tools/list`, `tools/call`
- Entree principale: `backends/mcp/server.py`
- Wrapper compatibilite: `backends/mcp_server.py`
- Fichier projet: `.mcp.json` a la racine pour les clients MCP compatibles
- Bridge Ollama: `backends/mcp/ollama_bridge.py`
- Couverture outils: 49 outils (voir `docs/mcp/modules.md`)
- Decompilation auto: compare tous les backends disponibles et renvoie le meilleur score avec le detail `quality_details.backends`
- Compat legacy: `quality` peut encore etre envoye aux tools MCP de decompilation, mais il est ignore

## Commandes utiles

```bash
make install
python3 backends/mcp/server.py --transport stdio
python3 backends/mcp/ollama_bridge.py --list-tools
python3 backends/mcp/ollama_bridge.py --model qwen3:8b --prompt "Analyse examples/demo_analysis.elf"
```

## Conventions importantes

- Les outils acceptent `binary_path` ou `binary` selon le cas.
- Les adresses/offets peuvent etre en decimal ou en hex (`0x...`).
- Resolution auto des binaires:
  - chemin absolu,
  - chemin relatif workspace,
  - nom de fichier seul (recherche workspace).
- Les erreurs outils sont retournees avec `isError: true`.
- `structuredContent` contient la charge utile exploitable par le client.

Alias outils toleres (compatibilite):

- `strings` -> `extract_strings`
- `symbols` / `symboles` -> `get_symbols`
- `disasm` / `asm` -> `disassemble`
- `xrefs` -> `get_xrefs`

## Reperes de code

- Routeur outils: `backends/mcp/server.py` (`_call_tool`)
- Modules exposes: `backends/static/*.py`
- Tests MCP: `backends/static/tests/test_mcp_server.py`
- Tests bridge Ollama: `backends/static/tests/test_ollama_bridge.py`

## Binaire de demo

- Exemple stable pour tests rapides: `examples/demo_analysis.elf`

## Source de verite documentation

- Index MCP: `docs/mcp/README.md`
- Installation: `docs/mcp/INSTALLATION.md`
- Implementation: `docs/mcp/IMPLEMENTATION.md`
- Tests: `docs/mcp/TESTS.md`
- Changelog: `docs/mcp/CHANGELOG.md`

## Regle de maintenance

Mettre a jour ce fichier a chaque changement MCP (nouveaux tools, arguments, flux bridge, commandes, ou chemins).
