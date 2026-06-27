# Installation MCP

Ce guide explique comment lancer le serveur MCP local de Pile ou Face.

## Prerequis

- Python 3.8+
- Dependances backend installees (`make install`)
- Dependances outils selon usage (ex: `lief`, `capstone`, `yara`, `flare-capa`, `pyelftools`)

## Installation backend

Depuis la racine du projet :

```bash
make install
```

## Lancement du serveur MCP

Implementation principale :

```bash
python3 backends/mcp/server.py --transport stdio
```

Configuration projet prete a l'emploi :

- Le repo fournit maintenant un fichier [`.mcp.json`](../../.mcp.json) a la racine.
- Un client MCP compatible qui sait lire la configuration projet peut donc lancer directement le serveur `pile-ou-face` sans recopier la commande a la main.

Wrapper de compatibilite (equivalent) :

```bash
python3 backends/mcp_server.py --transport stdio
```

Mode debug :

```bash
python3 backends/mcp/server.py --transport stdio --debug
```

## Verification rapide

Verifier que l'aide CLI s'affiche :

```bash
python3 backends/mcp/server.py --help
```

ou :

```bash
python3 backends/mcp_server.py --help
```

Si la commande retourne l'usage du serveur, l'installation est correcte.

## Integration Ollama (bridge local)

Le bridge Ollama <-> MCP se lance avec :

```bash
python3 backends/mcp/ollama_bridge.py --list-tools
```

Option contexte memoire (active par defaut) :

```bash
python3 backends/mcp/ollama_bridge.py --model qwen3:8b --prompt "Analyse demo_analysis.elf" --memory-path docs/mcp/memory.md
```

Verifier la couverture outils exposee :

```bash
python3 backends/mcp/ollama_bridge.py --list-tools | wc -l
```

Attendu : `49`.

Commande one-shot :

```bash
python3 backends/mcp/ollama_bridge.py --model qwen3:8b --prompt "Analyse le binaire examples/demo_analysis.elf"
```

Ce script demarre automatiquement le serveur MCP local et route les `tool_calls` Ollama vers MCP.
