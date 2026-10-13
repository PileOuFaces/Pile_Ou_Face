# Pile ou Face MCP server — usage standalone

Le serveur MCP (`backends/mcp/server.py`) est un serveur JSON-RPC 2.0 stdio
standard. Il peut être utilisé par n'importe quel agent compatible MCP
(Claude Code, Codex, etc.), pas seulement depuis l'extension VS Code.

## Installation automatique (Claude Code / Codex)

```bash
cd backends/mcp
python3 setup_cli.py --project-dir /chemin/vers/ton/projet
```

Par défaut (`--agent all`) le script enregistre le serveur `pile-ou-face` :

- dans Claude Code, en écrivant `mcpServers.pile-ou-face` dans
  `<project-dir>/.mcp.json` (scope projet) ou `~/.claude.json` avec
  `--scope user` ;
- dans Codex, en écrivant la table `[mcp_servers.pile-ou-face]` dans
  `~/.codex/config.toml`.

Chaque fichier modifié est sauvegardé en `<fichier>.bak` avant écriture, et
seule l'entrée `pile-ou-face` est touchée — le reste de la config (y compris
d'autres secrets déjà présents) est préservé tel quel.

Options :

| Flag | Valeurs | Défaut | Rôle |
|------|---------|--------|------|
| `--agent` | `claude`, `codex`, `all` | `all` | Quel(s) agent(s) configurer |
| `--project-dir` | chemin | cwd | Projet que le serveur doit scanner |
| `--scope` | `project`, `user` | `project` | Config Claude Code : projet ou utilisateur |
| `--dry-run` | — | — | Affiche les changements sans écrire |

Redémarrer l'agent après l'installation pour qu'il recharge sa config MCP.

## Variable d'environnement `POF_MCP_WORKSPACE_ROOT`

Le serveur distingue deux racines :

- `ROOT` : dossier d'installation de l'extension (imports Python, cache,
  venv) — ne change jamais.
- `WORKSPACE_ROOT` : projet sur lequel l'agent travaille, utilisé par
  `find_files` et par la résolution floue de binaire. Par défaut c'est le
  `cwd` au lancement du serveur ; `setup_cli.py` le fixe explicitement via
  `POF_MCP_WORKSPACE_ROOT` dans l'entrée MCP générée, pour que ça reste
  correct même si l'agent lance le serveur depuis un autre répertoire.

## Dépendances Python

Le serveur utilise un `.venv` local à l'extension s'il existe
(`backends/.venv`), sinon l'interpréteur `python3` courant. Pour un usage
hors du repo de l'extension, installer les dépendances listées dans
`pyproject.toml`/`requirements` dans l'environnement Python utilisé pour
lancer `server.py` (voir `#451` pour le suivi du packaging npm/pip autonome,
hors scope de cette première itération).

## Frontière gratuit / premium

Les ~40 outils statiques (désassemblage, décompilation, CFG, call graph,
xrefs, imports, DWARF, entropie, strings, symbols, recherche binaire,
scripts sandboxés, outils IA) sont disponibles sans licence. Le tool
`plugin_invoke` reste soumis au consentement et au runtime des plugins
premium (`backends.plugins.consent` / `backends.plugins.runtime`) — un agent
externe sans licence active aura accès aux outils statiques mais pas aux
plugins premium.
