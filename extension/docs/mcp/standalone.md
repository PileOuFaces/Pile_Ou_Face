# Pile ou Face MCP server — usage standalone

Le serveur MCP (`backends/mcp/server.py`) est un serveur JSON-RPC 2.0 stdio
standard. Il peut être utilisé par n'importe quel agent compatible MCP
(Claude Code, Codex, etc.), pas seulement depuis l'extension VS Code.

Le transport stdio est **NDJSON** (une ligne JSON par message, en lecture
comme en écriture) — le format canonique parlé par les vrais clients MCP.
L'ancien framing *Content-Length* (style LSP) reste toléré en lecture par
tolérance, mais plus jamais émis.

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
| `--json` | — | — | Sortie structurée (une entrée par agent : `agent`, `path`, `dry_run`) au lieu du texte humain |
| `--doctor` | — | — | Lance un vrai handshake MCP (NDJSON `initialize`) contre le serveur et affiche le diagnostic en JSON ; code de sortie non nul si le handshake échoue |
| `--rollback` | — | — | Restaure la config de l'agent depuis son `.bak` au lieu d'installer |

Redémarrer l'agent après l'installation pour qu'il recharge sa config MCP.

### Diagnostic (`--doctor`)

```bash
python3 setup_cli.py --agent claude --project-dir /chemin/vers/ton/projet --doctor
```

Résout l'interpréteur Python qui serait utilisé dans la config générée,
lance `server.py` en sous-processus avec ce même interpréteur et
`POF_MCP_WORKSPACE_ROOT` pointé sur le projet, puis envoie une requête
`initialize` réelle en NDJSON. La sortie JSON contient `interpreter`,
`interpreter_version`, `interpreter_is_fallback`, `handshake_ok`,
`protocol_version` et `error`. C'est le seul moyen fiable de distinguer un
problème de résolution d'interpréteur (PATH, stub Apple Python 3.9) d'un
problème de framing ou d'un vrai bug serveur — un simple `curl`/test unitaire
ne peut pas reproduire un mismatch de transport inter-process avec un
véritable agent externe.

### Annulation (`--rollback`)

```bash
python3 setup_cli.py --agent claude --project-dir /chemin/vers/ton/projet --rollback
```

Restaure le fichier de config de l'agent depuis le `.bak` créé par la
dernière installation. Échoue explicitement (`FileNotFoundError`) si aucun
backup n'existe — jamais de restauration silencieuse vers un état inconnu.

## Panneau "Connect Agents" (extension VS Code)

Depuis la palette de commandes VS Code :

- **Pile ou Face: Connect Agents (MCP)** ouvre un panneau webview qui
  pilote `setup_cli.py` sans terminal : choix de l'agent (Claude
  Code/Codex/les deux) et du scope, puis Preview (équivalent `--dry-run
  --json`), Apply, Rollback et Run Doctor, avec le JSON brut de chaque
  commande affiché dans le panneau.
- **Pile ou Face: MCP Doctor** lance directement le handshake (équivalent
  `--doctor`) et affiche le résultat en notification VS Code (info si
  `handshake_ok`, erreur sinon).
- **Pile ou Face: MCP Rollback agent config** demande l'agent à restaurer
  via un quick-pick puis exécute le rollback.

Une barre de statut ("MCP" avec icône plug/check/warning) reflète en
permanence l'état du dernier handshake, se rafraîchit automatiquement
toutes les 5 minutes, et ouvre le panneau "Connect Agents" au clic.

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
