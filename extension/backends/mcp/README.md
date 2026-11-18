# MCP Backend

Ce dossier contient l'implémentation MCP côté backend.

- `server.py` : serveur MCP (transport stdio, JSON-RPC 2.0).
- `__init__.py` : export du point d'entrée principal.

- `ai_provider.py` : fournisseurs IA cloud ; `set` enregistre la clé API dans
  `~/.pile-ou-face/.env` (le Host la transmet par stdin via `--api-key-stdin`).
- `env_loader.py` : lecture et écriture de `~/.pile-ou-face/.env`.

Protection de `~/.pile-ou-face/.env` (clés API IA locales) :

- Écriture atomique : fichier temporaire dans le même dossier puis `os.replace` ;
  en cas d'erreur, le temporaire est supprimé et l'ancien fichier reste intact.
- POSIX : dossier créé en `0700`, fichier créé en `0600` dès sa création
  (`tempfile.mkstemp`, qui utilise `os.open` avec le mode `0600`). Un dossier ou
  un fichier existant accessible au groupe ou aux autres est resserré à la
  prochaine écriture et un avertissement est journalisé (chemin et modes
  uniquement, jamais la valeur des clés).
- Windows : les modes POSIX ne s'appliquent pas. Le fichier hérite des ACL du
  dossier parent (par défaut le profil utilisateur) ; aucune ACL spécifique
  n'est posée ni vérifiée.
- Limite : ces permissions n'empêchent pas un autre processus exécuté sous le
  même compte utilisateur de lire le fichier, qui est stocké en clair.
- Les messages d'erreur d'enregistrement citent le nom de la variable et la
  raison système, jamais la clé.

Compatibilité:

- `backends/mcp_server.py` reste disponible comme wrapper de compatibilité.
