# Changelog MCP

## 2026-06-21 — V4

- Ajout du bouton `Arreter` dans le Dashboard et le widget flottant.
- Annulation commune des generations Ollama et cloud par `requestId`.
- Terminaison idempotente du processus actif et conservation du texte deja streame.
- Rendu Markdown securise des reponses finales, sans injection HTML.
- Prise en charge des titres, listes, tableaux, citations, liens autorises et blocs de code.
- Actions de modification des prompts et de regeneration des reponses depuis
  n'importe quelle bulle compatible.
- Reconstruction explicite de la branche de conversation et reutilisation du
  modele associe a la reponse remplacee.
- Export de la conversation active en Markdown ou JSON depuis le Dashboard et
  le widget flottant.
- Ajout d'un snapshot JSON versionne avec modeles, dates, contexte binaire et
  consommation de tokens.
- Renommage inline persistant des conversations.
- Recherche locale sans accents et tri par date, titre ou modele dans
  l'historique du Dashboard.
- Affichage du budget de contexte approximatif dans les deux vues du chat.
- Avertissement avant envoi lorsqu'une part importante de l'historique doit
  etre ignoree ou raccourcie.
- Parametres globaux et par conversation pour la temperature, le top-p et la
  limite de tokens de sortie.
- Transmission normalisee de ces reglages a Ollama, Anthropic, Gemini,
  OpenAI, Mistral, OpenRouter, Groq et DeepSeek.
- Catalogue local et date de tarifs cloud par modele ou motif.
- Estimation du cout par reponse et par conversation, avec indication claire
  des totaux partiels et des modeles sans tarif.
- Actions `Demander a l'IA` dans le CFG, le pseudo-C, les strings, les imports
  et les resultats de recherche.
- Construction commune d'un prompt avec binaire, architecture, fonction,
  adresse, filtres et contenu visible, limite a 6 000 caracteres.

## 2026-06-21 — V3

- Streaming natif des providers cloud OpenAI, Anthropic, Mistral, Gemini,
  OpenRouter, Groq et DeepSeek.
- Normalisation du flux provider en evenements NDJSON `token`, `done` et `error`.
- Affichage progressif commun avec Ollama et conservation des tokens entree,
  sortie et total.
- Ajout de l'action contextuelle VS Code pour envoyer une instruction ou une
  selection `.disasm.asm` vers le composeur IA.
- Widget Assistant IA redimensionnable a la souris, taille persistante et
  comportement responsive conserve.
- Ajout de tests SSE simules pour les providers et de tests extension pour le
  forwarding du flux et le contexte de desassemblage.
- Roadmap restructuree pour preparer V4 : arret de generation, Markdown
  securise, export, gestion avancee des conversations et estimation des couts.

## 2026-05-14

- Ajout d'un fichier projet [`.mcp.json`](../../.mcp.json) a la racine pour declarer le serveur MCP `pile-ou-face` en transport stdio.
- La decompilation auto cote backend/MCP (`decompile_function`, `decompile_binary`) ne s'arrete plus au premier backend valide :
  - tous les backends disponibles sont lances,
  - le meilleur resultat est choisi via le scoring existant,
  - `quality_details.backends` liste maintenant tous les candidats observes, succes comme erreurs.
- Les tools MCP `decompile_function` et `decompile_binary` tolerent encore l'argument legacy `quality`, mais il est maintenant ignore pour compatibilite avec la signature backend actuelle.

## 2026-04-24

- Deplacement de la memoire MCP vers `docs/mcp/memory.md` (au meme endroit que le reste de la doc MCP).
- Ajout du chargement automatique de la memoire cote serveur MCP (`backends/mcp/server.py`) :
  - lecture de `docs/mcp/memory.md` (fallback legacy `docs/mcp/docs/memory.md`, puis `memory.md`),
  - exposition du contexte via `initialize.result.instructions` quand disponible.
- Ajout du chargement automatique de la memoire cote bridge Ollama (`backends/mcp/ollama_bridge.py`) :
  - lecture de `docs/mcp/memory.md` (fallback legacy `docs/mcp/docs/memory.md`, puis `memory.md`),
  - injection du contexte dans le `system prompt` a chaque requete.
- Ajout d'une compatibilite d'alias de tools pour eviter les erreurs `Unknown tool` quand le modele utilise un nom proche :
  - cote serveur MCP: resolution d'alias (`strings` -> `extract_strings`, `symbols` -> `get_symbols`, `disasm` -> `disassemble`, etc.),
  - cote bridge Ollama: remap des `tool_calls` vers les noms canoniques exposes par `tools/list`.
- Ajout de tests unitaires couvrant cette integration (`test_mcp_server.py`, `test_ollama_bridge.py`).

## 2026-04-14

- Ajout d'une integration UI Ollama dans le hub VS Code (`extension/webview/shared/panel-outils.html` + `extension/webview/hub.js`).
- Ajout de la selection de modele Ollama, saisie de prompt et affichage de reponse directement dans l'onglet `Outils`.
- Ajout des handlers extension (`hubOllamaListModels`, `hubOllamaPrompt`) pour:
  - lister les modeles via `GET /api/tags`,
  - executer `backends/mcp/ollama_bridge.py` sans passer par le terminal.
- Mise a jour de la documentation Ollama pour inclure le flux depuis l'extension.
- Deplacement de l'UI Ollama/MCP depuis `Outils` vers le `Dashboard` (page d'accueil).
- Passage en mode discussion (historique local + contexte automatique reinjecte dans les prompts suivants).
- Ajout du bouton `Nouvelle discussion` pour reinitialiser le contexte depuis l'UI.
- Amelioration du bridge Ollama pour mieux comprendre les demandes naturelles ("code asm", "desassemblage", "symboles", "strings").
- Fallback automatique et plus robuste quand le modele ne lance pas les tools (outil cible selon intention + resume `get_binary_info` en secours).
- Resolution fuzzy des noms de binaires cote MCP (ex: `vul_demo.elf` peut resoudre `vuln_demo.elf`).
- Ajout de tests unitaires sur le fallback intent-aware et la resolution fuzzy des chemins.
- Ajout d'un historique multi-conversations dans l'UI Dashboard Ollama (liste des discussions, reprise d'un fil, bouton `Vider`).
- Ajout d'un widget IA flottant accessible depuis tous les onglets pour discuter avec MCP sans quitter le panneau courant.
- Fiabilisation du tool-calling dans `ollama_bridge.py`:
  - filtrage des tools exposes selon l'intention detectee,
  - auto-completion/normalisation des arguments tools (`binary_path`, `max_lines`),
  - resolution de binaire via `find_files` a partir d'indices de prompt,
  - gestion robuste des erreurs tools sans casser la boucle agent.
- Ajout de tests unitaires dedies a ces mecanismes de fiabilite.

## 2026-03-27

- Creation du serveur MCP backend (stdio, JSON-RPC 2.0).
- Exposition des tools MVP : `get_binary_info`, `disassemble`, `get_symbols`, `extract_strings`, `get_xrefs`.
- Creation du package `backends/mcp/` + wrapper de compatibilite `backends/mcp_server.py`.
- Ajout des tests unitaires `backends/static/tests/test_mcp_server.py`.
- Mise en place de la documentation dediee dans `mcp/docs/`.

## 2026-04-13

- Ajout du bridge `backends/mcp/ollama_bridge.py` pour connecter Ollama au serveur MCP.
- Ajout des tests `backends/static/tests/test_ollama_bridge.py`.
- Ajout de la doc d'integration `docs/mcp/OLLAMA.md`.
- Mise a jour de `INSTALLATION.md`, `IMPLEMENTATION.md`, `TESTS.md` et index `README.md`.
- Ajout du tool MCP `find_files` (recherche workspace par nom/substring/glob).
- Resolution automatique des chemins binaires par nom de fichier (ex: `demo_analysis.elf`).
- Ajout de tests MCP pour la recherche de fichiers et la resolution de path.
- Correction du tool `disassemble` pour fonctionner sans argument `--output` (sorties auto-generees).
- Ajout du parametre `max_lines` pour limiter le volume de lignes retournees par `disassemble`.
- Ajustement du prompt systeme du bridge Ollama pour eviter les instructions CLI a l'utilisateur.
- Fallback du bridge Ollama: retry automatique quand le modele repond "please provide a request".
- Robustification de la detection de reponse "noop" (inclut "I still need a file...").
- Extension du routeur MCP `backends/mcp/server.py` pour couvrir l'ensemble des outils de `docs/mcp/modules.md` (49/49).
- Ajout des handlers MCP pour annotations, cache, regles YARA/CAPA, CFG/call graph, decompilation, export, scans, recherche, patch, etc.
- Normalisation unifiee des parametres (`int`, `float`, offsets hex/dec) et chargement automatique des mappings de desassemblage pour les outils CFG/XREF.
- Documentation MCP mise a jour (`IMPLEMENTATION.md`, `TESTS.md`) pour refleter la couverture complete et les commandes de verification actuelles.
