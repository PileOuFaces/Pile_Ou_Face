# Implementation MCP

Ce document decrit l'implementation actuelle du serveur MCP backend.

## Emplacement du code

- Serveur principal : `backends/mcp/server.py`
- Wrapper compatibilite : `backends/mcp_server.py`
- Bridge Ollama <-> MCP : `backends/mcp/ollama_bridge.py`
- Providers IA cloud : `backends/mcp/ai_provider.py`
- Orchestration host : `extension/src/static/staticHandlers.ts` et `extension/src/shared/sharedHandlers.ts`
- Chat webview : `extension/webview/shared/outils.js` et `extension/webview/shared/messages.js`

## Transport et protocole

- Transport actif : `stdio`
- Protocole : JSON-RPC 2.0
- Framing : `Content-Length` + payload JSON UTF-8

Methodes supportees :

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`

Contexte memoire:

- Le serveur charge `docs/mcp/memory.md` (fallback legacy: `docs/mcp/docs/memory.md` puis `memory.md`).
- Si le fichier existe, `initialize` retourne aussi un champ `instructions` avec ce contexte.
- Le bridge `ollama_bridge.py` ajoute automatiquement ce contenu au `system prompt` pour ameliorer les reponses.

## Couverture des outils

Le serveur expose la matrice complete documentee dans `docs/mcp/modules.md`.

- Nombre total d'outils exposes : `49`
- Noms exposes : `annotations_*`, `cache_*`, `rules_*`, `disassemble`, `build_cfg*`, `build_call_graph`, `get_xrefs`, `get_symbols`, `extract_strings`, `get_binary_info`, `analyze_imports`, `decompile_*`, `plugins_list`, `plugin_invoke`, `find_files`, etc.
- Les fonctions optionnelles ne sont plus exposees en natif par le serveur public. Quand un plugin est actif, ses commandes apparaissent dynamiquement dans `tools/list` sous la forme `plugin.<namespace>.<action>`.

Verification rapide :

```bash
python3 backends/mcp/ollama_bridge.py --list-tools
```

## Routage et normalisation des arguments

Le routeur `_call_tool()` dans `backends/mcp/server.py` :

- normalise les chemins (`binary_path`/`binary`) ;
- accepte les offsets/adresses en decimal ou hex (`0x...`) ;
- genere automatiquement un mapping de desassemblage si un outil CFG/XREF en a besoin ;
- execute directement les modules `backends/static/*` (et garde une compatibilite `pof.symbols` pour `get_symbols`).

## Resolution automatique des binaires

- Chemin absolu
- Chemin relatif au workspace
- Nom de fichier seul (ex: `demo_analysis.elf`) via recherche workspace

Cette resolution est utilisee par tous les outils prenant `binary_path`.

## Gestion des erreurs

- Erreurs JSON-RPC standard pour requetes invalides.
- Erreurs outils encapsulees en resultat MCP (`isError: true`) avec payload JSON.
- Le champ `structuredContent` contient toujours la charge utile exploitable par le client.

## Integration Ollama

Le bridge `ollama_bridge.py` :

1. demarre le serveur MCP local ;
2. recupere `tools/list` ;
3. convertit les schemas MCP en tools Ollama (`type=function`) ;
4. execute les `tool_calls` via `tools/call` ;
5. reinjecte les resultats outils dans la conversation.

Le bridge inclut aussi un fallback quand le modele repond sans appeler d'outil sur une demande qui devrait en utiliser.

## Streaming et metriques

Deux chemins convergent vers les memes messages webview :

- Ollama utilise `ollama_bridge.py --stream-output`.
- Les providers cloud utilisent `ai_provider.py call --stream-output`.

Les processus ecrivent un flux NDJSON :

```json
{"type":"token","content":"fragment"}
{"type":"done","ok":true,"text":"reponse complete","usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}
```

Le host lit `stdout` ligne par ligne, regroupe les petits fragments pendant
environ 80 ms, puis emet `hubOllamaStream`. La reponse finale passe par
`hubOllamaResult`, ce qui conserve un seul renderer pour Ollama et le cloud.

Providers cloud pris en charge :

- OpenAI, Mistral, OpenRouter, Groq et DeepSeek via le format chat completions SSE ;
- Anthropic via les evenements Messages API ;
- Gemini via `streamGenerateContent`.

Les metriques finales sont normalisees en `prompt_tokens`,
`completion_tokens`, `total_tokens` et leurs variantes `request_*`.

## UX du chat

- historique local separe par conversation ;
- modele selectionne persistant ;
- auto-scroll uniquement lorsque l'utilisateur est deja proche du bas ;
- widget flottant redimensionnable avec taille persistante ;
- commande contextuelle `pileOuFace.askAiAboutDisasm` pour transferer une
  instruction ou une selection du desassemblage vers le composeur IA.
- bouton `Arreter` commun a Ollama et aux providers cloud : chaque generation
  porte un `requestId`, le host termine uniquement le processus correspondant
  et l'UI conserve les fragments deja affiches.
- rendu Markdown final pour les reponses assistant : titres, listes, tableaux,
  citations, liens et blocs de code sont construits avec des noeuds DOM
  autorises, sans `innerHTML`. Les URL sont limitees aux protocoles `http`,
  `https` et `mailto`; le flux live reste volontairement en texte brut.
- actions `Modifier` sur les prompts utilisateur et `Regenerer` sur les
  reponses assistant. La conversation est reconstruite jusqu'au prompt cible,
  puis la suite obsolete est remplacee par une nouvelle generation avec le
  modele d'origine lorsqu'il est encore disponible.
- export de la conversation active en Markdown lisible ou JSON structure. Le
  snapshot `pile-ou-face.ai-conversation.v1` inclut les modeles, dates, chemin
  du binaire et tokens entree/sortie/total par message et pour la conversation.
- gestion locale de l'historique avec titres personnalises persistants,
  recherche sans accents dans les titres/modeles/messages et tri par date,
  titre ou modele. Le choix de tri est memorise dans l'etat du webview.
- budget de contexte visible dans le Dashboard et le widget : estimation
  approximative a quatre caracteres par token, nombre de messages inclus,
  detection des messages ignores/raccourcis et confirmation avant une
  troncature importante. La limite interne reste de 12 messages et 1800
  caracteres de contexte conversationnel.
- parametres de generation `temperature`, `top_p` et `max_tokens` configurables
  globalement dans Options ou surcharges par conversation. Le host valide les
  bornes puis transmet les valeurs aux bridges; Ollama utilise
  `temperature`/`top_p`/`num_predict`, Gemini `generationConfig`, Anthropic et
  les providers compatibles OpenAI leurs champs natifs.
- estimation locale des couts cloud a partir de regles tarifaires configurees
  dans Options. Chaque regle cible un modele exact ou un motif `*`, definit les
  prix USD par million de tokens entree/sortie et une date d'effet. L'UI
  affiche le cout par reponse et le total de conversation, en signalant les
  estimations partielles lorsqu'un modele n'a pas de tarif.
- actions contextuelles `Demander a l'IA` depuis le CFG, le pseudo-C, les
  strings, les imports et les resultats de recherche. Le helper partage ajoute
  le binaire, les metadonnees, la fonction, l'adresse et les filtres disponibles
  avant de pre-remplir le composeur du Dashboard. Le contenu visible est borne
  a 6 000 caracteres avec conservation du debut et de la fin.
