# Inventaire des outils des agents IA capables de modifier l'état

- Issue : [#509](https://github.com/PileOuFaces/Pile_Ou_Face/issues/509)
- Parent : PileOuFaces/Pile_ou_Face_documentation#48 (POF-P2-002), critère
  « Rapport des outils et de leurs effets »
- Méthode : lecture du code de la branche `develops`, sans exécution ni
  modification de code. Les références `fichier:ligne` sont relatives à la
  racine du dépôt.
- Portée : outils exposés à un agent par le serveur MCP
  (`extension/backends/mcp/server.py`), par le pont Ollama
  (`extension/backends/mcp/ollama_bridge.py`) et par l'auto-triage
  (`extension/backends/mcp/auto_triage.py`).

Ce document décrit l'existant. Il ne propose aucun correctif.

## 1. Surfaces exposées

| Surface | Point d'entrée | Qui choisit l'outil appelé |
|---|---|---|
| Serveur MCP stdio | `tools/list` renvoie `TOOLS + AI_TOOLS + DYNAMIC_TOOLS + plugin_tools` (`extension/backends/mcp/server.py:1885-1891`) ; `tools/call` exécute l'outil demandé (`extension/backends/mcp/server.py:1893-1948`) | Le client MCP (Claude Code, Codex, pont Ollama…) |
| Pont Ollama | `run_agent_once` (`extension/backends/mcp/ollama_bridge.py:830`) ; lancé depuis le hub par `hubOllamaPrompt` (`extension/src/static/staticHandlers.ts:1352-1398`) | Le modèle Ollama (`extension/backends/mcp/ollama_bridge.py:1074-1093`) |
| Auto-triage | `run_auto_triage` (`extension/backends/mcp/auto_triage.py:646`) ; lancé depuis le hub par `hubAutoTriageStart` (`extension/src/static/staticHandlers.ts:1616-1712`) | Le code : séquence d'outils fixe (`extension/backends/mcp/auto_triage.py:660-671`, `413-422`) |

Le serveur MCP n'applique aucune confirmation par appel : `tools/call`
résout le nom puis appelle `_call_tool` directement
(`extension/backends/mcp/server.py:1905-1935`). Le module `ai_consent` n'est
pas importé par `server.py` (imports : `extension/backends/mcp/server.py:37-44`).
Dans le dépôt, `ai_consent.py` n'est appelé que depuis l'hôte VS Code
(`extension/src/static/staticHandlers.ts:941`, `1662`, `1972`, `2468`).

## 2. Légende

Effet :

- **Lecture** : aucune écriture repérée dans le chemin cité. Les créations
  implicites de base SQLite (répertoire, fichier, schéma) au premier accès
  ont été relevées pour les outils cités au §6 ; leur absence n'a pas été
  vérifiée exhaustivement dans les dépendances des autres outils « Lecture ».
- **Artefact** : écrit des fichiers dérivés ou un cache d'analyse, sans
  toucher au binaire ni aux annotations.
- **Modification** : modifie une donnée de l'utilisateur, une configuration,
  le binaire, ou exécute du code arbitraire.

Déclenchement par un contenu analysé (dernière colonne) :

- **[A]** Chemin de code ouvert via le pont Ollama (voir §5.1). Pour un
  client MCP externe : non établi, la confirmation éventuelle relève du client,
  hors de ce dépôt.
- **[B]** Le contenu analysé influence la valeur écrite, pas le choix de
  l'outil (voir §5.2).

## 3. Outils du serveur MCP

### 3.1 Outils statiques (`TOOLS`)

| Outil | Déclaration | Implémentation | Effet | Autorisation | Contenu → appel |
|---|---|---|---|---|---|
| `annotations_list` | `extension/backends/mcp/server.py:74` | `extension/backends/mcp/server.py:1231-1240` | Lecture des annotations, mais **initialisation persistante** : `AnnotationStore` ouvre `AnnotationDb` (`extension/backends/static/annotations/annotations.py:55`), qui crée le répertoire, la base `~/.pile-ou-face/annotations.db` et son schéma s'ils sont absents (`extension/backends/static/annotations/annotation_db.py:18-20`, `42-79`), et migre une ancienne base en ajoutant la colonne `source` (`extension/backends/static/annotations/annotation_db.py:81-94`) | Aucune | [A] |
| `annotations_save` | `extension/backends/mcp/server.py:87` | `extension/backends/mcp/server.py:1242-1259` | **Modification** : écrit commentaire et/ou renommage (`extension/backends/mcp/server.py:1252`, `1255`) avec la source par défaut `"user"` (`extension/backends/static/annotations/annotations.py:57`, `70`) | Aucune | [A] |
| `annotations_delete` | `extension/backends/mcp/server.py:102` | `extension/backends/mcp/server.py:1261-1272` | **Modification** : supprime des annotations (`extension/backends/mcp/server.py:1271`) | Aucune | [A] |
| `simulate_asm` | `extension/backends/mcp/server.py:116` | `extension/backends/mcp/server.py:1274-1286` | Lecture (simulation en mémoire) | Aucune | [A] |
| `get_exports` | `extension/backends/mcp/server.py:126` | `extension/backends/mcp/server.py:1288-1291` | Lecture | Aucune | [A] |
| `cache_invalidate` | `extension/backends/mcp/server.py:136` | `extension/backends/mcp/server.py:1354-1361` | **Modification** : `DELETE` de l'entrée de cache du binaire (`extension/backends/static/cache/cache.py:1104-1109`) ; `cache_db` est un chemin libre (`extension/backends/mcp/server.py:879-881`) | Aucune | [A] |
| `cache_stats` | `extension/backends/mcp/server.py:149` | `extension/backends/mcp/server.py:1363-1369` | Lecture d'après `server.py` ; effets internes de `db_stats` non vérifiés | Aucune | [A] |
| `cache_list` | `extension/backends/mcp/server.py:161` | `extension/backends/mcp/server.py:1371-1375` | Lecture d'après `server.py` ; effets internes de `list_binaries` non vérifiés | Aucune | [A] |
| `cache_purge` | `extension/backends/mcp/server.py:173` | `extension/backends/mcp/server.py:1377-1388` | **Modification** : `DELETE` d'un binaire ou de **toute** la table si `target_binary` est absent (`extension/backends/static/cache/cache_admin.py:106-124`) | Aucune | [A] |
| `build_call_graph` | `extension/backends/mcp/server.py:186` | `extension/backends/mcp/server.py:1390-1414` | Artefact si `mapping_path` absent : désassemblage écrit sous `.pile-ou-face/mcp` (`extension/backends/mcp/server.py:1137-1138`, `954-962`) | Aucune | [A] |
| `build_cfg` | `extension/backends/mcp/server.py:198` | `extension/backends/mcp/server.py:1416-1429` | Artefact (même mécanisme, `extension/backends/mcp/server.py:1419`) | Aucune | [A] |
| `build_cfg_for_function` | `extension/backends/mcp/server.py:210` | `extension/backends/mcp/server.py:1431-1445` | Artefact (`extension/backends/mcp/server.py:1434`) | Aucune | [A] |
| `decompile_function` | `extension/backends/mcp/server.py:224` | `extension/backends/mcp/server.py:1447-1461` | Artefact : écrit le cache de décompilation (`extension/backends/static/decompile/decompile.py:2998`) ; pour un binaire existant, charge les annotations via `AnnotationDb` (`extension/backends/static/decompile/decompile.py:2902-2904`, `extension/backends/static/decompile/decompile.py:1544`), ce qui crée ou migre la base d'annotations, même sans décompilateur disponible ; lance des processus locaux/Docker ou un appel HTTP selon le décompilateur configuré (`extension/backends/static/decompile/decompile.py:908`, `1221`) | Aucune | [A] |
| `decompile_binary` | `extension/backends/mcp/server.py:243` | `extension/backends/mcp/server.py:1463-1468` | Processus externes (même module) ; écriture de cache non établie (`extension/backends/static/decompile/decompile.py:3104`) | Aucune | [A] |
| `disassemble` | `extension/backends/mcp/server.py:260` | `extension/backends/mcp/server.py:1470-1477` | Artefact : crée `.asm` et mapping sous `ROOT/.pile-ou-face/mcp` et lance un sous-processus (`extension/backends/mcp/server.py:954-987`) | Aucune | [A] |
| `discover_functions` | `extension/backends/mcp/server.py:274` | `extension/backends/mcp/server.py:1479-1506` | Artefact si `mapping_path` absent (`extension/backends/mcp/server.py:1483`) | Aucune | [A] |
| `extract_dwarf` | `extension/backends/mcp/server.py:286` | `extension/backends/mcp/server.py:1508-1511` | Lecture | Aucune | [A] |
| `analyze_entropy` | `extension/backends/mcp/server.py:296` | `extension/backends/mcp/server.py:1513-1525` | Lecture | Aucune | [A] |
| `export_results` | `extension/backends/mcp/server.py:310` | `extension/backends/mcp/server.py:1527-1615` | **Modification** : écrit (écrase) le fichier `output_path` fourni par l'appelant, sans contrôle de chemin dans `server.py` (`extension/backends/mcp/server.py:1535`) ; ouverture en `"w"` (`extension/backends/static/export/export.py:38`, `63`, `103`, `162`) | Aucune | [A] |
| `get_binary_info` | `extension/backends/mcp/server.py:327` | `extension/backends/mcp/server.py:1617-1620` | Lecture | Aucune | [A] |
| `hex_dump` | `extension/backends/mcp/server.py:337` | `extension/backends/mcp/server.py:1622-1628` | Lecture | Aucune | [A] |
| `find_import_callsites` | `extension/backends/mcp/server.py:351` | `extension/backends/mcp/server.py:1630-1635` | Artefact : en l'absence de cache, enregistre le désassemblage et la map de xrefs dans le cache d'analyse du binaire (`extension/backends/static/disasm/import_xrefs.py:78-79`, `103-104`) | Aucune | [A] |
| `analyze_imports` | `extension/backends/mcp/server.py:364` | `extension/backends/mcp/server.py:1637-1640` | Lecture | Aucune | [A] |
| `offset_to_vaddr` | `extension/backends/mcp/server.py:374` | `extension/backends/mcp/server.py:1642-1652` | Lecture | Aucune | [A] |
| `execute_script` | `extension/backends/mcp/server.py:387` | `extension/backends/mcp/server.py:1654-1665` | **Modification** potentiellement totale : `exec` de code Python fourni par l'appelant, dans le processus serveur, avec les builtins complets (`extension/backends/static/repl/repl.py:51-67`). Fichiers, réseau et processus sont accessibles | Aucune | [A] |
| `rules_list` | `extension/backends/mcp/server.py:401` | `extension/backends/mcp/server.py:1667-1671` | Lecture | Aucune | [A] |
| `rules_toggle` | `extension/backends/mcp/server.py:410` | `extension/backends/mcp/server.py:1673-1682` | **Modification** : réécrit la configuration des règles (`extension/backends/static/rules/rules_manager.py:159-171`) | Aucune | [A] |
| `rules_add` | `extension/backends/mcp/server.py:423` | `extension/backends/mcp/server.py:1684-1693` | **Modification** : crée un fichier de règle YARA/capa (`extension/backends/static/rules/rules_manager.py:173-196`) dans `POF_STORAGE_DIR` ou `ROOT` (`extension/backends/static/rules/rules_manager.py:33-37`) | Aucune | [A] |
| `rules_delete` | `extension/backends/mcp/server.py:437` | `extension/backends/mcp/server.py:1695-1701` | **Modification** : supprime le fichier de règle et met à jour la config (`extension/backends/static/rules/rules_manager.py:198-215`) | Aucune | [A] |
| `search_binary` | `extension/backends/mcp/server.py:447` | `extension/backends/mcp/server.py:1703-1716` | Lecture | Aucune | [A] |
| `get_sections` | `extension/backends/mcp/server.py:462` | `extension/backends/mcp/server.py:1718-1721` | Lecture | Aucune | [A] |
| `analyze_stack_frame` | `extension/backends/mcp/server.py:472` | `extension/backends/mcp/server.py:1723-1729` | Artefact : en l'absence de cache valide, enregistre le résultat dans le cache d'analyse du binaire (`extension/backends/static/disasm/stack_frame.py:878-882`) ; une erreur d'écriture est ignorée silencieusement | Aucune | [A] |
| `extract_strings` | `extension/backends/mcp/server.py:485` | `extension/backends/mcp/server.py:1731-1744` | Lecture | Aucune | [A] |
| `get_symbols` | `extension/backends/mcp/server.py:495` | `extension/backends/mcp/server.py:1746-1751` | Lecture | Aucune | [A] |
| `get_xrefs` | `extension/backends/mcp/server.py:505` | `extension/backends/mcp/server.py:1753-1782` | Artefact si `mapping_path` absent (`extension/backends/mcp/server.py:1762`). En mode `to` (`extension/backends/mcp/server.py:1781`), **même avec un `mapping_path` fourni**, l'enrichissement ouvre `AnnotationDb` et `DisasmCache` si le binaire existe (`extension/backends/static/disasm/xrefs.py:359-365`). Leur ouverture crée la base et son schéma s'ils sont absents (`extension/backends/static/annotations/annotation_db.py:45-49`, `extension/backends/static/cache/cache.py:260-270`) | Aucune | [A] |
| `plugins_list` | `extension/backends/mcp/server.py:520` | `extension/backends/mcp/server.py:1293-1299` | Attache les plugins consentis (`attach=True`, `extension/backends/mcp/server.py:747-756`). Effets du runtime de plugin à l'attache : non établis | Consentement plugin (`require_consent=True`, `extension/backends/mcp/server.py:754`) | [A] |
| `plugin_invoke` | `extension/backends/mcp/server.py:529` | `extension/backends/mcp/server.py:1301-1352` | Dépend du plugin : non établi par lecture du Host | Consentement plugin (`extension/backends/mcp/server.py:1338`, `1348` ; contrôle : `extension/backends/plugins/runtime.py:421-430`). Ce n'est pas le consentement IA d'`ai_consent.py` | [A] |
| `find_files` | `extension/backends/mcp/server.py:542` | `extension/backends/mcp/server.py:1784-1787` | Lecture (parcours de `WORKSPACE_ROOT`, `extension/backends/mcp/server.py:889-895`) | Aucune | [A] |

### 3.2 Outils IA (`AI_TOOLS`)

| Outil | Déclaration | Implémentation | Effet | Autorisation | Contenu → appel |
|---|---|---|---|---|---|
| `ai_providers_list` | `extension/backends/mcp/server.py:575` | `extension/backends/mcp/server.py:1789-1790` | Lecture locale ; **Réseau** : interroge l'API de liste des modèles de chaque fournisseur cloud dont la clé est configurée, en transmettant cette clé dans un en-tête d'authentification, et interroge toujours `OLLAMA_BASE_URL` (`extension/backends/mcp/ai_provider.py:90-150`, `154-173`) | Aucune | [A] |
| `ai_providers_set` | `extension/backends/mcp/server.py:585` | `extension/backends/mcp/server.py:1792-1796` | **Modification** de configuration : écrit la clé API et/ou le modèle dans `~/.pile-ou-face/.env` et dans l'environnement du processus (`extension/backends/mcp/ai_provider.py:657-665`, `extension/backends/mcp/env_loader.py:4`, `22`) | Aucune | [A] |
| `ai_analyze` | `extension/backends/mcp/server.py:599` | `extension/backends/mcp/server.py:1798-1828` | **Réseau** : envoie `prompt` et `context` au fournisseur (par défaut `POF_DEFAULT_AI_PROVIDER`, sinon `ollama`, `extension/backends/mcp/server.py:1799-1807`). **Modification** si `write_annotation` est fourni : écrit la réponse du modèle comme renommage ou commentaire IA (`extension/backends/mcp/server.py:1814-1825`), sans écraser une annotation manuelle (`extension/backends/static/annotations/annotations.py:98-127`) | Aucune (`ai_consent` absent de `server.py`) | [A] ; [B] pour la valeur écrite |

### 3.3 Outils dynamiques (`DYNAMIC_TOOLS`)

Au démarrage, `scan_backend_tools` exécute chaque module `*.py` de
`extension/backends/static` et expose les fonctions publiques des modules qui
déclarent `__mcp_enabled__ = True` (`extension/backends/mcp/server.py:567-571`,
`extension/backends/mcp/tool_scanner.py:84-112`). La liste ci-dessous est
établie par lecture. Sa présence effective au runtime dépend du succès de
l'import de chaque module (`extension/backends/mcp/tool_scanner.py:90-96`) :
non vérifiée par exécution.

| Outil | Définition | Effet | Autorisation | Contenu → appel |
|---|---|---|---|---|
| `binary_patch.patch_bytes` | `extension/backends/static/patch/binary_patch.py:22` | **Modification du binaire** en place, sans historique (`extension/backends/static/patch/binary_patch.py:53-55`) | Aucune | [A] |
| `patch_manager.list_patches` | `extension/backends/static/patch/patch_manager.py:78` | Lecture de l'historique, mais **initialisation persistante** : `_load` ouvre `PatchDb` (`extension/backends/static/patch/patch_manager.py:37-39`), qui crée le répertoire, la base (`POF_PATCHES_DB` ou `~/.pile-ou-face/patches.db`) et son schéma s'ils sont absents (`extension/backends/static/patch/patch_db.py:16-56`) | Aucune | [A] |
| `patch_manager.apply_patch` | `extension/backends/static/patch/patch_manager.py:83` | **Modification du binaire** + historique SQLite (`extension/backends/static/patch/patch_manager.py:118`, `132`) | Aucune | [A] |
| `patch_manager.revert_patch` | `extension/backends/static/patch/patch_manager.py:137` | **Modification du binaire** + historique (`extension/backends/static/patch/patch_manager.py:157-161`) | Aucune | [A] |
| `patch_manager.redo_patch` | `extension/backends/static/patch/patch_manager.py:166` | **Modification du binaire** + historique (`extension/backends/static/patch/patch_manager.py:194-198`) | Aucune | [A] |
| `patch_manager.revert_all` | `extension/backends/static/patch/patch_manager.py:203` | **Modification du binaire** + historique (`extension/backends/static/patch/patch_manager.py:213-224`) | Aucune | [A] |
| `patch_manager.delete_history` | `extension/backends/static/patch/patch_manager.py:229` | **Modification** : supprime l'historique de patchs d'un binaire, donc la possibilité d'annuler (`extension/backends/static/patch/patch_manager.py:231-232`) | Aucune | [A] |
| `patch_manager.purge_missing` | `extension/backends/static/patch/patch_manager.py:235` | **Modification** : purge les historiques des binaires absents sous `workspace_root` (`extension/backends/static/patch/patch_manager.py:237-238`) | Aucune | [A] |
| `structs.parse_struct_definitions` | `extension/backends/static/annotations/structs.py:284` | Lecture (analyse de texte) | Aucune | [A] |
| `structs.load_struct_store` | `extension/backends/static/annotations/structs.py:374` | Lecture ; si `types.db` existe, son ouverture passe la base en WAL et crée les tables manquantes (`extension/backends/static/annotations/struct_db.py:140-142`, `extension/backends/static/annotations/struct_db.py:43-44`) | Aucune | [A] |
| `structs.list_struct_store` | `extension/backends/static/annotations/structs.py:381` | Lecture, via `load_struct_store` (`extension/backends/static/annotations/structs.py:385`) : mêmes effets sur une base `types.db` existante | Aucune | [A] |
| `structs.save_struct_source` | `extension/backends/static/annotations/structs.py:398` | **Modification** : remplace les définitions de types du binaire (`extension/backends/static/annotations/structs.py:404`) | Aucune | [A] |
| `structs.import_type_definitions` | `extension/backends/static/annotations/structs.py:430` | **Modification** : fusionne des définitions dans le catalogue (`extension/backends/static/annotations/structs.py:452-454`) | Aucune | [A] |
| `structs.compute_struct_layout` | `extension/backends/static/annotations/structs.py:527` | Lecture (calcul) | Aucune | [A] |
| `typed_data.get_typed_data` | `extension/backends/static/annotations/typed_data.py:705` | Lecture (`extension/backends/static/annotations/typed_data.py:182`) ; appelle `load_struct_store` (`extension/backends/static/annotations/typed_data.py:719`) : mêmes effets sur une base `types.db` existante | Aucune | [A] |
| `function_radar.build_function_radar` | `extension/backends/static/analysis/function_radar.py:609` | Artefact : remplit le cache d'analyse (`extension/backends/static/analysis/function_radar.py:167`, `177`, `202`, `212`, `234`, `245`, `256`) | Aucune | [A] |
| `analysis_index.build_analysis_index` | `extension/backends/static/analysis/analysis_index.py:126` | Artefact : remplit le cache d'analyse (`extension/backends/static/analysis/analysis_index.py:150-161`) ; `cache_db` libre (`extension/backends/static/analysis/analysis_index.py:128`) | Aucune | [A] |
| `calling_convention.analyze_calling_conventions` | `extension/backends/static/disasm/calling_convention.py:317` | Lecture (aucune écriture directe repérée dans le module) | Aucune | [A] |
| `pe_resources.get_pe_resources` | `extension/backends/static/binary/pe_resources.py:196` | Lecture (aucune écriture directe repérée dans le module) | Aucune | [A] |

**Surface d'appel plus large que la liste déclarée.** Tout nom contenant un
`.`, absent des outils statiques et ne commençant pas par `plugin.`, est
transmis à `_dispatch_dynamic_tool` (`extension/backends/mcp/server.py:1831-1836`).
Cette fonction charge le premier fichier `<module>.py` trouvé sous
`extension/backends/static` et appelle `getattr(module, fn)(**args)`
(`extension/backends/mcp/server.py:1205-1227`). Elle ne vérifie ni
`__mcp_enabled__`, ni l'appartenance du nom à `DYNAMIC_TOOLS`, ni l'absence de
préfixe `_`. Un appelant peut donc atteindre des fonctions non listées par
`tools/list`, par exemple `patch_manager._write_bytes`
(`extension/backends/static/patch/patch_manager.py:58-61`). L'inventaire
exhaustif de ces fonctions atteignables n'est pas établi ici.

### 3.4 Outils de plugins (`plugin.*`)

Les commandes et fonctionnalités des plugins actifs et consentis sont
exposées sous `plugin.<id>` (`extension/backends/mcp/server.py:760-836`).
Leur appel est routé vers `plugin_invoke` (`extension/backends/mcp/server.py:1907-1933`)
et soumis au consentement plugin (voir `plugin_invoke`). Leurs effets dépendent
du code de chaque plugin : non établis.

## 4. Pont Ollama et auto-triage

### 4.1 Pont Ollama (`ollama_bridge.py`)

Le pont ne déclare pas d'outil propre : il relaie les outils du serveur MCP.

- Il annonce au modèle tous les outils de `tools/list`, ou un sous-ensemble
  de lecture si une intention est détectée dans la demande
  (`extension/backends/mcp/ollama_bridge.py:844-852`, `495-516`).
- Le nom demandé par le modèle n'est pas restreint à l'ensemble annoncé :
  `_resolve_requested_tool_name` renvoie le nom brut s'il ne correspond à rien
  (`extension/backends/mcp/ollama_bridge.py:476-492`).
- Chaque `tool_call` du modèle est exécuté sans confirmation
  (`extension/backends/mcp/ollama_bridge.py:1074-1093`), jusqu'à `max_steps`
  itérations (15 depuis le hub, `extension/src/static/staticHandlers.ts:1383`).
- Les sorties d'outils (y compris chaînes, symboles et code décompilé du
  binaire) sont réinjectées dans la conversation (`extension/backends/mcp/ollama_bridge.py:1106-1140`).
- **Réseau** : les messages, donc les sorties d'outils, sont envoyés à l'URL
  Ollama (`extension/backends/mcp/ollama_bridge.py:736-763`). Cette URL est
  fournie par le message webview (`extension/src/static/staticHandlers.ts:1354`).
- **Autorisation** : `hubOllamaPrompt` ne consulte pas `ai_consent.py`
  (`extension/src/static/staticHandlers.ts:1352-1398`), alors que
  `ai_consent.py` prévoit un consentement pour tout fournisseur, y compris
  local (`extension/backends/mcp/ai_consent.py:14-16`). L'action utilisateur
  se limite à l'envoi du prompt.

### 4.2 Auto-triage (`auto_triage.py`)

L'auto-triage n'est pas un outil MCP (`extension/backends/mcp/auto_triage.py:5-10`).
Il appelle une séquence fixe d'outils : `build_call_graph`,
`discover_functions`, `get_xrefs`, `extract_strings`
(`extension/backends/mcp/auto_triage.py:660-671`), puis `decompile_function`
ou `disassemble` (`extension/backends/mcp/auto_triage.py:413-422`). Ces appels
héritent des effets « Artefact » du §3.1.

| Effet | Référence | Autorisation |
|---|---|---|
| **Réseau** : envoi du code de chaque fonction au fournisseur | `extension/backends/mcp/auto_triage.py:445-447` | Consentement `ai_consent` vérifié ou demandé par modale avant le lancement (`extension/src/static/staticHandlers.ts:1660-1688`) |
| **Modification** : renommage et commentaire IA par fonction, sans écraser une annotation manuelle | `extension/backends/mcp/auto_triage.py:486-498`, `780` ; `extension/backends/static/annotations/annotations.py:98-127` | Même modale. Son texte ne mentionne que l'envoi du code (`extension/src/static/staticHandlers.ts:1674`), pas l'écriture d'annotations |
| **Modification** : écriture du rapport Markdown | `extension/backends/mcp/auto_triage.py:879-880` ; chemin choisi par l'hôte (`extension/src/static/staticHandlers.ts:1695`) | Même modale |

### 4.3 Autres points d'entrée IA hors agents

Hors périmètre « outil exposé à un agent », mais protégés par
`ai_consent.py` : suivi IA des plugins (`extension/src/static/staticHandlers.ts:939-971`),
`hubAugmentDecompile` (`extension/src/static/staticHandlers.ts:1948`, contrôle
`1972-1993`) et `hubNaturalLanguageSearch`
(`extension/src/static/staticHandlers.ts:2448`, contrôle `2468-2489`).

## 5. Déclenchement par un contenu analysé

### 5.1 [A] Appel d'outil choisi par un modèle

- **Pont Ollama : chemin de code ouvert.** Le contenu du binaire revient au
  modèle comme message `tool` (`extension/backends/mcp/ollama_bridge.py:1134-1140`).
  Les `tool_calls` suivants sont exécutés sans confirmation ni filtrage des
  outils de modification (`extension/backends/mcp/ollama_bridge.py:1074-1093`,
  `476-492`). Rien dans le code n'empêche qu'une chaîne ou un symbole du binaire
  amène le modèle à appeler `execute_script`, `export_results`,
  `binary_patch.patch_bytes` ou un autre outil du §6. Le passage effectif à
  l'acte dépend du modèle : **non établi** par lecture.
- **Client MCP externe : non établi.** Le serveur exécute tout `tools/call`
  reçu (`extension/backends/mcp/server.py:1893-1935`). Une éventuelle
  confirmation dépend du client, hors de ce dépôt.

### 5.2 [B] Valeur écrite influencée par le contenu

- **Auto-triage.** Le code analysé, qui peut contenir des chaînes du binaire,
  est envoyé au modèle (`extension/backends/mcp/auto_triage.py:429-437`). Le
  nom et la docstring renvoyés sont écrits sans relecture
  (`extension/backends/mcp/auto_triage.py:471-498`, `780`). Le contenu ne
  choisit pas l'outil, mais il peut déterminer le texte des annotations IA.
- **`ai_analyze` avec `write_annotation`.** La réponse du modèle est écrite
  telle quelle (`extension/backends/mcp/server.py:1820-1824`).

## 6. Outils modifiant l'état sans accord explicite

« Sans accord explicite » signifie : ni consentement `ai_consent`, ni
consentement plugin, ni confirmation utilisateur dans le chemin de code cité.

**Données utilisateur, binaire ou configuration**

| Outil | Ce qui est modifié |
|---|---|
| `execute_script` | Quelconque (exécution de code arbitraire) |
| `binary_patch.patch_bytes` | Octets du binaire, sans historique |
| `patch_manager.apply_patch`, `revert_patch`, `redo_patch`, `revert_all` | Octets du binaire et historique de patchs |
| `patch_manager.delete_history`, `patch_manager.purge_missing` | Historique de patchs |
| `annotations_save` | Annotations, enregistrées avec la source `"user"` |
| `annotations_delete` | Annotations |
| `structs.save_struct_source`, `structs.import_type_definitions` | Catalogue de types du binaire |
| `rules_add`, `rules_toggle`, `rules_delete` | Fichiers et configuration des règles YARA/capa |
| `export_results` | Fichier arbitraire désigné par `output_path` |
| `ai_providers_set` | `~/.pile-ou-face/.env` (clé API, modèle) |
| `cache_invalidate`, `cache_purge` | Base de cache d'analyse, éventuellement entière |
| `ai_analyze` (avec `write_annotation`) | Annotations IA |
| Fonctions atteignables par `_dispatch_dynamic_tool` hors liste (§3.3) | Non inventorié |

**Réseau sans consentement `ai_consent`**

| Outil / chemin | Ce qui sort |
|---|---|
| `ai_analyze` | `prompt` et `context` vers le fournisseur configuré |
| Pont Ollama (`hubOllamaPrompt`) | Conversation et sorties d'outils vers l'URL Ollama fournie par la webview |
| `decompile_function`, `decompile_binary` | Binaire vers le décompilateur configuré : processus local ou Docker ; en HTTP, une requête part toujours, mais le contenu du binaire n'est transmis que si le modèle de corps contient `{binary_b64}` (`extension/backends/static/decompile/decompile.py:877-895`) |
| `ai_providers_list` | Requête de liste des modèles vers chaque fournisseur cloud configuré, avec la clé API configurée en en-tête d'authentification ; requête vers `OLLAMA_BASE_URL` (sans clé) |

**Artefacts et cache d'analyse (données dérivées)**

| Outil | Ce qui est écrit |
|---|---|
| `disassemble` ; `build_call_graph`, `build_cfg`, `build_cfg_for_function`, `discover_functions`, `get_xrefs` sans `mapping_path` | Fichiers `.asm` et mapping sous `ROOT/.pile-ou-face/mcp` |
| `get_xrefs` en mode `to`, avec ou sans `mapping_path` | Ouverture d'`AnnotationDb` et du cache de désassemblage (§6, tableau suivant) |
| `decompile_function` | Cache de décompilation |
| `function_radar.build_function_radar`, `analysis_index.build_analysis_index` | Cache d'analyse SQLite |
| `analyze_stack_frame` | Cache d'analyse : résultat du cadre de pile |
| `find_import_callsites` | Cache d'analyse : désassemblage et map de xrefs |

**Initialisation ou migration de bases persistantes**

| Outil | Ce qui est créé ou modifié |
|---|---|
| `annotations_list` | Répertoire, base `annotations.db` et schéma s'ils sont absents ; ajout de la colonne `source` sur une ancienne base |
| `patch_manager.list_patches` | Répertoire, base `patches.db` et schéma s'ils sont absents |
| `get_xrefs` (mode `to`, binaire existant) | Base d'annotations et cache de désassemblage (WAL), avec leur schéma, s'ils sont absents |
| `decompile_function` (binaire existant) | Base d'annotations et son schéma s'ils sont absents ; migration d'une ancienne base |
| `structs.load_struct_store`, `structs.list_struct_store`, `typed_data.get_typed_data` | Sur une base `types.db` existante : passage en WAL et création des tables manquantes |

**Accord partiel**

- Auto-triage : le consentement couvre l'envoi au fournisseur. Le texte de la
  modale ne mentionne pas l'écriture d'annotations IA ni du rapport (§4.2).
