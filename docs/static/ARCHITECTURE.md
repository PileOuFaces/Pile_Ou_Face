# Architecture de la partie statique

## Principe general

La partie statique est construite comme une chaine d'analyse modulaire :

```text
Webview VS Code
   -> messages JavaScript
   -> handlers de l'extension
   -> scripts Python backends/static
   -> JSON
   -> rendu dans le hub
```

Chaque analyse statique est un module Python autonome. Cela permet de l'appeler depuis l'interface VS Code, depuis une CLI, depuis des tests, ou depuis l'API de scripting.

## Couches principales

### Interface webview

Fichiers :

- `extension/webview/static/panel-static.html`
- `extension/webview/static/panel-static.css`
- `extension/webview/hub.js`
- `extension/webview/shared/cfgHelpers.js`

Responsabilites :

- afficher les groupes publics `CODE`, `DATA` et `Script` ;
- afficher dynamiquement `AUDIT`, `MALWARE` et `OFFENSIF` seulement si les plugins correspondants sont actifs ;
- gerer les onglets;
- afficher tableaux, graphes, resultats et formulaires;
- envoyer les actions utilisateur a l'extension;
- garder le contexte actif : fonction, adresse, selection.

### Extension VS Code

Fichiers :

- `extension/src/static/hub.js`
- `extension/src/static/staticHandlers.js`
- `extension/src/static/commands.js`
- `extension/src/static/handlers.js`
- `extension/src/shared/staticCache.js`
- `extension/src/shared/fileManager.js`

Responsabilites :

- recevoir les messages de la webview;
- resoudre le chemin du binaire actif;
- lancer les modules Python;
- gerer les artefacts `.asm`, mappings et caches;
- ouvrir les documents dans VS Code;
- faire le pont entre UI et backend.

### Backend Python

Dossier :

- `backends/static/`

Responsabilites :

- parser les binaires;
- desassembler;
- extraire metadonnees, sections, symboles, strings et imports;
- construire CFG, call graph et xrefs;
- lancer les analyses `core` du host open source ;
- attacher et invoquer les commandes des plugins actifs ;
- produire du JSON stable pour l'interface;
- exposer des CLI testables.

## Flux d'une analyse simple

Exemple : chargement des strings.

```text
1. L'utilisateur ouvre l'onglet Strings.
2. hub.js envoie un message `hubLoadStrings`.
3. extension/src/static/hub.js resout le chemin du binaire.
4. Le handler lance `backends/static/strings.py`.
5. Le module retourne une liste JSON.
6. La webview affiche le tableau et les boutons d'export.
```

## Flux du desassemblage

Le desassemblage est un flux plus riche parce qu'il produit des artefacts reutilises par d'autres vues.

```text
1. L'utilisateur clique `Ouvrir le desassemblage`.
2. L'extension resout le binaire actif.
3. `backends/static/disasm.py` genere un `.asm`.
4. Un mapping JSON relie chaque adresse a une ligne.
5. VS Code ouvre le fichier `.asm`.
6. CFG, call graph, xrefs et navigation utilisent le mapping.
```

Artefacts typiques :

- fichier de desassemblage `.asm`;
- fichier de mapping `.disasm.mapping.json`;
- caches d'analyse;
- annotations;
- patches.

## Backend statique par domaines

### Parsing et metadonnees

- `headers.py` — metadonnees binaire + detection packer (heuristiques + YARA via `_scan_with_yara()`)
- `packer_signatures.yar` — signatures YARA formelles (UPX PE/ELF, ASPack, MPRESS, Petite, PECompact)
- `sections.py`
- `symbols.py`
- `entropy.py`
- `pe_resources.py`
- `binary_exports.py`
- `exception_handlers.py`

### Code et graphes

- `disasm.py`
- `arch.py`
- `cfg.py`
- `call_graph.py`
- `discover_functions.py`
- `xrefs.py`
- `import_xrefs.py`
- `stack_frame.py`
- `calling_convention.py`
- `decompile.py`
- `ghidra_decompile.py`

### Donnees

- `strings.py`
- `search.py`
- `hex_view.py`
- `typed_data.py`
- `structs.py`
- `typed_struct_refs.py`
- `dwarf.py`
- `rules_manager.py`

### Plugins et enrichissement optionnel

Le host public ne porte plus nativement les capacites optionnelles. Elles sont chargees a chaud depuis `backends/plugins/` :

- `AUDIT` : `taint`, `vuln_patterns`
- `MALWARE` : `behavior`, `anti_analysis`, `yara`, `capa`, `deobfuscation`
- `OFFENSIF` : `rop`, `flirt`, `func_similarity`, `bindiff`

Le runtime plugin gere la discovery, la validation de manifest, l'attachement Python et l'invocation MCP/UI.

### Edition et outillage host

- `binary_patch.py`
- `patch_manager.py`
- `annotations.py`
- `export.py`
- `repl.py`

## Cache et persistance

Le projet evite de recalculer certaines analyses lourdes. Dans l'extension VS
Code, le dossier de reference est `context.storageUri`, c'est-a-dire le
`workspaceStorage` de VS Code pour le workspace courant :

```text
<workspaceStorage>/<workspace-id>/PileOuFaces.stack-visualizer/
```

Le dossier projet `.pile-ou-face/` reste un fallback de compatibilite pour
certains lancements CLI, MCP ou artefacts de developpement ; ce n'est pas le
stockage principal de l'extension.

Elements persistants :

- `static_cache/` : caches par binaire;
- `annotations/` : labels, commentaires, bookmarks;
- `decompile_cache/` : pseudo-C mis en cache;
- `pfdb/` : base d'analyse SQLite selon les modules;
- `patches/` : patchs persistants;
- `plugins/` : plugins installes par l'extension;
- `licenses/` : licences importees dans le workspace;
- `decompilers.json` : configuration des decompilateurs.

## Formats supportes

Formats principaux :

- ELF;
- PE;
- Mach-O;
- blob brut.

Architectures prises en charge selon les modules :

- x86 / x86-64;
- ARM / Thumb;
- AArch64;
- MIPS;
- PowerPC;
- SPARC;
- RISC-V;
- BPF;
- WebAssembly;
- M68K;
- SH;
- TriCore.

Toutes les features n'ont pas le meme niveau de support sur chaque architecture. Le module `backends/static/arch.py` centralise la matrice de support et les conventions propres aux ISA.

## Tests

La partie statique dispose d'une suite pytest dans :

- `backends/static/tests/`

Exemples couverts cote host public :

- desassemblage;
- CFG;
- xrefs;
- headers;
- sections;
- strings;
- entropy;
- imports;
- decompilation;
- stack frame;
- binary patch;
- structs;
- typed data;
- scripting Python intégré via `repl.py`.

Commande :

```bash
python -m pytest backends/static/tests
```

Pour le corpus de binaires réels, un target dédié compile la matrice disponible
localement, exécute les contrôles, puis écrit un résumé JSON de métriques par
cas :

```bash
make test-real-corpus
```

Sortie générée :

```text
.pile-ou-face/test-artifacts/real_binary_corpus_metrics.json
```

Ce fichier utilise le schema
`pile-ou-face.real-binary-corpus.metrics.v2` et contient notamment
rappel/précision de découverte des fonctions, taille CFG, types d'arêtes,
arêtes `call` nommées par fonction source/cible et résumé stack-frame. Le
dossier `.pile-ou-face/` reste ignoré par Git : le résumé sert au suivi
local/CI sans versionner de binaires générés.

En CI, le job `Real Corpus ARM64` installe explicitement
`gcc-aarch64-linux-gnu` et `binutils-aarch64-linux-gnu`, exécute
`make test-real-corpus`, puis publie ce résumé JSON comme artifact GitHub
Actions.

## Extension et tests JavaScript

Les tests de l'extension se trouvent dans :

- `extension/test/`

Ils couvrent notamment :

- payload hex;
- visualiseur;
- handlers statiques;
- modeles de pile;
- helpers CFG;
- profils d'architecture raw.

Commande :

```bash
npm test -C extension
```

## Pourquoi cette architecture est utile

- Les modules Python restent reutilisables hors interface.
- La webview reste concentree sur l'ergonomie.
- Les handlers JavaScript isolent les details VS Code.
- Les resultats JSON facilitent les tests et l'export.
- Le projet peut ajouter une feature en creant un module backend, un handler, puis une vue.
