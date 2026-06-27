# Roadmap — Analyse Statique

Objectif : égaler puis dépasser IDA Pro / Ghidra sur l'analyse statique de binaires ELF/PE/Mach-O et blobs bruts.

**Dernière mise à jour :** 2026-06-26

---

## Orientation repo

Cette roadmap vit dans le repo public host. Elle peut mentionner des capacités plugin visibles côté produit, mais elle ne documente pas les implémentations externes ni leur fonctionnement interne.

---

## Légende

| Icône | Signification |
|-------|---------------|
| ✅ | Livré et fonctionnel |
| ⚠️ | Partiel — amélioration identifiée |
| ❌ | Absent — à créer |
| 🔥 | Priorité haute |
| ⭐ | Différenciateur (dépasse IDA) |

---

## 1. État des modules

### 1.1 Binaire & Parsing

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Architecture & adapters ISA | `binary/arch.py` | ✅ | Matrice `FeatureSupport`, adapters x86/x64/ARM32/ARM64/MIPS/PPC/SPARC/RISC-V/BPF/WASM/M68K/SH/TriCore |
| Headers ELF/PE/Mach-O | `binary/headers.py` | ✅ | Magic bytes, validation à l'ouverture |
| Sections | `binary/sections.py` | ✅ | |
| Symbols | `binary/symbols.py` | ✅ | |
| Exports navigables | `binary/binary_exports.py` | ✅ | Démangling C++, navigation vers désasm |
| Imports + xrefs | `binary/imports_analysis.py` | ✅ | Score suspicion, badges catégories, DLL dépliables |
| DWARF | `binary/dwarf.py` | ✅ | Commentaires `; src/file.c:42` dans le désasm |
| Entropy | `binary/entropy.py` | ✅ | |
| Packer detection | `binary/headers.py` + `binary/packer_signatures.yar` | ✅ | Signatures YARA formelles (byte patterns) : UPX PE x86/x64, UPX ELF, ASPack, MPRESS, Petite, PECompact ; fallback gracieux si yara-python absent ; score +40/famille YARA, signal `yara_signature` ; UI différencie signature formelle vs heuristique |
| Offset → vaddr | `binary/offset_to_vaddr.py` | ✅ | ELF/PE/Mach-O via lief |
| Ressources PE | `binary/pe_resources.py` | ⚠️ | Détail plus exploitable dans le host avec pivots vers `Recherche` (texte / hex) ; pas encore de navigation directe `Hex`/offset ressource |
| Exception handlers | `exception_handlers.py` | ⚠️ | Vue reliée à `Désasm`, `CFG` et `Pseudo-C` ; enrichissements backend encore limités selon format |

### 1.2 Désassemblage & Graphes

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Désassemblage enrichi | `disasm/disasm.py` | ✅ | Bannières fonctions, labels, commentaires inline, hints stack |
| Discover functions | `disasm/discover_functions.py` | ✅ | Tail-calls, thunks, PLT stubs, `boundary_reason`, métriques CLI |
| CFG | `disasm/cfg.py` | ✅ | Switch tables (x86/ARM64, RIP-relative, lief), adapters multi-arch, `case_label` sur arcs ; `unresolved_default` sur blocs sans cible default résolue ; fallback max_entries 256 |
| Call graph | `disasm/call_graph.py` | ✅ | Adapters ISA, fallback `iter_supported_adapters()` |
| Xrefs | `disasm/xrefs.py` | ✅ | Code refs + data refs multi-arch via adapters |
| Import xrefs | `disasm/import_xrefs.py` | ✅ | Callsites par import, navigation vers désasm |
| Stack frame | `disasm/stack_frame.py` | ⚠️ | x86/x64/ARM64/ARM32 + fallback générique ; frame-pointer-less partiel |
| Calling convention | `disasm/calling_convention.py` | ⚠️ | x86/x64/ARM64/ARM32 détaillé ; autres ISA via table `arch.py` |
| ASM simulator | `disasm/asm_sim.py` | ✅ | |

### 1.3 Décompilation

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Décompilateur multi-backend | `decompile/decompile.py` | ✅ | Ghidra/RetDec/Angr Docker ; `quality_details` exposé dans l'UI ; scoring `auto_first` calibré sur corpus 4 bandes (high/medium/low/bad) |

### 1.4 Annotations & Types

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Annotations | `annotations/annotations.py` | ✅ | JSON `.pile-ou-face/annotations/<hash>.json` |
| Structs C (éditeur v3) | `annotations/structs.py` | ⚠️ | `struct`, `union`, `enum` ; `enum class`/`enum struct` + underlying type ✅ ; tableaux multidim (`array_dims`) ✅ ; pointeurs de fonctions ✅ ; propagation avancée (Hex View, accès indirects non triviaux) encore partielle |
| Typed data | `annotations/typed_data.py` | ✅ | Endian et `ptr_size` détectés depuis lief et propagés dans tous les décodeurs |
| Typed struct refs | `annotations/typed_struct_refs.py` | ✅ | Propagation structs vers désasm / xrefs / pseudo-C |

### 1.5 Recherche & Exploration

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Hex View | `search/hex_view.py` | ⚠️ | Métadonnées `endianness`, `ptr_size`, `bits` et `arch` exposées ; synchro de plages améliorée ; reste des raffinements avancés pour certains blobs bruts |
| Search | `search/search.py` | ✅ | |
| Strings | `search/strings.py` | ✅ | |
| ROP gadgets | plugin `OFFENSIF` | ⚠️ | Commande attendue via runtime plugin ; implémentation externe |
| YARA scan | plugin `MALWARE` | ⚠️ | Commande optionnelle via runtime plugin ; le host offre une `bibliothèque active` éditable (projet + global) et un `chemin ponctuel` |

### 1.6 Analyse & Détection

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Behavior | plugin `MALWARE` | ⚠️ | Plugin optionnel attendu ; le host expose le point d'intégration |
| Anti-analysis | plugin `MALWARE` | ⚠️ | Plugin optionnel attendu ; le host expose le point d'intégration |
| Vuln patterns | plugin `AUDIT` | ⚠️ | Plugin optionnel attendu ; le host expose le point d'intégration |
| Taint analysis | plugin `AUDIT` | ⚠️ | Proof dossiers par fonction émis (XSYNC-002) ; le host consomme et affiche les flux enrichis |
| FLIRT signatures | plugin `OFFENSIF` | ⚠️ | Plugin optionnel attendu ; le host expose le point d'intégration |
| Func similarity | plugin `OFFENSIF` | ⚠️ | Plugin buildable ; intégration host branchée ; corpus packagé limité (OpenSSL uniquement) |
| Capa scan | plugin `MALWARE` | ⚠️ | Plugin optionnel attendu ; le host expose le point d'intégration |
| Analysis index | `analysis/analysis_index.py` | ✅ | Base SQLite unifiée |
| Function radar | `analysis/function_radar.py` | ✅ | Priorisation workflow : hotspots, quick wins, entrées candidates, clusters de signaux |

### 1.7 Export & Patch

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Binary diff | plugin `OFFENSIF` | ⚠️ | Plugin buildable ; intégration host branchée |
| Export | `export/export.py` | ✅ | |
| String déobfuscation | `export/string_deobfuscate.py` | ✅ | XOR/ROT/Base64/RC4/AES-ECB ; stackstrings x86-64 + ARM64 ; ARM32/Thumb/MIPS via profil `raw` ; recherche de clés crypto élargie et priorisée par indices AES |
| Binary patch | `patch/binary_patch.py` | ✅ | |
| Patch manager | `patch/patch_manager.py` | ✅ | Undo/redo inter-sessions, JSON `.pile-ou-face/patches/` |

### 1.8 Autres

| Module | Fichier | Statut | Notes |
|--------|---------|--------|-------|
| Cache SQLite | `cache/cache.py` + `cache/cache_index.py` | ✅ | `.pfdb` = source de vérité analyse ; index SQLite pour le catalogue du cache statique, purge et futur multi-session |
| Cache admin | `cache/cache_admin.py` | ✅ | |
| REPL Python | `repl/repl.py` | ✅ | API 15 fonctions, sandbox timeout |
| Rules manager | `rules/rules_manager.py` | ✅ | Règles projet + globales, activables séparément |
| MCP server | `backends/mcp/server.py` | ✅ | Transport stdio + HTTP |
| Ollama bridge | `backends/mcp/ollama_bridge.py` | ✅ | |

---

## 2. Ce qui reste à faire

### Ordre d'exécution prioritaire — qualité statique

Cet ordre privilégie d'abord la mesure, puis les améliorations algorithmiques
mesurables, avant les migrations de compatibilité plus risquées.

| Ordre | Chantier | Statut | Classification | Pourquoi maintenant |
|---:|---|---|---|---|
| 1 | Fiabiliser la couverture des tests | ✅ | `public-only` | Baseline reproductible avant toute évolution : `coverage.py` côté Python, c8 côté extension, seuils anti-régression en CI |
| 2 | Remonter la couverture des tests critiques | ⚠️ | `public-only` | Les seuils actuels évitent la régression, mais la baseline reste trop basse pour sécuriser les gros refactors |
| 3 | Créer un corpus de binaires réels | ⚠️ | `public-only` | Mesurer GCC/Clang, `-O0/-O2/-Os`, PIE, stripped, x86-64 et ARM64 sur des résultats attendus |
| 4 | Renforcer l'analyse des binaires optimisés | ⚠️ | `public-only` | Exploiter le corpus pour améliorer le suivi `rsp/sp`, les réalignements, `alloca`, DWARF64 et Mach-O unwind |
| 5 | Corriger la sémantique de revue | ❌ | `cross-repo` | Remplacer l'inférence « deux annotations = reviewed » par un état explicite partagé (`needs_review`, dossiers de preuve) |
| 6 | Rendre les analyses annulables | ⚠️ | `public-only` | Le désassemblage long est annulable ; généraliser ensuite aux autres subprocessus static |
| 7 | Achever la migration SQLite | ❌ | `public-only` avec audit des consommateurs | Retirer les fallbacks `.asm` / `.mapping.json` seulement après migration des derniers consommateurs dynamiques et MCP |

#### 1. Couverture des tests ✅

Livré le 2026-06-22 :

- Python : `coverage.py` avec branch coverage sur `backends/static` et
  `backends/plugins`, seuil global initial de **63 %**.
- Extension : NYC remplacé par c8, avec couverture de `src/**/*.ts` et
  `webview/**/*.js`.
- Seuils extension initiaux : **27 % lignes/statements**, **58 % branches**,
  **73 % fonctions**.
- CI : les jobs rapides et complets exécutent désormais les tests avec les
  seuils de couverture.
- Commandes locales : `make test-python-coverage`,
  `make test-extension-coverage` et `make test-coverage`.

Baseline au moment de l'activation :

- Python : **64 %**, 941 tests collectés, 937 réussis et 4 ignorés.
- Extension : **28,32 % lignes**, **60,32 % branches**, **75,59 % fonctions**,
  311 tests réussis et 1 ignoré.

Les seuils sont volontairement placés juste sous la baseline. Ils doivent être
augmentés progressivement à mesure que le corpus réel et les tests de
régression enrichissent la suite.

Pour lire le pourcentage global actuel :

- Python : `make test-python-coverage`, puis lire la ligne `TOTAL`.
- Extension : `make test-extension-coverage`, puis lire la ligne `All files`.
- Tous les contrôles : `make test-coverage`.

#### 2. Remonter la couverture des tests critiques ⚠️

La couverture est maintenant mesurée, mais elle reste trop basse pour servir de
filet de sécurité sérieux sur les gros changements static.

Objectif court terme :

- Python : passer de **64 %** à **70 %**, en priorité sur
  `backends/static`.
- Extension : passer de **28,32 % lignes** à **35 %**, en priorité sur
  `src/static`, `src/static/hub` et les contrôleurs webview static à 0 %.
- Ajouter des tests sur les chemins utilisateur critiques plutôt que couvrir
  artificiellement les petites branches sans valeur.
- Monter les seuils CI uniquement après chaque gain validé, pour éviter les
  seuils décoratifs.

Priorités de tests :

1. loaders/navigation/actions de l'onglet static ;
2. `analysisContext.ts` : cache, SQLite, fallbacks et erreurs subprocess ;
3. `staticHandlers.ts` : orchestration backend et erreurs utilisateur ;
4. webview static : payload, search, widgets et rendu de messages ;
5. Python static : stack frame, CFG, xrefs, exception handlers et radar.

Avancement 2026-06-26 :

- Extension : **30,33 % lignes/statements**, **60,98 % branches**,
  **77,27 % fonctions**, 361 tests réussis et 1 ignoré.
- Seuils c8 remontés à **30 % lignes/statements**, **60 % branches** et
  **77 % fonctions**.
- Tests ajoutés sur `asmUtils.ts`, `payloadCore.js`,
  `filePayloadController.js`, `payloadBuilderController.js` et
  `payloadStateController.js`.

#### 3. Corpus de binaires réels ⚠️

Construire une matrice versionnée couvrant :

- GCC et Clang ;
- `-O0`, `-O2`, `-Os` ;
- PIE et non-PIE ;
- symboles présents et binaires stripped ;
- x86-64 et ARM64.

Mesures attendues : précision/rappel des fonctions découvertes, exactitude des
arêtes CFG et qualité des variables/arguments de stack reconstruits.

Avancement 2026-06-26 :

- Corpus généré à la volée depuis une source C déterministe, sans versionner de
  binaires opaques.
- Matrice courte CI-friendly : GCC et Clang si disponibles, `-O0`, `-O2`,
  `-Os`, PIE/non-PIE, symboles présents et binaires stripped.
- Support ARM64 via `aarch64-linux-gnu-gcc` quand le toolchain est disponible,
  avec job CI dédié `Real Corpus ARM64` sur Ubuntu.
- Mesures automatisées : rappel/précision de découverte de fonctions, présence
  d'arêtes CFG, CFG par fonction `main` et schéma stack-frame sur `pof_stacky`.
- Résumé JSON optionnel par cas via `make test-real-corpus`, écrit dans
  `.pile-ou-face/test-artifacts/real_binary_corpus_metrics.json` pour suivre
  les tendances sans versionner les binaires générés.
- Attendus CFG enrichis avec arêtes `call` nommées depuis le source C
  déterministe (`main`, `pof_switchy`, `pof_branchy`, etc.) et exposées dans le
  résumé JSON `pile-ou-face.real-binary-corpus.metrics.v2`.

Reste à faire :

- Étendre progressivement la matrice ARM64 au-delà du cas `-O2` PIE symbolisé,
  si le coût CI reste acceptable.

#### 4. Binaires optimisés ⚠️

Utiliser le corpus réel pour étendre le suivi de `rsp/sp` à travers les
branches, les réalignements et `alloca`. Compléter également le décodage
DWARF64 et la résolution par fonction des métadonnées unwind Mach-O.

Avancement 2026-06-26 :

- Stack frame x86 : suivi des réalignements `and rsp, -0x10` et des
  ajustements statiques via `lea rsp, [rsp +/- imm]`.
- Stack frame x86 : détection des ajustements dynamiques type `alloca`
  (`sub/add rsp, registre`) et suppression conservatrice des accès
  `rsp` ambigus pour éviter de créer de fausses variables/arguments.
- Stack frame ARM64 : détection des ajustements dynamiques type `alloca`
  (`sub/add sp, sp, registre`) et suppression conservatrice des accès
  `sp` ambigus ; les accès `x29` restent exploitables.
- Cache stack-frame invalidé via nouvelles versions pour recalculer les anciens
  résultats après chaque raffinement de sémantique.
- Tests ajoutés sur réalignement, `alloca` dynamique et `lea` statique.
- Exception handlers ELF : support des records `.eh_frame` DWARF64
  (`0xffffffff` + longueur 64-bit), sans interrompre le scan au premier
  record étendu.
- Exception handlers Mach-O : résolution par fonction des entrées
  `__compact_unwind` quand la section est présente, avec encoding/personality
  et LSDA exposés dans les flags existants.

Reste à faire :

- Propager le suivi `rsp/sp` à travers les branches et merges CFG.
- Parser les pages `__unwind_info` Mach-O compactées quand `__compact_unwind`
  n'est pas disponible.

#### 5. Sémantique de revue ❌

Une annotation ne constitue pas une revue. Ajouter un état explicite enregistré
par l'utilisateur au lieu de déduire `reviewed` du nombre d'annotations.

Contract:
- name: function review-state semantics
- owner repo: public host
- consumer repo: optional plugins
- backward compatible: à définir
- counterpart change required: oui
- merge order: public-first recommandé

#### 6. Analyses annulables ⚠️

Rendre les notifications de progression annulables et propager l'annulation
jusqu'au subprocessus Python, avec terminaison propre et état UI explicite.

Avancement 2026-06-26 :

- Désassemblage avec progression : notification VS Code maintenant annulable.
- IHM static : bouton `Recalculer` dans l'onglet Désassemblage pour relancer
  explicitement l'analyse sans cache (`useCache: false`).
- IHM décompilateur : bouton `↻ Recalculer` pour relancer la décompilation de
  la sélection courante en contournant le cache webview.
- `runCommand` accepte un `cancelToken` optionnel et termine le subprocessus
  avec `SIGTERM`, puis `SIGKILL` en garde-fou si nécessaire.
- Tests extension ajoutés pour le passage du token et la terminaison du
  processus enfant.

Reste à faire :

- Étendre le même mécanisme aux autres analyses longues déclenchées depuis les
  handlers static.

#### 7. SQLite source de vérité unique ❌

Auditer puis migrer les derniers consommateurs dynamiques et MCP avant de
supprimer les fallbacks `.asm` / `.disasm.mapping.json`.

### 🔥🔥🔥 Phase 1 — Fondations V1 (priorité immédiate)

---

#### CLEAN CODE — suppression du code mort ✅

**Objectif :** éliminer le code inutilisé qui grossit le projet, complique la lecture et crée des vecteurs de maintenance silencieux.

**Périmètre identifié :**

| Domaine | Statut | Note |
|---------|--------|------|
| Fallbacks legacy `.asm` / `.disasm.mapping.json` | ⚠️ | Encore utilisés par pipeline dynamique et MCP — non suppressibles sans migration complète |
| `hub.ts` — dead functions | ✅ | Audit exhaustif : aucune fonction morte détectée ; découpe en modules suivie dans l'item dédié |
| `staticHandlers.ts` — dead code | ✅ | `normalizeInstallDir` supprimée ; branche `prependPath` morte supprimée |
| `backends/static/` — `_addr_to_int` dupliquée | ✅ | Consolidée dans `backends/shared/utils.parse_addr` (disasm, xrefs, function_radar) |
| `backends/static/` — autres utilitaires | ✅ | Audit : `json.dumps`, formatage hex, validation path — patterns inline lisibles, pas d'extraction justifiée |
| `docs/` — docs historiques modules optionnels natifs | ✅ | Audit : aucun contenu obsolète détecté, architecture déjà à jour |
| Tests — fixtures non référencées | ✅ | Audit : toutes les fixtures sont utilisées par des tests actifs |

**Processus suggéré :**
1. Inventorier avec `grep` / LSP les symboles définis mais jamais appelés dans `hub.ts` et `staticHandlers.ts`.
2. Supprimer les fallbacks `.asm` legacy après avoir vérifié qu'aucun handler ne les produit encore.
3. Identifier et supprimer les fixtures de test orphelines.
4. Nettoyer les docs historiques (ne pas réécrire, juste supprimer les sections obsolètes).

**Règle d'or :** si une fonction n'est appelée nulle part et n'est pas un point d'entrée publié (API, CLI, MCP), elle est morte et doit être supprimée.

---

#### Découper `hub.ts` ⚠️

Modules créés et dispatch map opérationnel. `hub.ts` : 3408 → 1185 lignes (-65%) au 2026-06-11.

| Module | Statut | Notes |
|---|---|---|
| `hub/navigation.ts` | ✅ | |
| `hub/loaders.ts` | ✅ | `getSymbols` migré |
| `hub/graphRenderers.ts` | ✅ | |
| `hub/analysisContext.ts` | ✅ | |
| `hub/actions.ts` | ✅ | |
| `hub/traceHistory.ts` | ✅ | |
| `hub/asmUtils.ts` | ✅ | |
| `hub/archSupport.ts` | ✅ | `FEATURES`, `FEATURE_LEVELS`, `readArchSupportFromMapping`, `getFeatureLevel`, `isFeatureAtLeast`, `isFeatureUsable`, `isFeatureFull`, `worstFeatureEntry` |

Reste dans `hub.ts` : orchestration panel + `runTrace` (mode dynamique — à extraire vers `hub/traceHistory.ts` en Phase 2).

---

#### Calibrer le scoring décompilateur ✅

Corpus synthétique (8 fixtures JSON) constitué dans `backends/static/tests/fixtures/decompile_corpus/` couvrant 4 bandes de qualité : **high** [50,120], **medium** [15,49], **low** [0,14], **bad** [≤−1]. Poids de `_score_decompile_code` validés sur corpus — aucun ajustement requis. Suite `test_decompile_scoring.py` réécrite en unittest (23 tests, 3 classes). Livré 2026-06-13.

---

#### Mach-O ARM64 ✅

RetDec, Angr et Ghidra produisent tous un résultat correct sur Mach-O ARM64. Le problème mentionné (`pdc` rizin) référençait un outil jamais implémenté — note obsolète supprimée.

---

#### Finaliser licence/chiffrement plugins ✅

Livré 2026-06-16. AES-256-GCM via `cryptography` dans `runtime.py` (plus de subprocess openssl pour le déchiffrement des bundles). Handler `pluginStatusRefresh` dans `shared/messages.js` (livré avec refactor #159). Tooling licences migré vers `cryptography` : `generate_rsa_keypair`, `sign_json_payload` (RSA-PSS SHA256), `verify_json_signature`, `_encrypt_file_with_content_key`, `_decrypt_payload`.

---

### 🔥🔥 Phase 2 — Différenciateurs V1

---

#### Investigation mode — analyse croisée v2 ✅

Livré 2026-06-16. Plugin `cross-analysis-pro` (`orchestrator.py` + `ranking.py`, `plugin_main.py`, `tab.js`).

Ce qui a été implémenté :
- `cluster_by_technique(ranked_functions, attck_result)` dans `ranking.py` : regroupe les fonctions par technique MITRE ATT&CK détectée, calcule `patch_priority: true` si une fonction a simultanément `taint` + `behavior`.
- Intégration optionnelle dans `plugin_main.py` : appel à `run_attck_tagging()` depuis `malware-triage-pro` avec fallback gracieux si le plugin est absent (`attck_result = None`).
- Champ `"techniques"` ajouté au JSON de sortie — rétrocompatibilité totale avec les champs existants.
- UI `tab.js` : section « Techniques détectées » au-dessus de la liste de fonctions. Une carte par technique (ID ATT&CK, nom, badges tactiques, badge `PATCH PRIORITY`). Clic sur carte → filtre la liste de fonctions. Section masquée si `techniques: []`.

Ce qui reste (phase cross-repo) :
- Relations plus riches entre findings (`entities`, liens inter-findings).
- Patch targets corrélés entre `taint`, `behavior` et `ROP`.

---

#### Bundles plugins — nouvelles features ✅

| Feature | Plugin | Statut |
|---------|--------|--------|
| MITRE ATT&CK tagging statique | `malware-triage-pro` | ✅ `attck_tagger.py` |
| CWE + severity enrichment sur taint flows | `vulnerability-audit-pro` | ✅ `enrich_flow_with_cwe` dans `taint.py` |
| ROP chain builder (angr + ROPgadget) | `offensive-research-pro` | ✅ `rop_chain_builder.py` |

---

#### Structs C — cas avancés ⚠️

Backend livré : `enum class`/`enum struct` (avec underlying type optionnel), tableaux multidimensionnels (`array_dims` liste, `array_len` = produit total), pointeurs de fonctions (`type_kind: "fn_ptr"`, tag `fn_ptr` dans le layout). Reste : application depuis Hex View pour les plages larges et cas imbriqués, propagation pour les accès indirects et offsets non triviaux.

---

#### Func similarity — corpus élargi ⚠️

Starter pack actuel : OpenSSL libssl (1 entrée, 7 fonctions) dans `function_similarity_refs.json`.
Ajouter : `libc`, `zlib`, `libcrypto`, familles malware courantes.

---

#### Behavior / anti-analysis — contextualisation ⚠️

- `anti_analysis` : enrichir la portée/fonction associée hors cas imports simples.

---

### 🔥 Phase 3 — Polish et distribution V1

---

#### Export rapport ❌

JSON structuré + HTML navigable exportable depuis le panneau `Fonctions` ou depuis l'analyse croisée. Utile pour les pentesters qui livrent des rapports clients.

---

#### Installation one-click ❌

Téléchargement automatique des dépendances (Docker images, Python venv) depuis l'extension VS Code. Prérequis pour que l'outil soit adopté sans DevOps.

---

#### Hex ↔ Désasm sync — cas avancés ⚠️

Reste à étendre la synchro de plages aux contextes multi-sources hors workflow `Fonctions`.

---

### Post-V1 (hors scope immédiat)

| Sujet | Pourquoi après |
|---|---|
| Analyse dynamique (Frida, GDB) | Architecture différente, scope orthogonal |
| Corrélation pcap + binaire | Dépendance infrastructure réseau |
| Import/export IDA/Ghidra | Dépendances licences tierces |
| App cloud / browser | Infrastructure non triviale |
| Session collaborative | Complexité serveur temps réel |
| Multi-langue UI | Faible ROI à ce stade |

---

## 3. Tableau de priorisation V1

| Priorité | Sujet | Effort | Impact |
|----------|-------|--------|--------|
| ✅ | **Couverture tests fiable** : coverage.py + c8 + seuils CI | Faible | Rend les régressions mesurables et prépare le corpus réel |
| 🔥🔥🔥 | **Corpus de binaires réels** : compilateurs, optimisations, PIE, stripped, x86-64/ARM64 | Moyen | Base objective pour mesurer la qualité des analyses |
| 🔥🔥🔥 | **Analyse des binaires optimisés** : stack, DWARF64, Mach-O unwind | Élevé | Meilleur gain de précision statique |
| 🔥🔥 | **Sémantique de revue explicite** | Moyen | Évite les faux états `reviewed` ; changement cross-repo |
| 🔥 | **Analyses annulables** | Faible | UX robuste sur les gros binaires |
| 🔥 | **SQLite source de vérité unique** | Moyen | Élimine les artefacts périmés après migration des consommateurs |
| ✅ | **Licences** : AGPL-3.0 + CLA + SPDX headers (164 py / 25 ts) + README Licensing | Faible | Prérequis légal pour commercialiser |
| ✅ | **Clean code** : dead code TS/Python ✅ — fallbacks `.asm` non suppressibles sans migration pipeline | Moyen | Maintenabilité et lisibilité |
| ✅ | **Découper `hub.ts`** : 3408→1185 lignes ✅ modules hub/ tous créés (`archSupport.ts` ✅ 2026-06-13) | Élevé | Bloquant pour tout travail futur sur l'extension |
| ✅ | **Calibrer décompilateur** sur corpus (4 bandes qualité, 23 tests) | Moyen | Le mode Auto doit être fiable — feature clé du pitch |
| 🔥🔥🔥 | **Mach-O ARM64** : fix décompilation (contourner `pdc` rizin) | Moyen | Plateforme principale des développeurs macOS |
| ✅ | **Finaliser licence/chiffrement plugins** | Élevé | Prérequis distribution V1 — livré 2026-06-16 |
| ✅ | **Investigation mode v2** (clustering ATT&CK, cartes techniques, patch priority) | Élevé | Livré 2026-06-16 |
| ✅ | **Bundles plugins features** (MITRE ATT&CK, CWE, ROP builder) | Moyen | Livré |
| 🔥🔥 | **Structs C avancés** (C++ enum class, fn ptrs, multidim) | Moyen | Protocoles binaires et formats de données |
| 🔥🔥 | **Func similarity — corpus élargi** (libc, zlib, malware) | Faible | Multiplie la valeur sans effort architectural |
| ✅ | **Packer detection formelle** (YARA byte patterns + corpus de validation) | Moyen | Livré 2026-06-15 |
| 🔥 | **Export rapport** JSON + HTML | Faible | Use case pentester direct |
| 🔥 | **Installation one-click** | Élevé | Adoption sans friction |
| ⚠️ | **Hex ↔ Désasm sync** — cas avancés | Faible | Finition workflow |
