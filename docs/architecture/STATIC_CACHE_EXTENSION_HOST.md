# Cache statique : appels synchrones et contextes d'appel sur l'Extension Host

## Périmètre et méthode

- Commit de base inspecté : `0e96a4f75f8622009cce572262b105e1962b43e4`.
- Source principale : `extension/src/shared/staticCache.ts`.
- Appelants recherchés dans `extension/src/` uniquement (code et tests).
- Méthode : lecture statique. Aucune exécution, aucune mesure de latence.
- Toutes les références sont au format `chemin:ligne` au commit de base.
- Les lignes citées sans préfixe de chemin appartiennent à `extension/src/shared/staticCache.ts`.

### Limite de ce que le code lu démontre

- Les fonctions appelantes sont définies sous `extension/src/` et manipulent des objets VS Code
  (`panel.webview.postMessage`, `vscode.window`), par exemple `extension/src/shared/sharedHandlers.ts:344`
  et `extension/src/shared/sharedHandlers.ts:598`.
- L'enregistrement et la répartition des messages vers ces gestionnaires n'ont pas été inspectés.
- Le fait que chaque appelant s'exécute dans le processus Extension Host est donc une déduction
  à partir de l'emplacement du code et des objets manipulés, non une preuve d'exécution.
- Les fonctions appelantes sont déclarées `async`, mais l'appel synchrone qu'elles contiennent
  s'exécute sans `await` : le fil qui l'exécute est occupé pendant la durée de l'appel.
- `getExtensionPath` est importé de `./utils` (`extension/src/shared/staticCache.ts:8`) ; son
  implémentation n'a pas été lue.

## 1. Appels synchrones dans `staticCache.ts`

| Ligne | Appel | Fonction englobante | Rôle établi par lecture |
| --- | --- | --- | --- |
| `extension/src/shared/staticCache.ts:25` | `fs.statSync` | `getCacheKey` (23) | Lit `mtimeMs` et `size` du binaire pour construire la clé de cache. |
| `extension/src/shared/staticCache.ts:26` | `crypto.createHash(...).update(...).digest` | `getCacheKey` (23) | Calcul synchrone de l'empreinte SHA-256 tronquée à 16 caractères (chemin, mtime, taille). |
| `extension/src/shared/staticCache.ts:54` | `fs.existsSync` (dans `candidates.find`) | `detectPythonExecutable` (47) | Cherche l'interpréteur Python du venv parmi trois chemins ; repli sur `python3` si aucun n'existe. |
| `extension/src/shared/staticCache.ts:61` | `fs.existsSync` | `runCacheStore` (57) | Vérifie la présence du script `cache_index.py` ; retourne `null` s'il est absent. |
| `extension/src/shared/staticCache.ts:62` | `fs.mkdirSync` (récursif) | `runCacheStore` (57) | Crée le dossier `static_cache` dans le répertoire de stockage. |
| `extension/src/shared/staticCache.ts:63` | `cp.spawnSync` | `runCacheStore` (57) | Lance le script Python `cache_index.py` avec `--db` et les arguments de l'opération, attend sa fin et lit sa sortie standard. |
| `extension/src/shared/staticCache.ts:76` | `JSON.parse` | `runCacheStore` (57) | Analyse synchrone de la sortie standard du sous-processus. |
| `extension/src/shared/staticCache.ts:102` | `fs.statSync` | `writeCache` (98) | Lit `mtimeMs` et `size` pour les passer à l'opération `put`. |
| `extension/src/shared/staticCache.ts:109` | `JSON.stringify` | `writeCache` (98) | Sérialise la donnée à stocker ; transmise au sous-processus via `input` (stdin). |

Appels indirects à ceux-ci dans le même fichier :

- `getCacheKey` est appelé en `extension/src/shared/staticCache.ts:90` (`readCache`) et
  `extension/src/shared/staticCache.ts:99` (`writeCache`).
- `runCacheStore` est appelé en `extension/src/shared/staticCache.ts:92` (`readCache`),
  `extension/src/shared/staticCache.ts:103` (`writeCache`), `extension/src/shared/staticCache.ts:117`
  (`listCacheEntries`), `extension/src/shared/staticCache.ts:122` (`pruneCacheEntries`),
  `extension/src/shared/staticCache.ts:125-127` (`clearCacheEntries`) et
  `extension/src/shared/staticCache.ts:130` (`deleteCacheEntriesForBinary`).
- Chaque appel à `runCacheStore` qui atteint la ligne 63 bloque donc jusqu'à la fin du sous-processus
  ou jusqu'à l'expiration du `timeout` (voir section 4).

## 2. Fonctions exportées et appelants

Exports : `extension/src/shared/staticCache.ts:135-145`.

### 2.1 `readCache` (89)

Appels synchrones atteints : `getCacheKey` (`fs.statSync`, hachage), puis `runCacheStore` (`fs.existsSync`,
`fs.mkdirSync`, `cp.spawnSync`, `JSON.parse`).

| Appelant | Fonction englobante | Contexte démontrable |
| --- | --- | --- |
| `extension/src/static/hub/loaders.ts:41` | `resolveCachedBinaryView` (30) | Appelée par les gestionnaires `hubLoadSymbols` (`extension/src/static/hub/loaders.ts:62`), `hubLoadStrings` (`extension/src/static/hub/loaders.ts:93`), `hubLoadInfo` (`extension/src/static/hub/loaders.ts:144`) et `hubLoadSections` (`extension/src/static/hub/loaders.ts:197`). L'appel est conditionné par `useCache` (`extension/src/static/hub/loaders.ts:40`). |
| `extension/src/static/hub/analysisContext.ts:459` | `readAnalysisCacheEntry` (456) | Voir 3.1. Appel précédé de `getAnalysisCacheTarget` (447), qui retourne `null` si `allowCache` est faux. |

Injection : `readCache` est importé en `extension/src/static/hub.ts:35`, puis passé à
`createAnalysisContext` (`extension/src/static/hub.ts:919`) et à `createLoaders`
(`extension/src/static/hub.ts:933`). Les paramètres reçus sont déclarés en
`extension/src/static/hub/analysisContext.ts:26` et `extension/src/static/hub/loaders.ts:13`.

Appelants de test : voir section 5.

### 2.2 `writeCache` (98)

Appels synchrones atteints : `getCacheKey`, `fs.statSync` (102), `JSON.stringify` (109), puis `runCacheStore`.

| Appelant | Fonction englobante | Contexte démontrable |
| --- | --- | --- |
| `extension/src/static/hub/loaders.ts:48` | `resolveCachedBinaryView` (30) | Exécuté après `await compute()` (`extension/src/static/hub/loaders.ts:47`), sans condition sur `useCache`. Même liste de gestionnaires que 2.1. |
| `extension/src/static/hub/analysisContext.ts:465` | `writeAnalysisCacheEntry` (462) | Voir 3.1. |

Injection : identique à 2.1 (`extension/src/static/hub.ts:919`, `extension/src/static/hub.ts:933`).

### 2.3 `getCacheKey` (23)

- Appels synchrones : `fs.statSync` (25), hachage (26).
- Appelants dans `extension/src/` hors `staticCache.ts` : aucun appelant hors test identifié.
- Appels internes : `extension/src/shared/staticCache.ts:90`, `extension/src/shared/staticCache.ts:99`.
- Appels de test : `extension/src/tests/staticCache.test.ts:21-22`.

### 2.4 `getCacheDir` (34)

- Aucun appel synchrone au système de fichiers dans la fonction elle-même (`path.join`).
- Appelants hors test identifiés : aucun.
- Appels internes : `extension/src/shared/staticCache.ts:39`, `extension/src/shared/staticCache.ts:62`.
- Appels de test : `extension/src/tests/staticCache.test.ts:23`, `extension/src/tests/staticCache.test.ts:33`.

### 2.5 `getStaticCacheDbPath` (38)

- Aucun appel synchrone au système de fichiers dans la fonction elle-même.
- Appelants hors test identifiés : aucun.
- Appel interne : `extension/src/shared/staticCache.ts:65` (dans `runCacheStore`).
- Appels de test : `extension/src/tests/staticCache.test.ts:24`, `extension/src/tests/staticCache.test.ts:32`.

### 2.6 `listCacheEntries` (116)

Appels synchrones atteints : `runCacheStore` (opération `list`).

| Appelant | Fonction englobante | Contexte démontrable |
| --- | --- | --- |
| `extension/src/shared/fileManager.ts:252` | `listCacheEntries` de `fileManager` (251) | Importé sous l'alias `listSqliteCacheEntries` (`extension/src/shared/fileManager.ts:12`). Appelé par `listAll` (`extension/src/shared/fileManager.ts:262`). |

Chaîne vers l'appelant de plus haut niveau lu : `listAll` est appelé par `extension/src/shared/sharedHandlers.ts:345`
(`handleMissingBinarySelection`, 321), `extension/src/shared/sharedHandlers.ts:557` (`hubForgetRecentBinary`, 544),
`extension/src/shared/sharedHandlers.ts:593` (`listGeneratedFiles`, 592), `extension/src/shared/sharedHandlers.ts:612`
(`cleanupGeneratedFiles`, 596) et `extension/src/shared/sharedHandlers.ts:624` (`purgeStaleCache`, 614).

Appelant de `fileManager.listCacheEntries` (export en `extension/src/shared/fileManager.ts:347`) hors `listAll` :
aucun appelant hors test identifié dans `extension/src/`.

### 2.7 `pruneCacheEntries` (121)

Appels synchrones atteints : `runCacheStore` (opération `prune`).

| Appelant | Fonction englobante | Contexte démontrable |
| --- | --- | --- |
| `extension/src/shared/fileManager.ts:282` | `purgeStaleCache` (280) | Appelée par `extension/src/shared/sharedHandlers.ts:615` (`purgeStaleCache`, 614) et par `extension/src/shared/fileManager.ts:323` (`cleanupForBinary`, 318, si `purgeStale` est vrai). |
| `extension/src/shared/fileManager.ts:307` | `cleanupAll` (290) | Si `artifactsOnly` est faux et `purgeStale` est vrai. Les appels de `cleanupAll` lus (`extension/src/shared/sharedHandlers.ts:606`) ne passent pas d'options. |

### 2.8 `clearCacheEntries` (125)

Appels synchrones atteints : `runCacheStore` (opération `clear`).

| Appelant | Fonction englobante | Contexte démontrable |
| --- | --- | --- |
| `extension/src/shared/fileManager.ts:309` | `cleanupAll` (290) | Si `artifactsOnly` est faux et `purgeStale` est faux. Appelée par `extension/src/shared/sharedHandlers.ts:606` (`cleanupGeneratedFiles`, 596). |

### 2.9 `deleteCacheEntriesForBinary` (129)

Appels synchrones atteints : `runCacheStore` (opération `delete-binary`).

| Appelant | Fonction englobante | Contexte démontrable |
| --- | --- | --- |
| `extension/src/shared/fileManager.ts:176` | `cleanupCacheEntriesForBinary` (173) | Appelée par `cleanupForBinary` (`extension/src/shared/fileManager.ts:321`). `cleanupForBinary` est appelée par `extension/src/shared/sharedHandlers.ts:337` (`handleMissingBinarySelection`, 321) et `extension/src/shared/sharedHandlers.ts:550` (`hubForgetRecentBinary`, 544). |

## 3. Chaînes intermédiaires dans `extension/src/static/hub/`

### 3.1 Enveloppes `readAnalysisCacheEntry` et `writeAnalysisCacheEntry`

Définies en `extension/src/static/hub/analysisContext.ts:456` et `extension/src/static/hub/analysisContext.ts:462`.
Elles n'appellent le cache que si `getAnalysisCacheTarget` (447) retourne une cible : `allowCache` vrai,
chemin existant et non répertoire (`extension/src/static/hub/analysisContext.ts:448-450`). Avec `allowCache` faux,
aucun appel à `readCache` ou `writeCache` n'est atteint par ces enveloppes.

Appelants lus :

| Appelant | Fonction englobante | Accès |
| --- | --- | --- |
| `extension/src/static/hub/analysisContext.ts:278` | `loadBinaryHeaders` (277) | lecture, clé `info` |
| `extension/src/static/hub/analysisContext.ts:284` | `loadBinaryHeaders` (277) | écriture, clé `info` |
| `extension/src/static/hub/analysisContext.ts:476` | `resolveCachedAnalysisView` (469) | lecture |
| `extension/src/static/hub/analysisContext.ts:482` | `resolveCachedAnalysisView` (469) | écriture, après `await compute()` (481) |
| `extension/src/static/hub/analysisContext.ts:582` | `loadBinarySymbols` (580) | lecture, clé `symbols` ou `symbols_all` |
| `extension/src/static/hub/analysisContext.ts:595` | `loadBinarySymbols` (580) | écriture, dans la promesse d'extraction (590-597) |
| `extension/src/static/hub/graphRenderers.ts:130` | `hubLoadCfg` (96) | lecture, clé `cfg` ou `cfg_<adresse>` |
| `extension/src/static/hub/graphRenderers.ts:141` | `hubLoadCfg` (96) | écriture |
| `extension/src/static/hub/graphRenderers.ts:256` | `hubLoadCallGraph` (203) | lecture, clé `callgraph` |
| `extension/src/static/hub/graphRenderers.ts:269` | `hubLoadCallGraph` (203) | écriture |
| `extension/src/static/hub/graphRenderers.ts:322` | `hubLoadDiscoveredFunctions` (286), via `resolveCachedAnalysisView` | lecture puis écriture, clé `discovered` |

### 3.2 Appelants de `loadBinaryHeaders` et `loadBinarySymbols` (liste non exhaustive de la couverture)

Ces appelants atteignent le cache seulement lorsque `useCache` n'est pas faux.

- `loadBinaryHeaders` : `extension/src/static/hub/analysisContext.ts:318`,
  `extension/src/static/hub/navigation.ts:118`, `extension/src/static/hub/navigation.ts:131`,
  `extension/src/static/hub/actions.ts:414`.
- `loadBinaryHeaders` avec `useCache: false` (n'atteint pas `readCache` via l'enveloppe) :
  `extension/src/static/hub/loaders.ts:156`.
- `loadBinarySymbols` : `extension/src/static/hub/graphRenderers.ts:250`,
  `extension/src/static/hub/loaders.ts:284`, `extension/src/static/hub/navigation.ts:132`,
  `extension/src/static/hub/actions.ts:415`, `extension/src/static/hub/actions.ts:416`.
- `loadBinarySymbols` avec `useCache: false` : `extension/src/static/hub/loaders.ts:67`.
- `extension/src/static/hub.ts:1111` et `extension/src/static/hub.ts:1139` déclarent des fonctions locales
  de mêmes noms ; leur lien avec `staticCache.ts` n'a pas été établi dans ce périmètre.

## 4. Délais et bornes appliqués aux appels

Délais et bornes explicitement présents dans le code lu :

| Élément | Référence | Portée |
| --- | --- | --- |
| `timeout: 10000` (valeur en millisecondes de l'option de `spawnSync`) | `extension/src/shared/staticCache.ts:71` | Appliqué à chaque appel `cp.spawnSync` de `runCacheStore` (63), donc à toutes les opérations (`get`, `put`, `list`, `prune`, `clear`, `delete-binary`). |
| Sortie en erreur ou statut non nul traitée comme absence de résultat | `extension/src/shared/staticCache.ts:74` | `runCacheStore` retourne `null`. |
| `try/catch` retournant `null` ou `false` | `extension/src/shared/staticCache.ts:77-79`, `extension/src/shared/staticCache.ts:29-31`, `extension/src/shared/staticCache.ts:111-113` | Les exceptions (dont `JSON.parse`) sont absorbées. |
| Plafond de 5000 chaînes (`MAX_CACHED_STRINGS`) | `extension/src/static/hub/loaders.ts:19`, `extension/src/static/hub/loaders.ts:91`, `extension/src/static/hub/loaders.ts:106` | Borne le nombre de chaînes extraites, donc la taille de la donnée passée à `writeCache` pour la clé `strings`. |
| `minLen` borné entre 1 et 64 | `extension/src/static/hub/loaders.ts:77` | Paramètre d'extraction des chaînes. |

Absences constatées dans le périmètre inspecté :

- Aucun délai sur `fs.statSync`, `fs.existsSync`, `fs.mkdirSync`, le hachage, `JSON.parse` et `JSON.stringify`
  dans `staticCache.ts`.
- Aucune option `maxBuffer` ni `killSignal` explicite dans l'appel `spawnSync`
  (`extension/src/shared/staticCache.ts:63-73`).
- Aucune limite de taille explicite sur la donnée sérialisée à la ligne 109 pour les clés autres que `strings`
  dans le code lu.
- Aucun mécanisme d'annulation ni de délai propre aux appelants autour de `readCache` et `writeCache` dans
  `extension/src/static/hub/loaders.ts:41-48` et `extension/src/static/hub/analysisContext.ts:459-465`.
- Aucune limite de fréquence ni de concurrence sur les appels au cache. La déduplication `_symbolsInFlight`
  (`extension/src/static/hub/analysisContext.ts:587-598`) intervient après la lecture de cache de la ligne 582.
- Le comportement effectif en cas d'expiration (état du sous-processus, durée réelle) n'a pas été observé.

## 5. Appels situés dans les tests

Ces références ne sont pas des chemins d'exécution de l'Extension Host.

| Fichier | Références | Nature |
| --- | --- | --- |
| `extension/src/tests/staticCache.test.ts` | `:6` (import réel), `:21-24`, `:30-33`, `:39-42`, `:48-51`, `:57-62` | Appels directs de `getCacheKey`, `getCacheDir`, `getStaticCacheDbPath`, `writeCache`, `readCache`, `pruneCacheEntries`, `listCacheEntries`, `deleteCacheEntriesForBinary`, `clearCacheEntries` sur le module réel. |
| `extension/src/tests/fileManager.test.ts` | `:10-13`, `:16`, `:32`, `:44`, `:53`, `:65` | Remplacement du module par un faux via `proxyquire` ; `staticCache.ts` n'est pas exécuté. |
| `extension/src/tests/loaders.test.ts` | `:66-67`, `:100-101` et occurrences suivantes jusqu'à `:835` | `readCache` et `writeCache` remplacés par des `sinon.stub`. |
| `extension/src/tests/analysisCancellation.test.ts` | `:92-93` | Doublures `sinon.stub`. |
| `extension/src/tests/analysisContextArtifacts.test.ts` | `:32-33`, `:137-150`, `:164` | Doublures `sinon.stub`. |

## 6. Points non établis par cette lecture

- Le fil d'exécution exact et le mécanisme de répartition des messages vers les gestionnaires cités.
- La durée réelle des appels : aucune mesure n'a été faite.
- L'existence d'autres appelants hors `extension/src/` : hors périmètre.
- Le contenu de `getExtensionPath` (`./utils`) et du script `backends/static/cache/cache_index.py`, qui n'ont pas été lus.
