# Clé et invalidation du cache statique

Ce document décrit l'état actuel, tel que lu dans le code, de la construction de la clé du cache statique et de ses règles d'invalidation. Il est établi par lecture seule au SHA de base `0e96a4f75f8622009cce572262b105e1962b43e4`. Aucun code n'a été exécuté. Il ne contient aucune recommandation.

Périmètre étudié :

- `extension/src/shared/staticCache.ts` (côté TypeScript) ;
- `extension/backends/static/cache/cache_index.py` (pont CLI Python) ;
- `extension/backends/static/cache/cache_store.py` (stockage SQLite) ;
- leurs appelants dans `extension/src/`.

## 1. Composants de la clé

L'identité d'une entrée est la clé primaire SQLite `(namespace, cache_key, variant)` (`extension/backends/static/cache/cache_store.py:30`). La lecture ne filtre que sur ces trois colonnes (`extension/backends/static/cache/cache_store.py:63`).

| Composant | Valeur | Lieu de calcul | Référence |
| --- | --- | --- | --- |
| `cache_key` | 16 premiers caractères hexadécimaux du SHA-256 de la chaîne `<chemin résolu>:<mtimeMs>:<size>` | TypeScript, `getCacheKey` | `extension/src/shared/staticCache.ts:23-28` |
| Chemin | `path.resolve(absPath)` | TypeScript | `extension/src/shared/staticCache.ts:27` |
| Date de modification | `stat.mtimeMs` (nombre, interpolé tel quel dans la chaîne) | TypeScript | `extension/src/shared/staticCache.ts:27` |
| Taille | `stat.size` | TypeScript | `extension/src/shared/staticCache.ts:27` |
| `namespace` | paramètre `type` de `readCache`/`writeCache`, transmis par `--namespace` | TypeScript, puis stocké par Python | `extension/src/shared/staticCache.ts:93`, `extension/src/shared/staticCache.ts:104` |
| `variant` | résultat de `cacheVariant(type, options)` | TypeScript | `extension/src/shared/staticCache.ts:82-87` |

Si `fs.statSync` échoue, `getCacheKey` renvoie `null` (`extension/src/shared/staticCache.ts:29-31`). `readCache` renvoie alors `null` (`extension/src/shared/staticCache.ts:91`) et `writeCache` renvoie `false` (`extension/src/shared/staticCache.ts:100`).

### Valeurs du namespace

Le namespace est la chaîne passée en argument `type` ; la fonction de cache ne la restreint pas. Les appelants observés dans `extension/src/` passent :

- `symbols` (`extension/src/static/hub/loaders.ts:64`) ;
- `strings` (`extension/src/static/hub/loaders.ts:95`) ;
- `info` (`extension/src/static/hub/loaders.ts:146`) ;
- `sections` (`extension/src/static/hub/loaders.ts:199`) ;
- `discovered` (`extension/src/static/hub/graphRenderers.ts:325`) ;
- d'autres valeurs fournies par `cacheKey` dans `extension/src/static/hub/analysisContext.ts:459` et `extension/src/static/hub/analysisContext.ts:465`, non énumérées ici.

### Valeurs du variant

- Pour tout `type` autre que `strings`, le variant est la chaîne vide (`extension/src/shared/staticCache.ts:83`).
- Pour `strings`, le variant est `<minLen|4>_<encodage nettoyé>_<section nettoyée|all>_v2` (`extension/src/shared/staticCache.ts:84-86`). Le suffixe `v2` est une constante littérale du code. Elle n'est pas dérivée d'une version de l'analyseur.
- Le défaut de `minLen` est 4, celui de l'encodage `utf-8` (`extension/src/shared/staticCache.ts:84-86`). Un `minLen` à 0 donne aussi 4, à cause de l'opérateur `||`.

### Version de l'analyseur

Aucune version de l'analyseur n'entre dans la clé dans le périmètre étudié. Les composants de `cache_key`, `namespace` et `variant` listés ci-dessus sont les seuls. Aucun des trois fichiers ne lit ni ne transmet une version, un hash de code ou une version d'outil. Le seul marqueur de version est le littéral `_v2` du variant des `strings` (`extension/src/shared/staticCache.ts:86`).

## 2. Métadonnées stockées (hors clé)

La commande `put` enregistre ces colonnes en plus de la clé (`extension/backends/static/cache/cache_store.py:19-31`) :

| Colonne | Origine | Lieu de calcul | Référence |
| --- | --- | --- | --- |
| `binary_path` | `path.resolve(absPath)` côté TypeScript, puis `Path(binary_path).resolve()` côté Python | TypeScript puis Python | `extension/src/shared/staticCache.ts:106`, `extension/backends/static/cache/cache_store.py:112` |
| `binary_mtime_ms` | `stat.mtimeMs`, lu dans un second `fs.statSync` | TypeScript | `extension/src/shared/staticCache.ts:102`, `extension/src/shared/staticCache.ts:107` |
| `binary_size` | `stat.size`, lu dans le même second `fs.statSync` | TypeScript | `extension/src/shared/staticCache.ts:102`, `extension/src/shared/staticCache.ts:108` |
| `payload_json` | `json.dumps(payload, ensure_ascii=False, separators=(",", ":"))` | Python | `extension/backends/static/cache/cache_store.py:93` |
| `payload_bytes` | longueur UTF-8 de `payload_json` | Python | `extension/backends/static/cache/cache_store.py:94` |
| `created_at_ms` | `time.time() * 1000` à l'écriture | Python | `extension/backends/static/cache/cache_store.py:97` |
| `accessed_at_ms` | `time.time() * 1000` à l'écriture et à chaque lecture réussie | Python | `extension/backends/static/cache/cache_store.py:70`, `extension/backends/static/cache/cache_store.py:97` |

Le `stat` de `writeCache` est lu deux fois : une fois dans `getCacheKey` (`extension/src/shared/staticCache.ts:99`) et une fois à la ligne 102. Le code ne garantit pas que les deux lectures renvoient les mêmes valeurs si le fichier change entre elles.

Aucune de ces métadonnées n'est relue ni comparée lors d'un `get` (`extension/backends/static/cache/cache_store.py:62-65`). Elles servent au listage, à la purge et à la suppression par binaire (section 4).

## 3. Péremption et remplacement

### Conditions de péremption à la lecture

`get_payload` ne teste aucune péremption. Il renvoie le `payload_json` de la ligne qui correspond à `(namespace, cache_key, variant)` (`extension/backends/static/cache/cache_store.py:62-65`). La seule validité est donc l'égalité de la clé, calculée à partir du chemin, de `mtimeMs` et de la taille.

- Si le chemin, `mtimeMs` ou la taille changent, `cache_key` change. La lecture ne trouve alors pas la ligne précédente et renvoie un échec de cache (`extension/src/shared/staticCache.ts:95`). L'ancienne ligne n'est pas supprimée par cette lecture.
- Si la base n'existe pas, `get_payload` renvoie `None` (`extension/backends/static/cache/cache_store.py:59-60`).
- Si `payload_json` est illisible, la ligne est supprimée et `None` est renvoyé (`extension/backends/static/cache/cache_store.py:72-79`).
- Côté TypeScript, une erreur de lancement, un code retour non nul ou une sortie non analysable donnent `null` (`extension/src/shared/staticCache.ts:74-79`), donc un échec de cache. Le délai maximal d'un appel est de 10 000 ms (`extension/src/shared/staticCache.ts:71`).
- Un appelant peut ajouter son propre test d'usage : `isCacheUsable` dans `extension/src/static/hub/loaders.ts:42`. Il ne fait pas partie de la clé.
- Un appelant peut contourner la lecture avec `useCache` à faux (`extension/src/static/hub/loaders.ts:40`). Il écrit tout de même le résultat (`extension/src/static/hub/loaders.ts:48`).

### Remplacement à l'écriture

`put_payload` fait un `INSERT ... ON CONFLICT(namespace, cache_key, variant) DO UPDATE` (`extension/backends/static/cache/cache_store.py:99-107`). Une écriture avec la même clé remplace `binary_path`, `binary_mtime_ms`, `binary_size`, `payload_json`, `payload_bytes` et `accessed_at_ms`. `created_at_ms` n'est pas dans la liste du `DO UPDATE` : il garde sa valeur initiale.

Une écriture avec une nouvelle valeur de `cache_key` crée une nouvelle ligne et ne remplace pas les lignes de la même `binary_path` qui ont une ancienne clé.

### Éviction par limites

Après chaque écriture, `_enforce_limits` supprime les lignes dont `accessed_at_ms` est le plus ancien, tant que le nombre de lignes dépasse `MAX_ENTRIES` (4 096) ou que la somme de `payload_bytes` dépasse `MAX_TOTAL_BYTES` (256 Mio) (`extension/backends/static/cache/cache_store.py:14-16`, `extension/backends/static/cache/cache_store.py:125-142`). Un payload de plus de `MAX_PAYLOAD_BYTES` (16 Mio) lève `ValueError` (`extension/backends/static/cache/cache_store.py:95-96`). `writeCache` renvoie alors `false`, car `runCacheStore` renvoie `null` quand le code retour n'est pas 0 (`extension/src/shared/staticCache.ts:74`, `extension/src/shared/staticCache.ts:110`). Ce dernier point est une déduction du flux de contrôle ; il n'a pas été exécuté.

## 4. Invalidation explicite

| Opération | Condition de suppression | Référence |
| --- | --- | --- |
| `prune` | Supprime toutes les lignes ayant les mêmes `cache_key` et `binary_path` qu'un groupe dont le statut n'est pas `ok` (`missing` ou `stale`) | `extension/backends/static/cache/cache_store.py:186-198` |
| `delete-binary` | Supprime toutes les lignes dont `binary_path` est égal au chemin résolu fourni | `extension/backends/static/cache/cache_store.py:201-209` |
| `clear` | Supprime toutes les lignes | `extension/backends/static/cache/cache_store.py:212-218` |

Le statut d'un groupe est calculé par `_list_entry` (`extension/backends/static/cache/cache_store.py:160-183`) :

- `missing` : `binary_path` est vide ou n'est pas un fichier ;
- `ok` : le fichier existe, `abs(st_mtime_ns / 1_000_000 - binary_mtime_ms) <= 0.001` et `st_size == binary_size` ;
- `stale` : le fichier existe mais la date ou la taille diffèrent.

Ce statut compare les métadonnées stockées (section 2) au fichier actuel. Il n'est pas évalué par `get_payload`.

Les appelants de ces opérations dans `extension/src/` sont :

- `purgeStaleCache` appelle `pruneCacheEntries` (`extension/src/shared/fileManager.ts:282`) ;
- `cleanupAll` appelle `pruneCacheEntries` si `purgeStale` est vrai, sinon `clearCacheEntries` (`extension/src/shared/fileManager.ts:306-310`) ;
- `cleanupCacheEntriesForBinary` appelle `deleteCacheEntriesForBinary` (`extension/src/shared/fileManager.ts:173-177`), lui-même appelé à `extension/src/shared/fileManager.ts:321`.

## 5. Cas sans invalidation

- **Contenu modifié avec `mtimeMs` et taille identiques.** `cache_key` est un hachage du chemin, de `mtimeMs` et de la taille uniquement (`extension/src/shared/staticCache.ts:26-28`). Le contenu du fichier n'est jamais lu ni haché dans le périmètre étudié. Si ces trois valeurs sont inchangées, la clé est identique. `get_payload` renvoie alors l'ancien payload (`extension/backends/static/cache/cache_store.py:62-65`). `_list_entry` renvoie `ok` dans ce cas, car il compare les mêmes métadonnées (`extension/backends/static/cache/cache_store.py:167-172`), donc `prune` ne supprime pas la ligne non plus.
- **Changement de l'analyseur ou de ses outils.** Aucune version n'est dans la clé (section 1). Une entrée existante est donc servie tant que la clé est identique, quelle que soit la version de l'analyseur qui l'a produite.
- **Lecture d'une ligne ancienne.** Une ligne dont la clé ne correspond plus à l'état du fichier n'est pas supprimée par une lecture. Elle reste jusqu'à `prune`, `delete-binary`, `clear` ou éviction par limites (section 3).

## 6. Fonctions de lecture et d'écriture

| Fonction | Fichier:ligne | Rôle |
| --- | --- | --- |
| `getCacheKey` | `extension/src/shared/staticCache.ts:23` | Calcule `cache_key` (SHA-256 tronqué de chemin, `mtimeMs`, taille) ; `null` si `stat` échoue |
| `cacheVariant` | `extension/src/shared/staticCache.ts:82` | Calcule le variant (non vide seulement pour `strings`) |
| `runCacheStore` | `extension/src/shared/staticCache.ts:57` | Lance `cache_index.py` via `spawnSync` (délai de 10 s), renvoie le JSON de sortie ou `null` |
| `readCache` | `extension/src/shared/staticCache.ts:89` | Lecture : calcule la clé puis envoie `get` ; renvoie le payload si `found` est vrai |
| `writeCache` | `extension/src/shared/staticCache.ts:98` | Écriture : calcule la clé, relit `stat`, envoie `put` avec le payload sur l'entrée standard |
| `listCacheEntries` | `extension/src/shared/staticCache.ts:116` | Envoie `list` |
| `pruneCacheEntries` | `extension/src/shared/staticCache.ts:121` | Envoie `prune` |
| `clearCacheEntries` | `extension/src/shared/staticCache.ts:125` | Envoie `clear` |
| `deleteCacheEntriesForBinary` | `extension/src/shared/staticCache.ts:129` | Envoie `delete-binary` avec le chemin résolu |
| `main` | `extension/backends/static/cache/cache_index.py:25` | Analyse les arguments et répartit vers les fonctions du store |
| `get_payload` | `extension/backends/static/cache/cache_store.py:53` | Lit par `(namespace, cache_key, variant)`, met à jour `accessed_at_ms`, supprime une ligne illisible |
| `put_payload` | `extension/backends/static/cache/cache_store.py:82` | Sérialise, borne la taille, insère ou remplace, applique les limites |
| `_enforce_limits` | `extension/backends/static/cache/cache_store.py:125` | Éviction par `accessed_at_ms` croissant selon les limites de nombre et de taille |
| `list_entries` | `extension/backends/static/cache/cache_store.py:145` | Regroupe par clé et métadonnées du binaire |
| `_list_entry` | `extension/backends/static/cache/cache_store.py:160` | Calcule le statut `ok`, `stale` ou `missing` |
| `prune_entries` | `extension/backends/static/cache/cache_store.py:186` | Supprime les groupes dont le statut n'est pas `ok` |
| `delete_binary` | `extension/backends/static/cache/cache_store.py:201` | Supprime par `binary_path` |
| `clear_entries` | `extension/backends/static/cache/cache_store.py:212` | Supprime toutes les lignes |
| `resolveCachedBinaryView` | `extension/src/static/hub/loaders.ts:30` | Appelant : `readCache` (ligne 41), puis `writeCache` (ligne 48) |
| `readAnalysisCacheEntry` | `extension/src/static/hub/analysisContext.ts:456` | Appelant : `readCache` (ligne 459) pour un fichier non répertoire |
| `writeAnalysisCacheEntry` | `extension/src/static/hub/analysisContext.ts:462` | Appelant : `writeCache` (ligne 465) |
| `listCacheEntries` (fileManager) | `extension/src/shared/fileManager.ts:251` | Appelant : liste le cache et trie par `mtime` décroissant |
