# Baseline du contrôle de types Python (mypy)

Ce document décrit l'état du contrôle de types Python du dépôt tel qu'il
ressort des seuls fichiers suivis, sans exécution de mypy. Il répond
uniquement au critère « Baseline documentée » de l'issue #479.

## Référence

- SHA de base : `ba9d2c2ef2a35277d8749b8272347ec02fa08a76`
  (commit `ba9d2c2`, « Merge pull request #486 from
  PileOuFaces/fix/auth-refresh-single-flight »).
- Méthode : lecture statique des fichiers de configuration et recherche
  textuelle dans l'arbre de travail, propre au moment de la consultation.
- Le rattachement exact de ce document au SHA ci-dessus doit être confirmé
  par le runner de confiance (voir « Limites de validation »).

## Configuration mypy : `extension/backends/pyproject.toml`

### Section `[tool.mypy]`

| Option | Valeur |
| --- | --- |
| `python_version` | `"3.11"` |
| `strict` | `false` |
| `warn_unreachable` | `true` |
| `show_error_codes` | `true` |
| `ignore_missing_imports` | `true` |
| `warn_return_any` | `true` |
| `disallow_untyped_defs` | `true` |
| `no_implicit_optional` | `true` |
| `warn_redundant_casts` | `true` |
| `warn_unused_ignores` | `false` |

Exclusions (`exclude`, expressions régulières mypy) :

- `"static/tests/"`
- `"venv/"`
- `"\\.venv/"`

### Overrides `[[tool.mypy.overrides]]`

Un seul override est défini :

| `module` | Option |
| --- | --- |
| `["backends.static.*"]` | `ignore_errors = true` |

Le commentaire qui le précède justifie ce choix : « lief ships incomplete
stubs — suppress attr/assignment errors in lief-heavy modules ».

Conséquence : toutes les erreurs signalées dans les modules
`backends.static.*` sont masquées, alors même que les options globales
(`disallow_untyped_defs`, `warn_return_any`, etc.) s'y appliquent
nominalement. Les tests sous `static/tests/` sont, eux, exclus de l'analyse.

### Autres fichiers

- `extension/pyproject.toml` ne contient aucune section `[tool.mypy]`
  (seulement ruff, pytest et coverage).
- `extension/backends/requirements-dev.txt` déclare `mypy>=1.0`
  (version non épinglée).
- `.gitignore` ignore `.mypy_cache/`.
- Aucun autre fichier de configuration mypy (`mypy.ini`, `.mypy.ini`,
  `setup.cfg` avec section mypy) n'a été trouvé.

## Hook pre-commit : `.pre-commit-config.yaml`

Hook déclaré :

- Dépôt : `https://github.com/pre-commit/mirrors-mypy`, `rev: v1.15.0`.
- `id: mypy`, `name: mypy (type check Python)`.
- `files: ^backends/static/(?!tests/).*\.py$`
- `args: [--config-file, backends/pyproject.toml]`
- `additional_dependencies` : `lief`, `capstone` (sans version épinglée).

### Comparaison avec l'emplacement réel

pre-commit évalue `files` sur les chemins relatifs à la racine du dépôt et
lance le hook depuis cette racine.

| Élément | Valeur dans le hook | Emplacement réel |
| --- | --- | --- |
| Motif `files` | `^backends/static/…` | `extension/backends/static/…` |
| `--config-file` | `backends/pyproject.toml` | `extension/backends/pyproject.toml` |

Il n'existe aucun répertoire `backends/` à la racine du dépôt. En l'état :

- le motif `files` ne correspond à aucun fichier suivi, donc le hook mypy
  n'est jamais déclenché sur les fichiers Python existants ;
- s'il était déclenché, le chemin `--config-file` désignerait un fichier
  inexistant.

Le motif ne vise en outre que `backends/static/`, c'est-à-dire précisément
le périmètre couvert par `ignore_errors = true`.

Ce document constate l'écart sans corriger la configuration (hors
périmètre de cette sous-tâche).

## mypy dans les workflows GitHub

Recherche insensible à la casse du terme `mypy` dans `.github/` : aucune
occurrence. Workflows suivis examinés sous `.github/workflows/` :

- `ci.yml`
- `codeql.yml`
- `docker-decompilers.yml`
- `gitleaks.yml`
- `large-real-corpus-loadtest.yml`
- `publish.yml`
- `sast.yml`
- `trivy.yml`
- `tripartite-scheduled.yml`
- `vsix.yml`

Conclusion : **mypy n'est exécuté dans aucun workflow CI**. À titre de
comparaison, `ci.yml` exécute en Python, depuis `./extension`,
`python3 -m ruff check .`, `python3 -m ruff format --check .` et les tests
`pytest` sous coverage.

## Inventaire des commentaires `type: ignore`

### Méthode et périmètre

- Expression régulière : `type:\s*ignore` (couvre `# type: ignore` et
  `# type: ignore[code]`, avec ou sans espace après `:`).
- Périmètre : fichiers de l'arbre de travail au SHA de base, hors fichiers
  ignorés par `.gitignore`, répertoire `.github/` inclus. L'arbre de travail
  était propre (aucun fichier non suivi), ce périmètre équivaut donc aux
  fichiers suivis.
- Tous types de fichiers inclus ; seules des occurrences dans des fichiers
  `.py` ont été trouvées, toutes sous forme de commentaires.
- Le présent document, ajouté après le SHA de base, mentionne lui-même la
  chaîne `type: ignore` et n'est pas compté. Pour un recomptage ultérieur,
  restreindre aux fichiers Python, par exemple :
  `git grep -cE 'type:[[:space:]]*ignore' ba9d2c2ef2a35277d8749b8272347ec02fa08a76 -- '*.py'`.

### Comptage par fichier

| Fichier | Nombre | Statut mypy selon la configuration |
| --- | ---: | --- |
| `extension/backends/mcp/ai_provider.py` | 1 | analysé |
| `extension/backends/mcp/server.py` | 1 | analysé |
| `extension/backends/mcp/tool_scanner.py` | 1 | analysé |
| `extension/backends/shared/utils.py` | 1 | analysé |
| `extension/backends/dynamic/engine/unicorn/disasm.py` | 1 | analysé |
| `extension/backends/static/annotations/annotations.py` | 1 | `ignore_errors` |
| `extension/backends/static/cache/cache.py` | 1 | `ignore_errors` |
| `extension/backends/static/decompile/decompile.py` | 3 | `ignore_errors` |
| `extension/backends/static/disasm/call_graph.py` | 5 | `ignore_errors` |
| `extension/backends/static/disasm/discover_functions.py` | 2 | `ignore_errors` |
| `extension/backends/static/search/strings.py` | 2 | `ignore_errors` |
| `extension/backends/static/tests/test_cache.py` | 5 | exclu (`static/tests/`) |
| `extension/backends/static/tests/test_e2e_pipeline.py` | 3 | exclu (`static/tests/`) |
| **Total (13 fichiers)** | **27** | |

Répartition : 5 hors `backends/static/`, 14 dans `backends/static/` hors
tests, 8 dans `backends/static/tests/`.

Avec `warn_unused_ignores = false`, mypy ne signale pas les commentaires
devenus inutiles ; les 22 commentaires situés dans un périmètre ignoré ou
exclu n'ont, en l'état, aucun effet sur le résultat.

## Nombre d'erreurs mypy

**Non mesuré.** mypy n'a pas été exécuté dans le cadre de cette sous-tâche.

Commande proposée pour une mesure ultérieure, à lancer depuis le
répertoire `extension/` avec la configuration existante :

```bash
cd extension
python3 -m mypy --config-file backends/pyproject.toml backends
```

Notes :

- `extension/backends/__init__.py` existe ; lancée depuis `extension/`, la
  commande nomme les modules `backends.…`, ce qui correspond au motif de
  l'override `backends.static.*`.
- Elle suppose mypy déjà disponible dans l'environnement préparé
  (`requirements-dev.txt` déclare `mypy>=1.0`). Aucune installation n'est
  requise ni effectuée par cette mission ; la version utilisée devra être
  consignée avec le résultat, la contrainte n'étant pas épinglée.
- Pour une mesure comparable au hook pre-commit, utiliser la même version
  que `mirrors-mypy` (`v1.15.0`).

## Critères de l'issue #479 restant ouverts

Cette sous-tâche ne traite que la baseline documentée. Restent ouverts :

- **sous-paquets ciblés vérifiés en CI** : aucun workflow n'exécute mypy ;
- **aucun nouvel ignore** : aucun contrôle n'empêche l'ajout de
  commentaires `type: ignore` ou d'overrides `ignore_errors`.

Cette sous-tâche **ne clôture pas** l'issue #479.

## Limites de validation

- Contenu établi par lecture statique, sans exécution de mypy, de
  pre-commit ni de Git par l'auteur du document.
- Le SHA de base provient du mandat et de l'état Git observé au démarrage
  de la session ; sa correspondance exacte doit être vérifiée par le
  runner de confiance, de même que le périmètre du diff et le contrôle
  `doc_static`.
- Le comportement décrit pour le hook pre-commit (non-déclenchement,
  fichier de configuration introuvable) est déduit des chemins ; il n'a
  pas été observé par exécution.
