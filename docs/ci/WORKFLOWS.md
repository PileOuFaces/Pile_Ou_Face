# Workflows GitHub Actions

Ce document décrit les workflows de `.github/workflows/` pour aider les
contributeurs à comprendre leurs déclencheurs, et en particulier ceux d'une
PR purement documentaire vers `develops`.

## Référence documentaire

- Commit de base attesté par le runner : `74c2ff4011aa7ec88f6685dddc01d532da01bf31`.
- Source unique : les fichiers de `.github/workflows/` à ce commit. Rien n'a
  été exécuté, aucune configuration GitHub (règles de protection, checks
  requis, branche par défaut, secrets, fork) n'a été consultée.
- Si les workflows changent après ce commit, ce document peut être obsolète.
- Convention : « absent » signifie que la clé n'est pas déclarée dans le
  fichier. Ce n'est pas la même chose qu'un filtre vide.

## Inventaire (10 fichiers)

### ci.yml

- Nom affiché : `CI`.
- Événements : `push`, `pull_request`.
- `push` : `branches-ignore: [main, develops]` ; `branches` absent ; `tags`
  absent ; `paths` :
  - `extension/**`
  - `.github/workflows/ci.yml`
  - `.github/workflows/publish.yml`
  - `.github/workflows/tripartite-scheduled.yml`
- `pull_request` : `branches: [main, develops]` ; `types` absent (types par
  défaut de GitHub, non déclarés dans le fichier) ; `paths` :
  - `extension/**`
  - `tooling/loadtest/**`
  - `.github/workflows/ci.yml`
  - `.github/workflows/trivy.yml`
  - `.github/workflows/large-real-corpus-loadtest.yml`
  - `.github/workflows/publish.yml`
  - `.github/workflows/tripartite-scheduled.yml`
  - `security/**`
  - `tooling/security_baseline.py`
  - `tooling/tests/test_security_baseline.py`
- `paths-ignore`, `tags-ignore`, `schedule`, `workflow_dispatch` : absents.
- Concurrence : groupe `ci-${{ github.workflow }}-${{ github.ref }}`,
  `cancel-in-progress: true`.
- Jobs principaux :
  - `security-baseline` (Security baseline policy)
  - `large-real-corpus-changes` (filtre `dorny/paths-filter`)
  - `large-real-corpus` (appelle `large-real-corpus-loadtest.yml`)
  - `lint`
  - `full-test` (matrice ubuntu-latest / macos-latest × Node 20.x / 22.x,
    sauf macOS + 20.x)
  - `deployment-profile-artifacts` (matrice de 4 profils)
  - `auth-licensing-windows`
  - `dynamic-unicorn`
  - `real-corpus-arm64`
  - `e2e-runtime-audit`
  - `security-scan`
  - `auth-licensing-e2e`
  - `backend-loadtest`
  - `ci-success` (`if: always()`, agrège les résultats)
- Conditions de jobs :
  - `large-real-corpus` : `github.base_ref == 'develops'` et sortie
    `relevant == 'true'`. Le filtre `relevant` porte sur
    `extension/backends/static/**`, `extension/backends/requirements.txt`,
    `extension/backends/requirements-ci.txt`, `tooling/loadtest/**`,
    `.github/workflows/ci.yml` et
    `.github/workflows/large-real-corpus-loadtest.yml`.
  - Dans `auth-licensing-windows`, `dynamic-unicorn`, `real-corpus-arm64` et
    `security-scan`, un filtre `dorny/paths-filter` conditionne les étapes
    (pas le job) : le job démarre, ses étapes sont ignorées si le filtre est
    faux.
  - `auth-licensing-e2e` : échoue si le secret `CROSS_REPO_READONLY_PAT` est
    vide (selon le script du fichier).
  - `ci-success` considère `skipped` comme un échec pour la plupart des jobs
    (fonction `fail_if_bad`), sauf `large-real-corpus` (seuls `failure` et
    `cancelled` échouent).

### codeql.yml

- Nom affiché : `CodeQL`.
- Événements : `pull_request`, `push`, `schedule`, `workflow_dispatch`.
- `pull_request` : `branches: [main, develops]` ; `paths`/`paths-ignore`
  absents.
- `push` : `branches: [main, develops]` ; `paths`/`paths-ignore`/`tags`
  absents.
- `schedule` : `cron: "23 4 * * 1"`.
- Concurrence : `codeql-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`,
  `cancel-in-progress: true`.
- Jobs : `analyze` (nom `Analyze (${{ matrix.language }})`, matrice
  `javascript-typescript` et `python`). Pas de `if:` au niveau du job.

### docker-decompilers.yml

- Nom affiché : `Docker — Build Decompilers`.
- Événements : `push`, `pull_request`, `workflow_dispatch`.
- `push` : `branches: [develops]` ; `paths` :
  - `docker/decompilers/**`
  - `extension/backends/static/decompile/**`
  - `.github/workflows/docker-decompilers.yml`
- `pull_request` : `branches: [develops]` ; mêmes `paths`.
- `workflow_dispatch` : entrée `decompiler` (choice : vide, `ghidra`,
  `retdec`, `angr`).
- `paths-ignore`, `tags`, `schedule` : absents.
- Concurrence : `docker-decompilers-${{ github.ref }}`,
  `cancel-in-progress` vrai seulement pour `pull_request`.
- Jobs principaux :
  - `detect-changes` (filtre par décompilateur, génère la matrice)
  - `build` (`if: any_changed == 'true' && github.ref != 'refs/heads/main'`)
  - `smoke-arm64` (non lancé pour `pull_request` selon sa condition)
  - `docker-build-success` (`if: always()`)

### gitleaks.yml

- Nom affiché : `Gitleaks`.
- Événements : `pull_request`, `push`, `schedule`, `workflow_dispatch`.
- `pull_request` : `branches: [main, develops]` ; `paths`/`paths-ignore`
  absents.
- `push` : `branches: [main, develops]` ; `paths`/`paths-ignore`/`tags`
  absents.
- `schedule` : `cron: "17 4 * * 3"`.
- Concurrence : `gitleaks-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`,
  `cancel-in-progress: true`.
- Jobs : `scan` (nom `Gitleaks`) : valide les exceptions
  (`python3 -m tooling.security_baseline`), scan des commits de la PR
  (`BASE_SHA..HEAD`) ou de l'historique complet hors PR, upload SARIF (pour
  une PR, seulement si le dépôt de la tête est `github.repository`) et
  archivage.

### large-real-corpus-loadtest.yml

- Nom affiché : `Large Real Corpus Loadtest`.
- Événements : `workflow_call`, `workflow_dispatch`, `schedule`.
- `schedule` : `cron: '23 3 * * 1'`.
- `push`, `pull_request`, `branches`, `tags`, `paths`, `paths-ignore` :
  absents. Pas de déclenchement direct par PR ; il est appelé par `ci.yml`
  (job `large-real-corpus`).
- Jobs : `large-real-corpus` (nom `Large corpus (${{ matrix.arch }})`,
  matrice x86_64, arm64, mips32, ppc32, riscv64 ; `ubuntu-24.04`).

### publish.yml

- Nom affiché : `Publish`.
- Événements : `push`, `workflow_dispatch`.
- `push` : `tags: ['v*.*.*']` ; `branches` et `paths` absents.
- `workflow_dispatch` : entrée `release_action` (choice `verify` /
  `publish`, défaut `verify`, requise).
- `schedule`, `pull_request`, `paths-ignore`, `tags-ignore` : absents.
- Jobs principaux :
  - `openvsx` (Open VSX : vérification de jeton, empaquetage, SBOM,
    attestation, publication selon l'événement et `release_action`)
  - `publish-marketplace` (`needs: openvsx` ;
    `if: github.event_name == 'workflow_dispatch' && inputs.release_action == 'publish'`)

### sast.yml

- Nom affiché : `Semgrep and Bandit`.
- Événements : `pull_request`, `push`, `schedule`, `workflow_dispatch`.
- `pull_request` : `branches: [main, develops]` ; `paths` :
  - `extension/**`
  - `tooling/**`
  - `security/**`
  - `.bandit.yml`
  - `.github/workflows/sast.yml`
- `push` : `branches: [main, develops]` ; mêmes `paths` ; `tags` absent.
- `schedule` : `cron: "41 4 * * 2"`.
- `paths-ignore` : absent.
- Concurrence : `sast-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`,
  `cancel-in-progress: true`.
- Jobs : `semgrep` (Semgrep), `bandit` (Bandit). Les étapes de scan
  dépendent de l'événement (`pull_request` ou non). Pas de `if:` au niveau
  des jobs.

### trivy.yml

- Nom affiché : `Trivy container security`.
- Événements : `pull_request`, `push`, `schedule`, `workflow_dispatch`.
- `pull_request` : `branches: [main, develops]` ; `paths` :
  - `docker/**`
  - `extension/backends/static/decompile/**`
  - `.github/workflows/trivy.yml`
- `push` : `branches: [main, develops]` ; mêmes `paths` ; `tags` absent.
- `schedule` : `cron: "37 4 * * 4"`.
- `paths-ignore` : absent.
- Concurrence : `trivy-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`,
  `cancel-in-progress: true`.
- Jobs : `scan` (Trivy config and filesystem).

### tripartite-scheduled.yml

- Nom affiché : `Scheduled Tripartite E2E`.
- Événements : `schedule`, `workflow_dispatch`.
- `schedule` : `cron: '17 3 * * *'`. Le commentaire du fichier indique que
  les schedules s'exécutent depuis la branche par défaut (`main`) tout en
  récupérant `develops`.
- `push`, `pull_request`, `branches`, `tags`, `paths`, `paths-ignore` :
  absents.
- Concurrence : `scheduled-tripartite-e2e`, `cancel-in-progress: true`.
- Jobs : `tripartite-e2e` (nom `Host develops + Auth develops + Plugins develops`).
  Échoue si `CROSS_REPO_READONLY_PAT` est vide.

### vsix.yml

- Nom affiché : `VSIX Artifact`.
- Événements : `push`.
- `push` : `branches: [main]` ; `paths` :
  - `extension/**`
  - `.github/workflows/vsix.yml`
- `tags`, `paths-ignore`, `pull_request`, `schedule`,
  `workflow_dispatch` : absents.
- Jobs : `package` (Package VSIX).

## Tableau récapitulatif des déclencheurs

| Fichier | pull_request | push | schedule | workflow_dispatch | autres |
|---|---|---|---|---|---|
| `ci.yml` | `main`, `develops` + paths | toutes branches sauf `main`/`develops` + paths | non | non | |
| `codeql.yml` | `main`, `develops` | `main`, `develops` | `23 4 * * 1` | oui | |
| `docker-decompilers.yml` | `develops` + paths | `develops` + paths | non | oui | |
| `gitleaks.yml` | `main`, `develops` | `main`, `develops` | `17 4 * * 3` | oui | |
| `large-real-corpus-loadtest.yml` | non | non | `23 3 * * 1` | oui | `workflow_call` |
| `publish.yml` | non | tags `v*.*.*` | non | oui | |
| `sast.yml` | `main`, `develops` + paths | `main`, `develops` + paths | `41 4 * * 2` | oui | |
| `trivy.yml` | `main`, `develops` + paths | `main`, `develops` + paths | `37 4 * * 4` | oui | |
| `tripartite-scheduled.yml` | non | non | `17 3 * * *` | oui | |
| `vsix.yml` | non | `main` + paths | non | non | |

## PR documentaire vers `develops` (déduction)

Cette section est une **déduction** tirée des filtres déclarés. Aucun run
réel n'a été observé et rien n'est garanti sur l'exécution effective.

### Hypothèse

PR dont la base est `develops` et dont les fichiers modifiés se limitent à
des chemins documentaires, par exemple `docs/**` (dont `docs/ci/WORKFLOWS.md`)
ou un `README.md` à la racine, sans toucher aux chemins listés dans les
`paths` ci-dessus.

### Workflows susceptibles de se déclencher

| Workflow | Déclenché ? | Justification (filtres déclarés) |
|---|---|---|
| `codeql.yml` | Oui (déduit) | `pull_request` avec `branches: [main, develops]` et aucun `paths`/`paths-ignore`. |
| `gitleaks.yml` | Oui (déduit) | Idem : `branches: [main, develops]`, aucun filtre de chemins. |
| `ci.yml` | Non (déduit) | `paths` de `pull_request` limités à `extension/**`, `tooling/loadtest/**`, certains workflows, `security/**` et deux fichiers `tooling/` ; aucun ne couvre `docs/**`. |
| `sast.yml` | Non (déduit) | `paths` : `extension/**`, `tooling/**`, `security/**`, `.bandit.yml`, `sast.yml`. |
| `trivy.yml` | Non (déduit) | `paths` : `docker/**`, `extension/backends/static/decompile/**`, `trivy.yml`. |
| `docker-decompilers.yml` | Non (déduit) | `paths` : `docker/decompilers/**`, `extension/backends/static/decompile/**`, son propre fichier. |
| `vsix.yml` | Non | Pas d'événement `pull_request` ; `push` sur `main` seulement. |
| `publish.yml` | Non | Pas d'événement `pull_request` ; tags `v*.*.*` ou dispatch manuel. |
| `tripartite-scheduled.yml` | Non | Uniquement `schedule` et `workflow_dispatch`. |
| `large-real-corpus-loadtest.yml` | Non directement | `schedule`, `workflow_dispatch`, `workflow_call` ; appelé par `ci.yml`, donc pas lancé si `ci.yml` ne l'est pas. |

### Déclenchement du workflow et exécution des jobs

- Pour `codeql.yml` et `gitleaks.yml`, les jobs (`analyze`, `scan`) n'ont pas
  de `if:` au niveau du job : si le workflow est déclenché, leur exécution
  est attendue, sous réserve de la disponibilité des runners, des
  permissions et des étapes elles-mêmes. Une exécution réussie n'est pas
  garantie par cette lecture.
- Dans `gitleaks.yml`, l'upload SARIF pour une PR est conditionné au fait que
  `github.event.pull_request.head.repo.full_name == github.repository`.
  Pour une PR venant d'un fork, cette étape serait ignorée (selon la
  condition déclarée).
- Les jobs conditionnels de `ci.yml` (filtres `dorny/paths-filter`,
  `large-real-corpus`) ne sont pas évalués pour une PR purement
  documentaire, car `ci.yml` n'est pas déclenché (déduit).

### Variations selon les chemins modifiés

- Fichier sous `extension/**` (même documentaire, par ex.
  `extension/README.md`) : déclenche `ci.yml` et `sast.yml`. Dans `ci.yml`,
  les filtres internes affinent ensuite les étapes. Exemples : la
  documentation sous `extension/backends/static/**` rend `relevant` vrai pour
  `real-corpus-arm64` et `large-real-corpus` ; sous
  `extension/backends/dynamic/**`, c'est `dynamic-unicorn`.
- Fichier sous `tooling/**` : déclenche `sast.yml`. `ci.yml` n'est déclenché
  que pour `tooling/loadtest/**`, `tooling/security_baseline.py` et
  `tooling/tests/test_security_baseline.py`.
- Fichier sous `security/**` : déclenche `ci.yml` et `sast.yml`.
- `.bandit.yml` : déclenche `sast.yml`.
- Fichier sous `docker/**` : déclenche `trivy.yml` ; sous
  `docker/decompilers/**`, aussi `docker-decompilers.yml`.
- `extension/backends/static/decompile/**` : déclenche `ci.yml`,
  `sast.yml`, `trivy.yml` et `docker-decompilers.yml`.
- Modification d'un des fichiers de `.github/workflows/` cités dans les
  `paths` : déclenche les workflows concernés (voir chaque inventaire).
- `docs/ci/binary-scan-action.yml` n'est pas dans `.github/workflows/` : il
  n'est pas un workflow de ce dépôt et n'apparaît dans aucun filtre de
  chemins déclaré.

### Après fusion et incertitudes

- Un `push` sur `develops` (fusion de la PR) déclenche, selon les filtres,
  `codeql.yml` et `gitleaks.yml` (sans filtre de chemins). Les autres
  workflows à `push` sur `develops` suivent leurs `paths`.
- Un `push` sur la branche de la PR elle-même ne déclenche pas `codeql.yml`
  ni `gitleaks.yml` (limités à `main` et `develops`) ; `ci.yml` ne se
  déclencherait que pour les `paths` listés.
- Non déterminable par ces fichiers : checks requis par les règles de
  protection de branche, validation manuelle des runs sur PR de fork,
  désactivation de workflows côté GitHub, quotas, secrets réellement
  configurés, branche par défaut effective (seul un commentaire de
  `tripartite-scheduled.yml` la mentionne), et résultat réel de tout job.
- `ci-success` (« required check pour les PRs » selon un commentaire du
  fichier) n'est pas déclenché pour une PR documentaire ; savoir si cela
  bloque la PR dépend de réglages GitHub non visibles ici.
