# Releasing — déploiement de l'extension

Ce document décrit **comment publier une version de l'extension** (Marketplace VS Code + Open VSX).

## Principe en une phrase

Rien ne se publie depuis `develops`. **La publication exige deux actions distinctes : pousser un tag `vX.Y.Z` sur un commit présent sur `main` (paquet + attestation, sans publication), puis lancer manuellement `Publish` sur ce tag avec `release_action = publish`.**

Flux : `feature/*` → PR → `develops` → PR de promotion → `main` → tag `vX.Y.Z` (VSIX attesté) → *Run workflow* `publish` → Open VSX puis Marketplace.

## Les workflows

| Workflow | Déclencheur | Rôle |
|----------|-------------|------|
| `ci.yml` | Toute PR vers `develops`/`main` ; push sur une autre branche seulement si `extension/**` ou un workflow CI/publication change (jamais sur `develops`/`main`) | Lint, tests, matrice OS, E2E, corpus. Produit `CI Success`, le check requis avant merge. Après une fusion, seuls CodeQL, Gitleaks, Semgrep/Bandit et Trivy tournent sur `develops`/`main`. |
| `docker-decompilers.yml` | push `develops` / PR vers `develops` (chemins `docker/decompilers/**`, `extension/backends/static/decompile/**`) | Build + **push** des images décompilateur sur ghcr. Sur `develops` : tags `:<version>` (immuable, depuis `image_versions.json`) + `develops` + `sha-*`. Sur PR : build de validation, **sans** push. |
| `vsix.yml` | push `main` | Package un `.vsix` en artefact (téléchargeable, **pas** publié). |
| `publish.yml` | push d'un tag `v*.*.*` ; *Run workflow* manuel (`release_action` = `verify` ou `publish`) | **Push du tag** : vérifie que le tag est un ancêtre de `main`, package le VSIX (profil SaaS officiel), génère le SBOM, **atteste** VSIX et SBOM, conserve le VSIX en artefact — **aucune publication**. **`release_action = publish`** (lancé sur le tag) : mêmes étapes, puis publication Open VSX, puis Marketplace à partir du même VSIX vérifié. **`verify`** : vérifie le token Open VSX sans publier. Ne crée pas de GitHub Release. |

## Prérequis (une seule fois)

Secrets du dépôt (Settings → Secrets → Actions) :

- `VSCE_PAT` — Personal Access Token Azure DevOps pour le Marketplace VS Code.
- `OPEN_VSX_TOKEN` — token [open-vsx.org](https://open-vsx.org).

Vérifier le token Open VSX sans publier : Actions → **Publish** → *Run workflow* → `release_action = verify`.

## Procédure de release

### 1. Préparer sur `develops` (via PRs)

- Bumper `extension/package.json` (`version`) **et** `extension/package-lock.json` (garder les deux alignés).
- Ajouter l'entrée `CHANGELOG.md` de la version (Added / Changed / Fixed).
- Si un **Dockerfile ou adaptateur de décompilateur a changé**, bumper l'entrée correspondante dans `extension/backends/static/decompile/image_versions.json`.

### 2. Images décompilateur (opt-in — pas de dépendance de release)

La décompilation Docker est **opt-in** : l'extension ne pull **aucune image par défaut**. Quand une PR touchant `docker/decompilers/**` ou `extension/backends/static/decompile/**` est mergée sur `develops`, `docker-decompilers.yml` build + pousse les tags `:<version>` (catalogue `extension/backends/static/decompile/image_versions.json`) sur ghcr — pour l'option « utiliser le nôtre » des réglages.

Ce n'est **pas un prérequis** de la release de l'extension : comme il n'y a pas de défaut, rien ne casse si un tag manque — la décompilation Docker est simplement indisponible tant que l'utilisateur n'a pas configuré de décompilateur.

### 3. Promouvoir `develops` → `main`

Ouvrir une PR `develops` → `main`, la merger. En cas de conflit de version (`package.json`/`package-lock.json`), **garder la version de `develops`** (la nouvelle).

### 4. Tagger sur `main`

```bash
git checkout main && git pull origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

Le push du tag déclenche `publish.yml` en mode **artefact seulement** : VSIX packagé, SBOM, attestation. Rien n'est publié.

### 5. Publier (décision explicite)

Actions → **Publish** → *Run workflow* sur le **tag** `vX.Y.Z` → `release_action = publish`. Ce lancement reconstruit et atteste son propre VSIX depuis le tag (il ne réutilise pas l'artefact du push du tag) : le job `openvsx` le publie, puis `publish-marketplace` publie ce même VSIX.

### 6. Vérifier

- Les runs `Publish` du tag (artefact) et du lancement manuel (`publish`) sont verts.
- Le VSIX publié correspond à son commit : `gh attestation verify <fichier.vsix> --repo PileOuFaces/Pile_Ou_Face`.
- Une GitHub Release n'est **pas** créée automatiquement : la créer à la main sur le tag si elle est souhaitée.
- Marketplace : la nouvelle version apparaît sur la page de l'extension.
- Open VSX : `https://open-vsx.org/extension/PileOuFaces/stack-visualizer`.

## Pré-release (beta / rc)

Tagger avec un suffixe `-pre`, `-beta` ou `-rc` (ex. `v0.3.0-rc1`) : lors du lancement `publish`, les deux jobs publient alors en **`--pre-release`**. Utile pour tester une build sans la pousser au canal stable.

## Dépannage

| Symptôme | Cause / correctif |
|----------|-------------------|
| `Tag is not on main — publish aborted` | Le commit taggé n'est pas sur `main`. Merger la promotion (étape 3) avant de tagger. |
| `vsce` : version déjà publiée | La `version` de `package.json` existe déjà sur le Marketplace. Bumper + retagger. |
| Job publish échoue sur le PAT | Secret `VSCE_PAT` / `OPEN_VSX_TOKEN` manquant ou expiré. Pas de dommage, juste pas de publication. |
| Utilisateur : décompilation Docker indisponible | Normal si aucun décompilateur n'est configuré (Docker opt-in). Sinon l'image choisie (« utiliser le nôtre ») n'a pas encore été publiée sur ghcr — vérifier le run `docker-decompilers.yml`. |

## Autres composants (déploiement séparé)

- **Serveur d'auth / SaaS collaboratif** : déploiement Kubernetes, voir chaque dépôt (`Pile_ou_Face_auth`, `Pile_ou_Face_server`).
- **Plugins premium** : `release-customer.yml` (workflow_dispatch) dans `Pile_ou_Face_plugins` — bundle chiffré et signé par client.
- **Documentation publique** : dépôt `Pile_ou_Face_documentation` (MkDocs), branche de base `main`.
