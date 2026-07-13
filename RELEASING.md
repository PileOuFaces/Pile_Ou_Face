# Releasing — déploiement de l'extension

Ce document décrit **comment publier une version de l'extension** (Marketplace VS Code + Open VSX).

## Principe en une phrase

Rien ne se publie depuis `develops`. **La publication se déclenche uniquement quand un tag `vX.Y.Z` est poussé sur un commit présent sur `main`.**

Flux : `feature/*` → PR → `develops` → PR de promotion → `main` → tag `vX.Y.Z` → publication.

## Les workflows

| Workflow | Déclencheur | Rôle |
|----------|-------------|------|
| `ci.yml` | PR + push (`develops`/`main`) | Lint + tests. C'est le check requis avant merge. |
| `docker-decompilers.yml` | push `develops` / PR vers `develops` (chemins `docker/decompilers/**`, `extension/backends/static/decompile/**`) | Build + **push** des images décompilateur sur ghcr. Sur `develops` : tags `:<version>` (immuable, depuis `image_versions.json`) + `develops` + `sha-*`. Sur PR : build de validation, **sans** push. |
| `vsix.yml` | push `main` | Package un `.vsix` en artefact (téléchargeable, **pas** publié). |
| `publish.yml` | push d'un tag `v*.*.*` | **Publie** : job `publish-marketplace` (`vsce`) + job `openvsx` (`ovsx`). Chaque job vérifie que le tag est bien un ancêtre de `main`. Publie la version lue dans `extension/package.json`. |

## Prérequis (une seule fois)

Secrets du dépôt (Settings → Secrets → Actions) :

- `VSCE_PAT` — Personal Access Token Azure DevOps pour le Marketplace VS Code.
- `OPEN_VSX_TOKEN` — token [open-vsx.org](https://open-vsx.org).

Vérifier le token Open VSX sans publier : Actions → **Publish** → *Run workflow* → `openvsx_mode = verify`.

## Procédure de release

### 1. Préparer sur `develops` (via PRs)

- Bumper `extension/package.json` (`version`) **et** `extension/package-lock.json` (garder les deux alignés).
- Ajouter l'entrée `CHANGELOG.md` de la version (Added / Changed / Fixed).
- Si un **Dockerfile ou adaptateur de décompilateur a changé**, bumper l'entrée correspondante dans `extension/backends/static/decompile/image_versions.json`.

### 2. Publier d'abord les images décompilateur (si concernées)

Quand une PR touchant `extension/backends/static/decompile/**` ou `docker/decompilers/**` est mergée sur `develops`, `docker-decompilers.yml` **build + pousse les tags `:<version>`** sur ghcr.

> ⚠️ **Ordre critique** : l'extension figée pull `decompiler-<outil>:<version>` (le tag épinglé). Ce tag doit exister sur ghcr **avant** que la version d'extension soit publiée, sinon les utilisateurs auront « image introuvable » lors d'une décompilation Docker.

Vérifier que le run `docker-decompilers.yml` sur `develops` est **vert** avant de continuer.

### 3. Promouvoir `develops` → `main`

Ouvrir une PR `develops` → `main`, la merger. En cas de conflit de version (`package.json`/`package-lock.json`), **garder la version de `develops`** (la nouvelle).

### 4. Tagger sur `main`

```bash
git checkout main && git pull origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

Le push du tag déclenche `publish.yml` → Marketplace + Open VSX.

### 5. Vérifier

- Le run `Publish` est vert (2 jobs).
- Marketplace : la nouvelle version apparaît sur la page de l'extension.
- Open VSX : `https://open-vsx.org/extension/PileOuFaces/stack-visualizer`.

## Pré-release (beta / rc)

Tagger avec un suffixe `-pre`, `-beta` ou `-rc` (ex. `v0.3.0-rc1`) : les deux jobs publient alors en **`--pre-release`**. Utile pour tester une build sans la pousser au canal stable.

## Dépannage

| Symptôme | Cause / correctif |
|----------|-------------------|
| `Tag is not on main — publish aborted` | Le commit taggé n'est pas sur `main`. Merger la promotion (étape 3) avant de tagger. |
| `vsce` : version déjà publiée | La `version` de `package.json` existe déjà sur le Marketplace. Bumper + retagger. |
| Job publish échoue sur le PAT | Secret `VSCE_PAT` / `OPEN_VSX_TOKEN` manquant ou expiré. Pas de dommage, juste pas de publication. |
| Utilisateur : image décompilateur introuvable | Le tag `:<version>` n'a pas été poussé (étape 2 sautée, ou run docker rouge). |

## Autres composants (déploiement séparé)

- **Serveur d'auth / SaaS collaboratif** : déploiement Kubernetes, voir chaque dépôt (`Pile_ou_Face_auth`, `Pile_ou_Face_server`).
- **Plugins premium** : `release-customer.yml` (workflow_dispatch) dans `Pile_ou_Face_plugins` — bundle chiffré et signé par client.
- **Documentation publique** : dépôt `Pile_ou_Face_documentation` (MkDocs), branche de base `main`.
