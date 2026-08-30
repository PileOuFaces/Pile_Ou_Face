# Contributing to Pile ou Face

Merci de l'intérêt pour le projet. Ce guide explique comment configurer l'environnement, lancer les tests et soumettre une contribution.

## Prérequis

- **Node.js** 18+
- **Python** 3.8+
- **Docker** (optionnel, pour les décompilateurs)
- **git**

## Installation

```bash
# Cloner le repo
git clone https://github.com/PileOuFaces/Pile_Ou_Face.git
cd Pile_Ou_Face

# Installer les dépendances Python (venv dans extension/backends/.venv)
make install

# Installer les dépendances Node.js
cd extension && npm install
```

## Hooks pre-commit

Installez les hooks avant de travailler sur une branche :

```bash
python3 -m pip install pre-commit
pre-commit install
```

Les hooks relancent localement le lint Python de la CI publique (`ruff check` et `ruff format --check` dans `extension/`) pour éviter les PR qui échouent uniquement sur GitHub.

## Lancer les tests

```bash
# Tous les tests (Python + JS)
make test

# Tests Python uniquement
cd extension && PYTHONPATH=. backends/.venv/bin/python3 -m pytest backends/static/tests/

# Tests JS uniquement
cd extension && npm test

# Couverture Python
cd extension && PYTHONPATH=. backends/.venv/bin/python3 -m pytest backends/static/tests/ --cov=backends

# Couverture JS
cd extension && npm run test:coverage
```

## Structure du repo

```
Pile_Ou_Face/
├── extension/              # Extension VS Code (TypeScript)
│   ├── src/               # Logique extension + handlers
│   ├── front/             # Webview (HTML, CSS, JS)
│   ├── backends/          # Moteur d'analyse Python
│   │   ├── static/        # 30+ modules d'analyse statique
│   │   ├── dynamic/       # Analyse dynamique (Unicorn)
│   │   ├── mcp/           # Serveur MCP
│   │   └── plugins/       # Runtime plugins
│   └── docker/            # Décompilateurs et compilateurs Docker
└── docs/                  # Documentation
    ├── static/            # Doc fonctionnalités et architecture
    └── mcp/               # Doc serveur MCP
```

## Workflow de contribution

1. Créez une branche depuis `develops` : `git checkout -b feature/<nom>`
2. Faites vos modifications
3. Lancez les tests : `make test`
4. Ouvrez une Pull Request vers `develops`

**Règles :**
- Ne pas ouvrir de PR directement vers `main`
- Chaque PR doit avoir au moins un test couvrant la modification
- Respecter le style existant (Ruff pour Python, ESLint pour TypeScript)

## Textes de l’interface et localisation

Les textes visibles des webviews restent écrits en français dans les fichiers HTML et JavaScript,
puis sont associés à leur traduction anglaise dans `extension/front/shared/i18n.js`. Les commandes
et réglages natifs de VS Code utilisent `extension/package.nls.json` et
`extension/package.nls.fr.json`.

Lors de l’ajout ou de la modification d’un texte utilisateur :

1. ajoutez son entrée anglaise au catalogue `EN` ;
2. ne cataloguez jamais les adresses, symboles, annotations utilisateur, sorties backend ou autres
   données techniques ;
3. vérifiez les deux langues depuis Options → Interface → Langue ;
4. lancez `cd extension && npm run lint:i18n && npm test`.

`npm run lint:i18n` inspecte les textes et attributs accessibles des fichiers HTML. Il échoue quand
une chaîne vraisemblablement française n’est pas cataloguée. Les contenus de `code`, `pre`, `script`
et `style` sont volontairement ignorés pour préserver les données techniques.

## Licence

Ce repo est sous **AGPL-3.0-only** (voir [`LICENSE`](LICENSE) à la racine).

Le fichier `extension/LICENSE` a été intentionnellement supprimé pour éviter la duplication. La licence canonique est celle à la racine du repo. `vsce` utilisera le champ `"license"` de `package.json` pour le Marketplace.

Tout contributeur doit signer le [`CLA.md`](CLA.md) avant qu'une PR soit fusionnée.

## Signaler un bug

Ouvrez une issue sur [GitHub](https://github.com/PileOuFaces/Pile_Ou_Face/issues) en décrivant :
- La version de l'extension
- Le système d'exploitation
- Les étapes pour reproduire
- Le comportement attendu vs observé
