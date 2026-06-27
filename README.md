# Pile ou Face

**Reverse engineering dans VS Code** — un outil d'analyse binaire intégré qui remplace IDA Pro et Ghidra.

Pile ou Face analyse des binaires ELF, PE et Mach-O (x86, x64, ARM64) directement dans VS Code via un hub interactif. Chargez un binaire, explorez ses fonctions, son désassemblage, son pseudo-C, et lancez des analyses de sécurité — le tout sans quitter votre éditeur.

---

## Ce que fait Pile ou Face

### Analyse du code

| Onglet | Description |
|--------|-------------|
| **Désassemblage** | Désassemblage Intel/AT&T avec coloration syntaxique et annotations |
| **CFG** | Graphe de flux de contrôle interactif (blocs de base + arcs) |
| **Call Graph** | Graphe d'appels — qui appelle qui dans le binaire |
| **Fonctions** | Découverte automatique de fonctions (y compris binaires strippés) |
| **Décompilateur** | Pseudo-C via retdec ou Ghidra, avec sélection de fonctions |
| **Hex View** | Dump hexadécimal avec coloration par section et patch de bytes |
| **Stack Frame** | Variables locales, paramètres et carte mémoire de la stack |
| **Binary Diff** | Si plugin `OFFENSIF` actif, comparaison de deux binaires — fonctions modifiées, ajoutées, supprimées |

### Données et métadonnées

| Onglet | Description |
|--------|-------------|
| **Strings** | Chaînes ASCII/UTF-8/UTF-16 extraites avec offset et section |
| **Symboles** | Table des symboles (fonctions, variables globales) |
| **Sections** | Sections du binaire (`.text`, `.data`, `.bss`…) avec taille et offset |
| **Infos** | Format, architecture, entry point, hashes MD5/SHA-256, packers |
| **Recherche** | Recherche par texte, hex ou regex dans les octets du binaire |

### Analyse malware

| Onglet | Description |
|--------|-------------|
| **Comportement** | Si plugin `MALWARE` actif, détection d'indicateurs malveillants (IPs, URLs, crypto, anti-VM) |
| **Taint** | Si plugin `AUDIT` actif, trace les flux de données dangereux (source → sink) |
| **Anti-analyse** | Si plugin `MALWARE` actif, détection de techniques anti-debug, VM detection, timing tricks |
| **Détection** | Si plugin `MALWARE` actif, scan YARA + CAPA (Mandiant) avec règles custom |

### Offensif

| Onglet | Description |
|--------|-------------|
| **ROP Gadgets** | Si plugin `OFFENSIF` actif, recherche de gadgets ROP (`pop rax ; ret`, `syscall ; ret`…) |
| **Vulnérabilités** | Si plugin `AUDIT` actif, détection de patterns CWE (gets, strcpy, system…) |
| **FLIRT** | Si plugin `OFFENSIF` actif, identification de fonctions de bibliothèques par signatures |
| **Déobfuscation** | Si plugin `MALWARE` actif, décodage automatique XOR/ROT sur les strings obfusquées |
| **Script** | Éditeur Python intégré avec imports directs des modules publics `backends.static.*` |

---

## Installation

### Prérequis

- **Node.js** 18+
- **Python** 3.8+
- **git**

Support **Windows, macOS et Linux**. Détails : [docs/PLATFORMS.md](docs/PLATFORMS.md).

### Backend (Python)

```bash
make install
```

Installe les dépendances dans un venv (`lief`, `capstone`, `pyelftools`…).

### Extension (JavaScript)

```bash
cd extension
npm install
```

### Outils optionnels

| Outil | Pour quoi faire | Installation |
|-------|----------------|-------------|
| `retdec-decompiler` | Décompilation pseudo-C | [retdec releases](https://github.com/avast/retdec/releases) |
| `yara` | Scan YARA | `brew install yara` / `apt install yara` |
| `capa` | Analyse de capacités Mandiant | `pip install flare-capa` |

---

## Utilisation

1. Ouvrez VS Code avec l'extension Pile ou Face activée
2. **Ctrl+Shift+P** → `Pile ou Face: Hub`
3. Chargez un binaire (ELF, PE ou Mach-O)
4. Naviguez dans les onglets pour analyser

### Scripting

Le panneau **Script** permet d'écrire des scripts Python avec des imports directs depuis les modules publics du repo :

```python
from backends.static.binary.symbols import extract_symbols
from backends.static.search.strings import extract_strings

# Lister les fonctions
for s in extract_symbols(binary)[:10]:
    print(f"{s['addr']}  {s['name']}")

# Lister des strings
for item in extract_strings(binary)[:10]:
    print(item.get('offset'), item.get('value'))
```

La variable `binary` est automatiquement injectée avec le chemin du binaire chargé.

---

## Structure du projet

```
Pile_Ou_Face/
├── extension/              # Extension VS Code (JavaScript)
│   ├── src/               # Logique extension + handlers
│   ├── webview/           # Hub (HTML, CSS, JS)
│   └── test/              # Tests Mocha
│
├── backends/              # Moteur d'analyse (Python)
│   ├── static/            # 30+ modules d'analyse statique
│   │   ├── repl/          # Exécuteur de scripts Python intégré
│   │   └── tests/         # Tests backend
│   ├── plugins/           # Runtime public des plugins optionnels
│   ├── dynamic/           # Domaine dynamique
│   │   ├── core/          # Interfaces et types communs
│   │   ├── pipeline/      # Orchestration, modèle et enrichissements
│   │   ├── engine/        # Moteurs runtime concrets
│   │   └── tests/         # Tests du domaine dynamique
│   └── shared/            # Utilitaires partagés
│
├── examples/              # Exemples C pour tester
├── docs/                  # Documentation
│   └── static/            # Doc des modules + roadmap
├── scripts/               # Scripts de build/test
├── Makefile               # Build automation
└── requirements.txt       # Dépendances Python
```

---

## Commandes

```bash
make test              # Tous les tests (Python + JS)
make install           # Installer les dépendances Python
npm test -C extension  # Tests JS uniquement
npm run lint -C extension  # Linter
```

---

## Documentation

| Document | Contenu |
|----------|---------|
| [docs/static/README.md](docs/static/README.md) | Documentation complète des 30+ modules d'analyse |
| [docs/static/ROADMAP.md](docs/static/ROADMAP.md) | Roadmap et features à venir |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Vision, couches et responsabilités |
| [docs/PLATFORMS.md](docs/PLATFORMS.md) | Compatibilité Windows/macOS/Linux |

### Intégrations plugins

Ce repo documente et implémente uniquement la partie host publique. Les capacités plugin visibles dans l'UI peuvent exister comme intégrations externes ; ici, on documente seulement le contrat public côté host.

---

## GitNexus — Code intelligence pour les agents IA

Ce repo est indexé par [GitNexus](https://github.com/looptech-ai/gitnexus), un outil
de graphe de connaissance du code. L'index (`.gitnexus/`) permet aux agents IA
(Claude Code, Codex…) d'analyser l'impact d'un changement avant de l'écrire.

### Installation (première fois)

```bash
# Depuis la racine du repo
npx gitnexus analyze .
```

L'index se crée dans `.gitnexus/` (gitignored). L'opération prend ~20 secondes.

### Commandes utiles

```bash
# Statut de l'index
npx gitnexus status

# Blast radius : qu'est-ce qui casse si je touche cette fonction ?
npx gitnexus impact <NomDeLaFonction>

# Vue 360° d'un symbole : qui l'appelle, qu'est-ce qu'il appelle ?
npx gitnexus context <NomDeLaFonction>

# Recherche sémantique dans les flux d'exécution
npx gitnexus query "payload preview"

# Carte des changements en cours (avant commit)
npx gitnexus detect-changes

# Wiki d'architecture généré depuis le graphe
npx gitnexus wiki .
```

Ou depuis `extension/` via npm :

```bash
npm run nexus:analyze    # ré-indexer depuis la racine
npm run nexus:status     # état de l'index
npm run nexus:wiki       # générer le wiki d'architecture
```

### Avant toute refacto

1. `npx gitnexus status` — vérifier que l'index est frais
2. `npx gitnexus impact <cible>` — lire le blast radius complet
3. `npx gitnexus context <cible>` — identifier les appelants/appelés
4. Produire : **zone impactée → sélecteurs → fichiers dépendants → risques → plan de validation**
5. Faire le changement minimal, puis `npx gitnexus detect-changes` avant commit

### Serveur MCP (Claude Code)

Le fichier `.mcp.json` déclare le serveur `gitnexus` en mode stdio.
Claude Code peut donc appeler `gitnexus_impact`, `gitnexus_context`,
`gitnexus_query` et `gitnexus_detect_changes` directement pendant une session.

---

## Licensing

Ce dépôt (host public) est distribué sous **AGPL-3.0-only**. Voir [`LICENSE`](LICENSE).

**Dual-licensing open-core :**

| Composant | Licence |
|-----------|---------|
| Repo public (host, extension, backends) | AGPL-3.0-only |

**Ce que cela signifie :**
- Utilisation personnelle, recherche et déploiement interne : libre sous AGPL.
- Tout service réseau (SaaS) exposant le host doit publier ses modifications sources.
- Pour une redistribution commerciale sans obligations AGPL, contactez-nous pour une **licence commerciale**.

**Contributions :** chaque contributeur doit signer le [`CLA.md`](CLA.md) avant qu'un PR soit fusionné. Le CLA permet à la société de distribuer les contributions sous licence commerciale.
