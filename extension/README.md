# Pile ou Face

**Reverse engineering dans VS Code** — un outil d'analyse binaire intégré qui remplace IDA Pro et Ghidra.

Pile ou Face analyse des binaires ELF, PE et Mach-O (x86, x64, ARM64) directement dans VS Code via un hub interactif. Chargez un binaire, explorez ses fonctions, son désassemblage, son pseudo-C, et lancez des analyses de sécurité — le tout sans quitter votre éditeur.

---

## Fonctionnalités

### Analyse du code

| Onglet | Description |
|--------|-------------|
| **Désassemblage** | Intel/AT&T avec coloration syntaxique, labels, commentaires inline et hints de stack |
| **CFG** | Graphe de flux de contrôle interactif (blocs de base + arcs, switch tables) |
| **Call Graph** | Graphe d'appels — qui appelle qui dans le binaire |
| **Fonctions** | Découverte automatique (binaires strippés, tail-calls, thunks, stubs PLT) |
| **Décompilateur** | Pseudo-C via Ghidra, RetDec ou Angr avec scoring qualité automatique |
| **Hex View** | Dump hexadécimal avec métadonnées d'endianness et de taille de pointeur |
| **Stack Frame** | Variables locales, paramètres et carte mémoire de la stack |

### Données et métadonnées

| Onglet | Description |
|--------|-------------|
| **Strings** | Chaînes ASCII/UTF-8/UTF-16 extraites avec offset et section |
| **Symboles** | Table des symboles (fonctions, variables globales, exports, imports) |
| **Sections** | Sections du binaire avec taille, offset et scoring de suspicion |
| **Infos** | Format, architecture, entry point, hashes, entropie, détection de packers |
| **Recherche** | Recherche par texte, hex ou regex dans les octets du binaire |
| **Xrefs** | Références croisées — code refs, data refs, callsites d'imports |

### IA et MCP

| Fonctionnalité | Description |
|----------------|-------------|
| **Assistant IA** | Ollama (streaming + tool calling) + OpenAI, Anthropic, Mistral, Gemini, Groq, DeepSeek |
| **Auto-triage IA** | Nomme/commente automatiquement les fonctions interessantes, resume executif + rapport Markdown, consentement opt-in, budget borne et annulable |
| **Serveur MCP** | Expose 49 outils d'analyse aux agents IA (transport stdio + HTTP) |
| **Contexte auto** | Prompts préparés depuis le désassemblage, le CFG, les strings, les imports |

### Plugins optionnels

| Plugin | Capacités |
|--------|-----------|
| **Malware Triage Pro** | Comportement, anti-analyse, YARA, CAPA, déobfuscation de strings |
| **Vulnerability Audit Pro** | Patterns de vulnérabilités CWE, taint analysis |
| **Offensive Research Pro** | ROP gadgets, FLIRT, binary diff, similarité de fonctions |

---

## Installation

### Prérequis

- **VS Code** 1.120+
- **Node.js** 18+
- **Python** 3.10 à 3.13 pour l'installation automatique des dépendances (voir ci-dessous)

### Backend Python

```bash
make install
```

Installe les dépendances dans un venv (`lief`, `capstone`, `pyelftools`, `unicorn`…).

#### Installation depuis l'extension (consentement explicite)

À l'activation, l'extension vérifie seulement que `unicorn` et `capstone` sont
importables dans `backends/.venv` (ou dans l'interpréteur configuré via
`pythonPath`). Le Python système n'est pas pris en compte : il peut n'avoir
qu'une partie des dépendances (par exemple sans `lief`). S'ils manquent, elle
**ne lance rien** : une notification propose « Install » ou « Later ».

- **`requirements.lock.txt` absent** (défaut de packaging) : aucune
  installation possible ; un avertissement s'affiche, même à l'activation.

- **Later** ou notification fermée : aucun `pip`, aucun venv créé ; les
  fonctions Python restent indisponibles, l'extension continue de fonctionner.
- **Version de Python** : le venv est créé avec un CPython **3.10 à 3.13**, le seul
  intervalle où toutes les dépendances verrouillées publient des wheels (`yara-python`
  s'arrête à 3.13). L'extension cherche `python3.13` … `python3.10`, puis `python3` et
  `python`. Sous Windows, elle essaie les dossiers d'installation de python.org
  (`%LOCALAPPDATA%\Programs\Python\Python313` … `Python310`, puis `%ProgramFiles%`),
  puis `python` et `python3`, sans passer par le lanceur `py`, qui peut installer une
  version manquante. Elle prend le premier interpréteur de la plage.
  Si aucun ne convient, elle **refuse avant pip** et liste les interpréteurs trouvés.
  Un `backends/.venv` créé avec une version hors plage n'est pas réutilisé : le
  message indique de supprimer ce dossier.
- **Install** : création si besoin de `backends/.venv`, puis deux commandes pip
  dans ce venv :
  1. `<venv>/python -m pip install --require-hashes --only-binary=:all: --no-binary=hexdump,vivisect-vstruct-wb -r backends/requirements-build.lock.txt` ;
  2. `<venv>/python -m pip install --require-hashes --only-binary=:all: --no-binary=hexdump,vivisect-vstruct-wb --no-build-isolation -r backends/requirements.lock.txt`.

  Seuls des wheels sont installés, sauf pour les deux paquets publiés uniquement en
  sources (Python pur). Sans wheel pour cette version de Python, cet OS ou cette
  architecture, pip échoue sans rien compiler, et le message nomme le paquet en cause.

  L'installation se fait uniquement dans ce venv, sans `--break-system-packages`.
  Si la configuration pip (fichier `pip.conf`/`pip.ini` ou variable `PIP_*`)
  redirige l'installation (`target`, `prefix`, `root`, `user`, `python`), l'extension
  annule et l'indique ; les autres réglages (miroir, proxy, certificat) sont conservés.
- **Hors ligne** : l'échec est signalé (« PyPI is unreachable ») avec la
  commande manuelle ; l'activation n'est pas bloquée et la proposition revient
  au prochain démarrage.
- **Interpréteur configuré** (réglage `pythonPath` hors de `backends/.venv`) :
  l'extension ne le remplace jamais et n'y installe rien. Elle indique la commande
  à lancer soi-même, et signale une version hors de la plage 3.10 à 3.13.

#### Versions vérifiées : `backends/requirements.lock.txt` et `requirements-build.lock.txt`

`backends/requirements.txt` liste les dépendances directes (source éditée à la
main). `backends/requirements.lock.txt` en est dérivé : toutes les versions,
transitives comprises, sont figées avec les hashes de **toutes** les
distributions publiées (wheels Linux, macOS, Windows et sdist), pour toutes les
plateformes. Ne pas l'éditer à la main.

`backends/requirements-build.lock.txt` (dérivé de `requirements-build.txt`) fige
de la même façon les outils de construction (`setuptools`, `wheel`). Certaines
dépendances n'existent qu'en sdist : par défaut, pip installerait ces outils dans
un environnement de build isolé, **sans version ni hash**, puis exécuterait leur
code. L'extension installe donc d'abord ce fichier, puis le lock principal avec
`--no-build-isolation` : tout le code téléchargé est vérifié par hash.

Régénération (outil : [uv](https://docs.astral.sh/uv/) 0.9.5, la version utilisée pour le
fichier actuel) depuis `extension/backends/` :

```bash
for name in requirements requirements-build; do
  uv pip compile "$name.txt" \
    --universal --python-version 3.10 \
    --generate-hashes \
    --exclude-newer 2026-11-21T00:00:00Z \
    --output-file "$name.lock.txt"
done
```

- `--universal` : une seule résolution valable pour tous les OS et versions de Python ≥ 3.10.
  3.10 est le minimum du backend (`MIN_PYTHON_VERSION` dans `backends/mcp/setup_cli.py`,
  syntaxe `X | None`) ; `python-idb` exige d'ailleurs Python ≥ 3.9.
- `--exclude-newer` : ignore les publications postérieures à la date ; la même
  commande redonne le même fichier. Avancer cette date volontairement pour
  mettre à jour les versions, et reporter la nouvelle date ici.
- Vérifier ensuite dans un venv propre, avec les deux commandes pip de **Install**
  ci-dessus (outils de construction, puis lock principal avec `--no-build-isolation`).
- `hexdump` et `vivisect-vstruct-wb` n'existent qu'en sdist (Python pur) : pip les
  construit avec les outils figés, sans compilateur. Cette liste
  (`SOURCE_ONLY_PACKAGES` dans `src/shared/pythonDependencies.ts`) doit être
  revue à chaque régénération : tout autre paquet doit publier des wheels.
- Plage de Python de l'installation automatique (`SUPPORTED_MIN`/`SUPPORTED_MAX` dans
  `src/shared/pythonInterpreter.ts`) : la revoir si les wheels d'une nouvelle
  version deviennent disponibles pour tous les paquets compilés.
- **Non pris en charge — installation automatique sur macOS Intel :** `cryptography`
  50.0.2 (version verrouillée) ne publie pas de wheel macOS x86_64 ; seul arm64 en a
  depuis la 49. L'extension ne compile rien implicitement depuis les sources et ne
  rétrograde pas cette dépendance. Quand l'interpréteur Python qui recevrait les paquets
  est un macOS x86_64 (`sys.platform`, `platform.machine()`, Rosetta compris), elle ne
  propose donc pas l'installation et l'explique par un avertissement. Seule cette
  installation automatique est concernée : le reste de l'extension fonctionne, et les
  fonctions Python restent utilisables si l'on installe soi-même les dépendances de
  `backends/requirements.txt` dans un environnement Python choisi avec le réglage `pythonPath`.

### Décompilateurs (optionnel)

Les décompilateurs tournent dans des containers Docker isolés :

```bash
make decompiler-docker-build DECOMPILER=ghidra
make decompiler-docker-build DECOMPILER=retdec
make decompiler-docker-build DECOMPILER=angr
```

---

## Utilisation

1. Ouvrez VS Code avec l'extension Pile ou Face activée
2. **Alt+Shift+P** ou **Ctrl+Shift+P** → `Pile ou Face`
3. Chargez un binaire (ELF, PE ou Mach-O)
4. Naviguez dans les onglets pour analyser

### Scripting Python intégré

Le panneau **Script** permet d'écrire des scripts avec accès direct aux modules d'analyse :

```python
from backends.static.binary.symbols import extract_symbols
from backends.static.search.strings import extract_strings

for s in extract_symbols(binary)[:10]:
    print(f"{s['addr']}  {s['name']}")
```

La variable `binary` est automatiquement injectée avec le chemin du binaire chargé.

---

## Documentation

| Document | Contenu |
|----------|---------|
| [docs/static/ARCHITECTURE.md](../docs/static/ARCHITECTURE.md) | Architecture du système |
| [docs/static/PLUGIN.md](../docs/static/PLUGIN.md) | Contrat host/plugin |
| [docs/mcp/README.md](../docs/mcp/README.md) | Serveur MCP — installation et outils |
| [docs/static/DECOMPILERS.md](../docs/static/DECOMPILERS.md) | Configuration des décompilateurs |

---

## Licence

AGPL-3.0-only. Voir [`LICENSE`](LICENSE).

Pour une utilisation commerciale sans obligations AGPL, contactez-nous.
