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
- **Python** 3.8+

### Backend Python

```bash
make install
```

Installe les dépendances dans un venv (`lief`, `capstone`, `pyelftools`, `unicorn`…).

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
