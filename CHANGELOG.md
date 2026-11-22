# Changelog

## [Unreleased]

### Security

- Les dépendances Python du backend ne sont plus installées sans votre accord : une notification propose « Install » ou « Later ». L'installation se fait uniquement dans le venv de l'extension, avec des versions vérifiées par hash.
- Les réglages envoyés par l'interface sont validés côté extension.
- Le chemin de l'interpréteur Python et le dossier Ghidra local ne peuvent être choisis que dans le dialogue de VS Code.
- L'interface ne peut plus déclencher que les commandes VS Code qu'elle utilise réellement.
- Le fichier des clés API IA locales (`~/.pile-ou-face/.env`) est créé avec des droits restreints. Un échec d'enregistrement d'une clé n'affiche plus que le nom de la variable concernée.
- Le dossier temporaire de l'extension (caches, traces) et les fichiers du triage IA sont placés dans un dossier privé par utilisateur.
- Plusieurs valeurs affichées dans l'interface (registres d'une trace, noms de sections) sont désormais traitées comme du texte.
- Compilation : seules les options proposées par le panneau sont acceptées, et le binaire est produit dans un dossier privé. Il n'est copié ailleurs que vers un chemin choisi dans le dialogue d'enregistrement de VS Code. La source doit être un fichier `.c`, `.cpp`, `.rs` ou `.go`.
- L'enregistrement d'un script depuis l'éditeur du hub n'écrit plus que dans le dossier des scripts de l'extension, sous un simple nom de fichier `.py` (#553).

### Changed

- Le champ « Flags custom » du panneau de compilation est retiré : les options libres ne sont plus acceptées.
- **Python 3.10 ou plus récent est requis** pour les fonctions Python.
- **macOS Intel :** l'installation automatique des dépendances Python n'est pas proposée, car `cryptography` ne publie plus de paquet pour cette plateforme. Le reste de l'extension fonctionne, et vous pouvez installer les dépendances vous-même puis choisir l'interpréteur dans les réglages.
- Le chemin Python choisi s'applique immédiatement, sans rouvrir le hub ni recharger l'extension.
- Le cache des analyses statiques ne bloque plus l'éditeur.

### Fixed

- Les requêtes d'authentification ont des délais et peuvent être annulées. Une réponse tardive n'affecte plus une session déjà révoquée.
- La vue de pile n'affiche plus de variables de l'appelant à l'entrée d'une fonction, notamment pour les binaires compilés avec CET (Ubuntu) et lors d'appels répétés.
- Un script REPL qui dépasse son délai est réellement arrêté.
- Les adresses `[::1]` sont reconnues comme locales pour le serveur d'authentification.

## [0.3.2] - 2026-11-02

### Security

- Renforcement du consentement et de l'isolation des plugins. Mise à jour recommandée.

### Changed

- Une nouvelle autorisation peut être demandée une fois pour les plugins déjà installés.

## [0.3.1] - 2026-10-25

### Fixed

- Redimensionnement des icônes de l'extension pour respecter les limites d'image du VS Code Marketplace.

## [0.3.0] - 2026-10-24

### Added

- **Système de types** (struct/union/enum, typedefs, prototypes) : catalogue de types par binaire, visible et résilient depuis l'éditeur, avec typedefs et prototypes traités comme des types de premier ordre.
- Rendu sémantique dans le décompilateur : accès champ `ptr->field` (y compris chaînes multi-niveaux `ptr->inner->field`) et littéraux d'enum symboliques, y compris dans les labels `switch`/`case`.
- Bindings de types pour paramètres et variables locales (`typed_var_bindings`), appliqués au pseudocode décompilé.

### Fixed

- Télémétrie de l'offre officielle : configuration de l'endpoint, acheminement des événements vers le service prévu et compatibilité avec le format de nom d'événement utilisé par VS Code.

## [0.2.0] - 2026-07-13

Consolide les changements livrés depuis `0.1.0` (les incréments internes `0.1.x` n'avaient pas d'entrées de changelog).

### Added

- Distribution sur **Open VSX** (VSCodium, Cursor, Gitpod) en plus du Marketplace VS Code.
- **Mode debug** : réglage `pileOuFace.logLevel` (`debug`/`info`/`warning`/`error`) qui pilote les logs de l'extension et se propage aux backends Python via `BINHOST_LOG_LEVEL`, plus une commande pour afficher les logs.
- Annotations : **statut de revue** et **favoris (bookmarks)** par annotation.
- Générateur de scaffold de plugin.
- Progression en flux (streaming) des scans de plugins.
- API plugin `window.PoF` (accès binaire, groupes/familles, `navigateTo`, helpers UI) et surface d'import stable `backends.plugin_api` pour les plugins.

### Changed

- Annotations désormais stockées en **SQLite** (clé = hash de contenu du binaire), avec migration automatique depuis l'ancien format JSON par fichier. WAL et clés étrangères activées.
- Extension **bundlée avec esbuild** : VSIX plus léger et activation plus rapide.
- Webviews de plugins **isolées dans des iframes sandboxées** (séparation host/plugin).

### Fixed

- Sécurité : clé API Gemini envoyée via en-tête HTTP au lieu de la query string.
- Émulation dynamique : lecture mémoire non mappée sur `getpid`/`getuid` corrigée.
- Boucle de rechargement du désassemblage lors d'un rafraîchissement du chemin binaire.
- Décompilateur : les résultats obsolètes après navigation sont ignorés.
- Échecs des handlers d'annotation remontés à l'utilisateur au lieu d'échouer en silence.
- Activation sur VSCodium sans workspace storage (fallback).
- Filet de sécurité global `unhandledRejection` / `uncaughtException`.

## [0.1.0] - 2026-06-29

Initial release.

### Static Analysis

- Disassembly with function banners, labels, inline comments and stack hints (ELF/PE/Mach-O, x86/x64/ARM32/ARM64/MIPS/PPC/RISC-V and more)
- Control Flow Graph (CFG) with switch tables, multi-arch adapters and unresolved branch detection
- Call graph with ISA adapters and fallback discovery
- Cross-references — code refs, data refs, import callsites
- Stack frame reconstruction (x86/x64/ARM64/ARM32 + generic fallback)
- Function discovery — tail-calls, thunks, PLT stubs
- Binary headers, sections, symbols, exports, imports with suspicion scoring
- Entropy analysis and packer detection (YARA byte-pattern signatures: UPX, ASPack, MPRESS, PECompact, Petite)
- DWARF debug info — source file and line annotations in disassembly
- PE resources browser
- Exception handlers (ELF `.eh_frame` DWARF64, Mach-O `__compact_unwind`)
- Hex view with endianness and pointer-size metadata
- String search, ROP gadget search, YARA scan (via optional plugins)

### Decompilation

- Multi-backend decompiler (Ghidra, RetDec, Angr via Docker)
- Automatic quality scoring across backends with `auto` mode
- ELF/PE/Mach-O support on x86-64 and ARM64

### Annotations and Types

- Function and address annotations persisted per binary
- C struct/union/enum editor (enum class, multidimensional arrays, function pointers)
- Typed data propagation into disassembly, xrefs and pseudo-C

### Analysis

- Analysis index (SQLite) — unified results cache
- Function radar — hotspots, quick wins, entry candidates, signal clusters
- Behavior, taint, anti-analysis, vulnerability patterns, FLIRT, CAPA, binary diff (via optional plugins)
- MITRE ATT&CK tagging, CWE enrichment, ROP chain builder (via optional plugins)
- Cross-analysis mode — correlates taint + behavior + ATT&CK techniques across functions

### AI Assistant

- Ollama integration with streaming and tool calling
- Cloud providers: OpenAI, Anthropic, Claude, Mistral, Gemini, OpenRouter, Groq, DeepSeek
- MCP server (stdio + HTTP transport) exposing all analysis tools to AI agents
- Context-aware prompts from disassembly, CFG, strings, imports, search results
- Conversation history, export (Markdown/JSON), token budget tracking, cost estimation

### Other

- Binary patch manager with undo/redo across sessions
- String deobfuscation (XOR/ROT/Base64/RC4/AES-ECB, stackstrings x86-64/ARM64)
- Python REPL with 15-function analysis API
- Script manager with project and global rule sets
- Multi-architecture compiler support via Docker (ELF, PE, Mach-O — GCC, Clang, Rust, Go)
- Plugin runtime — install and manage premium analysis plugins
