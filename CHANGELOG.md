# Changelog

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
