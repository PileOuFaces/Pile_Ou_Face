# Référence des modules — Pile ou Face Static Backend
> Documentation pour l'integration MCP du **host public**.
> Les outils optionnels ne sont plus exposes nativement par le serveur public : ils passent par `plugins_list`, `plugin_invoke` et les outils dynamiques `plugin.*` quand un plugin est actif.

---

## Conventions

| Champ | Description |
|-------|-------------|
| **Tool name** | Nom de l'outil MCP (snake_case) |
| **Inputs** | Paramètres JSON attendus |
| **Output** | Clés JSON retournées |
| **Deps** | Dépendances Python requises |

Toutes les adresses sont des strings hex (`"0x401000"`). Tous les modules s'importent depuis `backends.static.<nom>`.

## Outils optionnels pluginises

Dans le repo public, les commandes suivantes ne sont plus des outils MCP natifs :

- `find_vulnerabilities`
- `taint_analysis`
- `analyze_behavior`
- `detect_anti_analysis`
- `yara_scan`
- `capa_scan`
- `find_rop_gadgets`
- `flirt_scan`
- `compare_functions`
- `diff_binaries`
- `deobfuscate_strings`

Le pattern attendu est :

1. appeler `plugins_list` ;
2. verifier qu'un plugin actif expose la commande voulue ;
3. appeler `plugin_invoke` ;
4. ou utiliser directement `plugin.<namespace>.<action>` si le runtime l'a publie dans `tools/list`.

---

## annotations

**Gestion des annotations persistantes** (commentaires, renames, bookmarks, statut/notes
de revue) liées à une adresse, dans une base SQLite dédiée
(`~/.pile-ou-face/annotations.db`, home de l'utilisateur — indépendante de
`context.storageUri`, résolue de la même façon par ce serveur MCP et par l'extension
VS Code). Les annotations créées via le MCP et celles créées via l'UI Hub de
l'extension pointent désormais vers la **même base** : un agent IA et l'utilisateur
voient/modifient les mêmes données pour un même binaire.

```
tool: annotations_list / annotations_save / annotations_delete
```

Façade orientée session : `AnnotationStore(binary_path)` (`backends/static/annotations/annotations.py`),
construite sur `annotation_db.AnnotationDb` (et non plus sur `DisasmCache`) — avec
`.comment()`, `.rename()`, `.get()`, `.list()`, `.delete()`, `.set_review()`,
`.get_review()`, `.set_bookmark()`, `.delete_bookmark()`, `.clear_bookmarks()`,
`.list_bookmarks()`. Le binaire est identifié par le hash sha256 de son contenu (pas
chemin+mtime).

Les fonctions module-level historiques `load_annotations`/`save_annotation`
(`(workspace, binary_sha256, ...)`) et le CLI `--save`/`--load` qui écrivaient
dans `.pof/annotations.json` ont été retirés : le chemin supporté est
`AnnotationStore` + SQLite. Les anciens fichiers JSON webview ne sont plus migrés.

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "addr": "0x401000", "comment": "...", "name": "func_name" }
```

### Output
```json
[{ "addr": "0x401000", "kind": "comment|name|review_status|review_notes|bookmark|bookmark_color", "value": "...", "updated_at": "..." }]
```

### Deps
`sqlite3` (via `cache.py`)

---

## anti_analysis

**Capacite pluginisee** de detection de techniques anti-analyse : VM detection, timing, imports anti-debug, checks d'environnement.

```
tool: detect_anti_analysis
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `MALWARE` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.malware.anti_analysis.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "plugin": "MALWARE",
  "command": "malware.anti_analysis.run",
  "result": {
    "signals": [{
      "technique": "RDTSC timing check",
      "description": "...",
      "confidence": "HIGH|MEDIUM",
      "addr": "0x401234"
    }]
  }
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## asm_sim

**Simulateur x86-64 statique** : exécute un fragment ASM et produit des snapshots de registres/pile à chaque étape.

```
tool: simulate_asm
```

### Fonction principale
```python
simulate(program, labels) -> list[dict]
parse_program(lines) -> (list[dict], dict[str, int])
```

### Input MCP
```json
{ "asm_code": "push rbp\nmov rbp, rsp\n..." }
```

### Output
```json
{
  "snapshots": [{
    "step": 1, "instr": "push rbp", "line": 1,
    "stack": [...], "registers": [{"name": "rbp", "value": "0x..."}]
  }],
  "meta": { "view_mode": "x86_64", "word_size": 8 },
  "risks": []
}
```

### Deps
Aucune

---

## behavior

**Capacite pluginisee** d'analyse comportementale : reseau, crypto, persistance, exfiltration, evasion.

```
tool: analyze_behavior
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `MALWARE` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.malware.behavior.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "plugin": "MALWARE",
  "command": "malware.behavior.run",
  "result": {
    "indicators": [{
      "category": "NETWORK|CRYPTO|PERSISTENCE|EVASION",
      "evidence": "connect(), bind()...",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "offset": 4198400
    }],
    "score": 72
  }
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## binary_exports

**Extraction des exports** d'un binaire ELF/PE/Mach-O. Pour les exécutables non strippés, inclut aussi la symbol table.

```
tool: get_exports
```

### Fonction principale
```python
extract_exports(binary_path: str) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "format": "ELF|PE|Mach-O",
  "exports": [{
    "addr": "0x401000",
    "name": "decode_xor_single",
    "demangled": null,
    "type": "function|data",
    "ordinal": null
  }],
  "count": 10
}
```

### Deps
`lief` (requis)

---

## binary_patch

**Patch bytes dans un binaire** à un offset fichier précis.

```
tool: patch_binary
```

### Fonction principale
```python
patch_bytes(binary_path: str, offset: int, bytes_hex: str) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "offset": "0x1234", "bytes": "90 90 eb 0a" }
```

### Output
```json
{ "ok": true, "written": 4, "offset": 4660 }
```

### Deps
Aucune (écriture binaire directe)

---

## bindiff

**Capacite pluginisee** de comparaison de deux binaires au niveau fonction.

```
tool: diff_binaries
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `OFFENSIF` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.offensive.bindiff.run`.

### Input MCP
```json
{ "binary_a": "/path/a.elf", "binary_b": "/path/b.elf", "threshold": 0.6 }
```

### Output
```json
{
  "plugin": "OFFENSIF",
  "command": "offensive.bindiff.run",
  "result": {
    "ok": true,
    "functions": [{
      "name": "check_password",
      "addr_a": "0x401166", "addr_b": "0x401180",
      "status": "identical|modified|removed|added",
      "similarity": 0.94,
      "diff": [{ "type": "added|removed|equal", "asm": "...", "addr_a": "...", "addr_b": "..." }]
    }],
    "stats": { "identical": 5, "modified": 2, "added": 0, "removed": 1 }
  }
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## cache

**Cache SQLite `.pfdb`** pour résultats d'analyse. Utilisé en interne par tous les modules — rarement exposé directement via MCP, mais utile pour `invalidate` et `list`.

```
tool: cache_invalidate / cache_stats
```

### Fonctions principales
```python
DisasmCache(db_path)
  .get_disasm(binary_path)  -> Optional[tuple[int, list[dict]]]
  .save_disasm(binary_path, lines) -> int
  .invalidate(binary_path)  -> None
default_cache_path(binary_path) -> str
compute_sha256(path) -> str
```

### Notes MCP
- `default_cache_path(bp)` → `$POF_STORAGE_DIR/pfdb/<binary_name>.<hash>.pfdb` quand `POF_STORAGE_DIR` est defini, sinon `<binary_dir>/pfdb/<binary_name>.<hash>.pfdb` pour un lancement CLI direct
- Les chemins sont normalisés en absolu (`os.path.abspath`) avant lookup
- `invalidate` force le recalcul à la prochaine analyse

### Deps
`sqlite3`, `hashlib`

---

## call_graph

**Graphe d'appels** (call graph) construit depuis le CFG et les symboles. Résout les stubs PLT/GOT (ELF) et dyld stubs (Mach-O).

```
tool: build_call_graph
```

### Fonction principale
```python
build_call_graph(cfg: dict, symbols: list[dict], lines=None, binary_path=None) -> dict
resolve_plt_symbols(binary_path: str) -> dict[str, str]  # {"0x401020": "printf@plt"}
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "nodes": [{ "addr": "0x401000", "name": "main", "is_external": false }],
  "edges": [{ "from": "0x401000", "to": "0x401020", "from_name": "main", "to_name": "printf@plt" }]
}
```

### Deps
`lief` (optionnel)

---

## capa_scan

**Capacite pluginisee** d'analyse des capacites probables d'un binaire avec `capa`.

```
tool: capa_scan
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `MALWARE` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.malware.capa.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "timeout": 120 }
```

### Output
```json
{
  "plugin": "MALWARE",
  "command": "malware.capa.run",
  "result": {
    "capabilities": [{
      "name": "inject process",
      "namespace": "host-interaction/process/inject",
      "locations": ["0x401234"],
      "matches": []
    }],
    "errors": []
  }
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## cfg

**Graphe de flux de contrôle** (CFG) : identifie blocs de base, arêtes (jmp, jcc, call, fallthrough), tables de switch.

```
tool: build_cfg / build_cfg_for_function
```

### Fonctions principales
```python
build_cfg(lines: list[dict], binary_path=None) -> dict
build_cfg_for_function(lines: list[dict], func_addr: str, binary_path=None) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "func_addr": "0x401166" }
```

### Output
```json
{
  "blocks": [{
    "addr": "0x401166",
    "lines": [{ "addr": "0x401166", "text": "push rbp" }],
    "successors": ["0x40118b"],
    "is_call": false,
    "is_switch": false,
    "switch_cases": []
  }],
  "edges": [{ "from": "0x401166", "to": "0x40118b", "type": "jcc|jmp|call|fallthrough|jumptable" }]
}
```

### Deps
`lief` (optionnel), `re`

---

## decompile

**Décompilation en pseudo-C** via retdec, radare2/r2ghidra ou Ghidra headless.

```
tool: decompile_function / decompile_binary
```

### Fonctions principales
```python
decompile_function(binary_path, addr, func_name="", decompiler="") -> dict
decompile_binary(binary_path, decompiler="") -> dict
list_available_decompilers() -> dict[str, bool]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "addr": "0x401166", "decompiler": "r2ghidra" }
```

`quality` peut encore etre envoye par d'anciens clients MCP, mais il est ignore pour compatibilite.

### Output
```json
{
  "addr": "0x401166",
  "code": "int check_password(char *s) {\n  ...\n}",
  "decompiler": "r2ghidra",
  "error": null
}
```

### Décompilateurs supportés
| ID | Outil requis |
|----|-------------|
| `r2pdc` | radare2 |
| `r2ghidra` | radare2 + r2ghidra plugin |
| `ghidra` | Ghidra headless |
| `retdec` | retdec CLI |

### Deps
`capstone`, `lief`, `subprocess` + outil externe au choix

---

## disasm

**Désassemblage complet** d'un binaire avec capstone.
Le serveur MCP gère automatiquement les fichiers de sortie (ASM + mapping JSON),
donc l'utilisateur n'a pas à fournir `--output`.

```
tool: disassemble
```

### Fonction principale
```python
disassemble(binary_path: str, output_asm: str, output_mapping: str | None) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "addr": "0x401000", "max_lines": 400 }
```

### Output
```json
{
  "ok": true,
  "binary_path": "/abs/path/binary",
  "asm_path": "/abs/workspace/.pile-ou-face/mcp/demo.123.disasm.asm",
  "mapping_path": "/abs/workspace/.pile-ou-face/mcp/demo.123.mapping.json",
  "count": 1234,
  "truncated": true,
  "addr_filter": "0x401000",
  "lines": [{ "addr": "0x401000", "line": 101, "text": "55                   push     rbp" }]
}
```

### Note
Le champ `text` est au format `"<hex_bytes>   <mnemonic>   <operands>"`.

### Deps
`lief` (requis), `capstone` (requis)

---

## discover_functions

**Découverte heuristique de fonctions** sur binaires strippés via prologue scanning (patterns `push rbp; mov rbp, rsp`).

```
tool: discover_functions
```

### Fonction principale
```python
discover_functions(lines, known_addrs, custom_preludes=None, binary_path=None, flirt_matches=None) -> list[dict]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
[{
  "addr": "0x401166",
  "name": "sub_401166",
  "confidence": "high|medium|low|confirmed",
  "reason": "ELF symbol table|prologue pattern|FLIRT match",
  "size": 42
}]
```

### Deps
`lief` (optionnel), `backends.static.flirt` (optionnel)

---

## dwarf

**Extraction des informations debug DWARF** depuis un binaire ELF non strippé : fonctions, types, variables.

```
tool: extract_dwarf
```

### Fonction principale
```python
extract_dwarf_info(binary_path: str) -> dict
extract_line_mapping(binary_path: str) -> dict[int, dict]  # {addr -> {file, line}}
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary.elf" }
```

### Output
```json
{
  "functions": [{ "name": "main", "low_pc": "0x401000", "high_pc": "0x401100", "return_type": "int" }],
  "types": [{ "kind": "struct", "name": "PacketHeader", "byte_size": 8, "members": [{ "name": "magic", "type": "uint32_t", "offset": 0 }] }],
  "variables": [{ "name": "g_count", "type": "int", "addr": "0x404010" }]
}
```

### Deps
`pyelftools` (requis)

---

## entropy

**Analyse entropie de Shannon** par sections et fenêtres glissantes. Utile pour détecter chiffrement, packing, données compressées.

```
tool: analyze_entropy
```

### Fonctions principales
```python
entropy_of_file(binary_path: str) -> dict
high_entropy_regions(binary_path, threshold=7.0, window=256, step=None) -> list[dict]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "threshold": 7.0, "window": 256 }
```

### Output
```json
{
  "global": 6.82,
  "sections": [{ "name": ".text", "entropy": 6.1, "size": 4096, "offset": "0x1000" }],
  "high_entropy_regions": [{ "offset": 8192, "offset_hex": "0x2000", "entropy": 7.85 }]
}
```

### Deps
`lief` (optionnel), `math`

---

## export

**Export des résultats d'analyse** vers formats portables : CSV (symboles, strings), JSON (xrefs), DOT (CFG Graphviz).

```
tool: export_results
```

### Fonctions principales
```python
export_symbols_csv(symbols, output_path) -> int
export_strings_csv(strings, output_path) -> int
export_xrefs_json(xref_map, output_path) -> int
export_cfg_dot(cfg, output_path, graph_name="CFG") -> int
```

### Input MCP
```json
{ "data": {...}, "format": "csv|json|dot", "output_path": "/tmp/out.csv" }
```

### Deps
`csv`

---

## flirt

**Capacite pluginisee** de reconnaissance de fonctions connues par signatures.

```
tool: flirt_scan
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `OFFENSIF` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.offensive.flirt.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "plugin": "OFFENSIF",
  "command": "offensive.flirt.run",
  "result": [{
    "addr": "0x401234",
    "name": "strlen",
    "lib": "libc",
    "confidence": "medium"
  }]
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## func_similarity

**Capacite pluginisee** de similarite de fonctions entre un binaire cible et un binaire de reference.

```
tool: compare_functions
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `OFFENSIF` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.offensive.func_similarity.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/target.elf", "reference_path": "/abs/path/libc.so", "threshold": 0.4, "top": 3 }
```

### Output
```json
{
  "plugin": "OFFENSIF",
  "command": "offensive.func_similarity.run",
  "result": {
    "matches": [{
      "addr": "0x401166",
      "name": "sub_401166",
      "match_name": "strcmp",
      "match_addr": "0x7f1234",
      "score": 0.82,
      "ref_binary": "/abs/path/libc.so",
      "opcode_count": 24
    }],
    "stats": { "target_functions": 12, "ref_functions": 850, "matches_found": 3, "threshold": 0.4 }
  }
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## headers

**Extraction des informations générales** d'un binaire : format, architecture, entry point, stripped, hashes, packer.

```
tool: get_binary_info
```

### Fonction principale
```python
extract_binary_info(binary_path: str) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "path": "/abs/path/binary",
  "format": "ELF|PE|Mach-O",
  "machine": "x86_64|arm64|i386",
  "entry": "0x401080",
  "type": "executable|shared|core",
  "bits": "64",
  "arch": "x86_64",
  "stripped": false,
  "interp": "/lib64/ld-linux-x86-64.so.2",
  "packers": ["UPX"],
  "md5": "...",
  "sha256": "...",
  "imphash": "..."
}
```

### Deps
`lief` (requis), `hashlib`

---

## hex_view

**Dump hexadécimal** paginé du contenu d'un binaire avec coloration par section.

```
tool: hex_dump
```

### Fonction principale
```python
hex_dump(binary_path: str, offset: int = 0, length: int = 512) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "offset": "0x1000", "length": 512 }
```

### Output
```json
{
  "rows": [{ "offset": "0x00001000", "hex": "55 48 89 e5 ...", "ascii": "UH.." }],
  "sections": [{
    "name": ".text", "offset": 4096, "virtual_address": 4198400,
    "size": 8192, "type": "code|data|bss|other"
  }],
  "file_size": 16384
}
```

### Deps
`lief` (optionnel)

---

## import_xrefs

**Trouve tous les call sites** d'une fonction importée (résolution PLT/GOT/dyld).

```
tool: find_import_callsites
```

### Fonction principale
```python
find_callsites(binary_path: str, fn_name: str) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "function": "printf" }
```

### Output
```json
{
  "function": "printf",
  "plt_addr": "0x100000928",
  "callsites": [{
    "addr": "0x1000004d8",
    "text": "e8 4b 04 00 00       call     0x100000928",
    "line": null
  }],
  "error": null
}
```

### Note
Supporte ELF (PLT), Mach-O (dyld stubs), PE (IAT). Parse les lignes disasm depuis le cache.

### Deps
`re`, `call_graph`, `cache`

---

## imports_analysis

**Analyse des imports** pour patterns suspects (injection, réseau, anti-debug, exécution arbitraire).

```
tool: analyze_imports
```

### Fonction principale
```python
analyze_imports(binary_path: str) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "imports": [{ "dll": "kernel32.dll", "functions": ["CreateProcess", "VirtualAlloc"], "count": 2 }],
  "suspicious": [{
    "function": "VirtualAlloc",
    "dll": "kernel32.dll",
    "category": "INJECTION|NETWORK|ANTI_DEBUG|PROCESS|CRYPTO|MEMORY",
    "description": "Alloue mémoire exécutable"
  }],
  "score": 45
}
```

### Score
0-100 : somme pondérée par catégorie (INJECTION=30, ANTI_DEBUG=25, NETWORK=15, CRYPTO=15, etc.)

### Deps
`lief` (requis), `cache`

---

## offset_to_vaddr

**Conversion offset fichier ↔ adresse virtuelle** (ELF/Mach-O/PE). Utile pour synchroniser hex view et désassemblage.

```
tool: offset_to_vaddr
```

### Fonctions principales
```python
offset_to_vaddr(binary_path: str, file_offset: int) -> Optional[int]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "offset": "0x1000" }
```

### Output
```json
{ "file_offset": 4096, "vaddr": "0x401000" }
```

### Deps
`struct`, `lief` (optionnel)

---

## packer_detect

**Capacite pluginisee** de detection de packers et protecteurs.

```
tool: detect_packers
```

### Statut host public
- outil MCP natif retire du repo public ;
- attendu via un plugin `MALWARE` ou `OFFENSIF` selon le packaging choisi ;
- accessible via `plugin_invoke` ou via un outil dynamique `plugin.*` si le plugin le publie.

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "plugin": "MALWARE|OFFENSIF",
  "result": {
    "packers": [{
      "name": "UPX",
      "confidence": "high|medium|low",
      "offsets": [{ "signature": "UPX!", "offset": "0x0" }],
      "reason": "Magic bytes found"
    }],
    "score": 90
  }
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## pof_cache

**CLI de gestion du cache** `.pfdb` : liste, stats, purge des entrées.

```
tool: cache_list / cache_stats / cache_purge
```

### Fonctions principales
```python
list_binaries(db_path: str) -> list[dict]
db_stats(db_path: str) -> dict
purge_binary(db_path: str, binary_path=None) -> int  # 0=all, int=deleted
```

### Output (list)
```json
[{
  "id": 1, "path": "/abs/path/binary", "hash": "...",
  "created_at": "2026-03-01T12:00:00",
  "disasm_lines": 299, "symbols": 12, "strings": 47, "annotations": 3
}]
```

### Output (stats)
```json
{
  "db_path": "/abs/storage/pfdb/binary.0123abcd4567ef89.pfdb",
  "size_bytes": 204800, "size_human": "200 KB",
  "binaries": 3, "total_disasm_lines": 12000
}
```

### Deps
`sqlite3`

---

## repl

**Exécuteur de scripts Python sandboxé** avec timeout. Expose le binaire analysé via la variable `binary` (lief).

```
tool: execute_script
```

### Fonction principale
```python
execute_script(code: str, binary_path: str, timeout: int = 30) -> dict
```

### Input MCP
```json
{ "code": "print([s.name for s in binary.sections])", "binary_path": "/abs/path/binary", "timeout": 30 }
```

### Output
```json
{ "ok": true, "stdout": "['.text', '.data', '.bss']", "stderr": "", "duration_ms": 42 }
```

### Note
Le code est encodé en base64 en CLI : `--code $(echo 'print(binary)' | base64)`.

### Deps
`base64`, `concurrent.futures`, `lief` (dans le sandbox)

---

## rop_gadgets

**Recherche de gadgets ROP** : scanne les bytes `ret` et désassemble les n instructions précédentes.

```
tool: find_rop_gadgets
```

### Fonction principale
```python
find_gadgets(binary_path: str, arch: str = "x86_64", max_insns: int = 5) -> list[dict]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "arch": "x86_64", "max_insns": 5 }
```

### Output
```json
[{
  "addr": "0x401234",
  "instructions": ["pop rdi", "ret"],
  "type": "pop_ret|pivot|syscall|load_store|arithmetic|generic",
  "regs_modified": ["rdi"]
}]
```

### Deps
`capstone` (optionnel, fallback désactivé si absent)

---

## rules_manager

**Gestion centralisée des règles YARA et capa** : liste, activation/désactivation, ajout de règles utilisateur.

```
tool: rules_list / rules_toggle / rules_add / rules_delete
```

### Fonctions principales
```python
RulesManager(project_root, global_config_path=None)
  .list_rules() -> list[dict]
  .toggle_rule(rule_id, enabled)
  .add_user_rule(name, content, rule_type) -> str
  .delete_user_rule(rule_id)
```

### Output (list)
```json
[{
  "id": "yara_custom_01",
  "name": "detect_xor_loop",
  "type": "yara|capa",
  "source": "user|builtin",
  "enabled": true,
  "path": "/abs/path/rules/detect_xor_loop.yar"
}]
```

### Deps
`json`, `shutil`

---

## search

**Recherche dans le contenu binaire** : texte, hex brut, ou regex.

```
tool: search_binary
```

### Fonction principale
```python
search_in_binary(binary_path, pattern, mode="text", section=None, max_results=None) -> list[dict]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "pattern": "flag{", "mode": "text|hex|regex", "section": ".rodata" }
```

### Output
```json
[{
  "offset": 8192,
  "offset_hex": "0x2000",
  "value": "flag{test_value}",
  "context": "...surrounding bytes..."
}]
```

### Deps
`re`, `sections`

---

## sections

**Extraction de la table des sections** (ELF/Mach-O/PE).

```
tool: get_sections
```

### Fonction principale
```python
extract_sections(binary_path: str) -> list[dict]
get_section_file_ranges(binary_path: str) -> list[tuple[str, int, int]]  # (name, start, end)
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "sections": [{
    "idx": 0, "name": ".text",
    "size": 8192, "size_hex": "0x2000",
    "vma": 4198400, "vma_hex": "0x401000",
    "type": "TEXT|DATA|RODATA|BSS|UNKNOWN",
    "offset": 4096,
    "segment": "__TEXT"
  }]
}
```

### Deps
`lief` (requis)

---

## stack_frame

**Analyse du stack frame** d'une fonction : variables locales (rbp-N), arguments (rbp+N), noms depuis DWARF.

```
tool: analyze_stack_frame
```

### Fonction principale
```python
analyse_stack_frame(binary_path: str, func_addr: str) -> dict
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "func_addr": "0x401166" }
```

### Output
```json
{
  "func_addr": "0x401166",
  "frame_size": 32,
  "vars": [{ "name": "local_8", "offset": -8, "size": 8, "source": "auto|dwarf" }],
  "args": [{ "name": "arg_0", "offset": 16, "size": 8, "source": "auto" }]
}
```

### Deps
`lief` (requis), `capstone` (requis), `dwarf` (optionnel)

---

## string_deobfuscate

**Déobfuscation de strings** : XOR (clé simple et multi-octets), ROT, Base64, stackstrings x86-64/ARM64.

```
tool: deobfuscate_strings
```

### Fonction principale
```python
deobfuscate_strings(binary_path: str) -> list[dict]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
[{
  "addr": "0x401200",
  "raw_hex": "41 42 43",
  "decoded": "ABC",
  "method": "XOR-0x41|XOR-multi-key|base64|base64url|stackstring|stackstring-arm64|ROT-13",
  "confidence": "high|medium|low"
}]
```

### Deps
`re`, `base64`, `backends.shared.utils`

---

## strings

**Extraction de strings** du binaire (UTF-8, UTF-16-LE/BE) avec adresses.

```
tool: extract_strings
```

### Fonctions principales
```python
extract_strings(binary_path, min_len=4, encoding="utf-8", section=None) -> list[dict]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "min_len": 4, "encoding": "utf-8", "section": ".rodata" }
```

### Output
```json
[{ "addr": "0x402000", "value": "/etc/passwd", "length": 11 }]
```

### Deps
`re`, `subprocess`, `backends.shared.utils`

---

## symbols

**Extraction de la table des symboles** (ELF nm-style, Mach-O, PE exports).

```
tool: get_symbols
```

### Fonction principale
```python
extract_symbols(binary_path: str, defined_only: bool = True) -> list[dict]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "all": false }
```

### Output
```json
{
  "symbols": [{
    "name": "check_password",
    "addr": "0x4011a6",
    "type": "T|D|B|U|W|A|?"
  }]
}
```

### Types de symboles
| Type | Signification |
|------|--------------|
| `T` | Code (.text) |
| `D` | Données initialisées |
| `B` | BSS (non initialisé) |
| `U` | Non défini (externe) |
| `W` | Weak symbol |

### Deps
`lief` (requis)

---

## taint

**Capacite pluginisee** d'analyse taint source → sink pour prioriser les chemins de donnees suspects.

```
tool: taint_analysis
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `AUDIT` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.audit.taint.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "plugin": "AUDIT",
  "command": "audit.taint.run",
  "result": {
    "flows": [{
      "source_fn": "fgets",
      "sink_fn": "system",
      "confidence": "HIGH|MEDIUM|LOW"
    }],
    "risk_score": 85
  }
}
```

### Sources connues
`read`, `fgets`, `recv`, `scanf`, `getenv`, `fread`...

### Sinks connus
`system`, `exec*`, `write`, `send`, `strcpy`, `sprintf`...

### Deps
Host public : aucune dependance native optionnelle.

---

## vuln_patterns

**Capacite pluginisee** de detection de patterns de vulnerabilites avec niveaux de preuve et mapping CWE.

```
tool: find_vulnerabilities
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `AUDIT` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.audit.vulns.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/binary" }
```

### Output
```json
{
  "plugin": "AUDIT",
  "command": "audit.vulns.run",
  "result": {
    "vulnerabilities": [{
      "type": "Buffer Overflow",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "gets() ne verifie pas la taille du buffer",
      "cwe": "CWE-121",
      "addr": "0x401020",
      "function": "gets"
    }],
    "count": 3
  }
}
```

### Fonctions surveillées
`gets` (CWE-121), `strcpy` (CWE-120), `system` (CWE-78), `sprintf` (CWE-134), `scanf` (CWE-120)...

### Deps
Host public : aucune dependance native optionnelle.

---

## xrefs

**Cross-références** : qui appelle/référence une adresse, ou quelles adresses une instruction cible.

```
tool: get_xrefs
```

### Fonctions principales
```python
extract_xrefs(lines, target_addr, include_data=True) -> list[dict]
build_xref_map(lines, include_data=True) -> dict  # {target: [ref, ...]}
extract_xrefs_from_addr(lines, from_addr) -> list[str]
```

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "addr": "0x401166", "mode": "to|from|map" }
```

### Output (mode `to`)
```json
{
  "addr": "0x401166",
  "mode": "to",
  "refs": [{
    "from_addr": "0x401354",
    "from_line": 42,
    "text": "e8 0d fe ff ff       call     0x401166",
    "type": "call|jmp|jcc|load|store|lea"
  }]
}
```

### Output (mode `from`)
```json
{ "addr": "0x401166", "mode": "from", "targets": ["0x401020", "0x401060"] }
```

### Deps
`re`, `cfg`

---

## yara_scan

**Capacite pluginisee** de scan YARA sur un binaire.

```
tool: yara_scan
```

### Statut host public
- outil MCP natif retire du repo public ;
- disponible via `plugin_invoke` si le plugin `MALWARE` est actif ;
- peut aussi etre publie dynamiquement comme `plugin.malware.yara.run`.

### Input MCP
```json
{ "binary_path": "/abs/path/binary", "rules_path": "/path/to/rules.yar", "timeout": 60 }
```

### Output
```json
{
  "plugin": "MALWARE",
  "command": "malware.yara.run",
  "result": {
    "matches": [{
      "rule": "detect_xor_loop",
      "tags": ["obfuscation"],
      "matches": [{ "offset": 4096, "offset_hex": "0x1000", "matched": "41 42 43" }]
    }],
    "error": null
  }
}
```

### Deps
Host public : aucune dependance native optionnelle.

---

## find_files

**Recherche de fichiers** dans le workspace MCP (nom exact, substring, ou glob).

```
tool: find_files
```

### Fonction principale
```python
find_files(query: str, limit: int = 20) -> dict
```

### Input MCP
```json
{ "query": "demo_analysis.elf", "limit": 20 }
```

### Output
```json
{
  "ok": true,
  "query": "demo_analysis.elf",
  "count": 1,
  "truncated": false,
  "root": "/abs/workspace/root",
  "results": [{
    "path": "/abs/workspace/root/examples/demo_analysis.elf",
    "relative_path": "examples/demo_analysis.elf"
  }]
}
```

### Deps
`os`, `fnmatch`

---

## Matrice des outils MCP recommandés

| Priorité | Tool name MCP | Module | Dépendances |
|----------|--------------|--------|-------------|
| 🔥🔥🔥 | `get_binary_info` | `headers` | lief |
| 🔥🔥🔥 | `disassemble` | `disasm` | lief, capstone |
| 🔥🔥🔥 | `get_xrefs` | `xrefs` | re, cfg |
| 🔥🔥🔥 | `build_cfg` | `cfg` | lief |
| 🔥🔥🔥 | `get_exports` | `binary_exports` | lief |
| 🔥🔥🔥 | `analyze_imports` | `imports_analysis` | lief |
| 🔥🔥 | `extract_strings` | `strings` | re |
| 🔥🔥 | `get_symbols` | `symbols` | lief |
| 🔥🔥 | `find_import_callsites` | `import_xrefs` | re, call_graph |
| 🔥🔥 | `compare_functions` | `func_similarity` | hashlib |
| 🔥🔥 | `decompile_function` | `decompile` | r2/ghidra |
| 🔥🔥 | `find_vulnerabilities` | `vuln_patterns` | lief |
| 🔥🔥 | `taint_analysis` | `taint` | lief |
| 🔥 | `analyze_behavior` | `behavior` | lief |
| 🔥 | `analyze_entropy` | `entropy` | lief |
| 🔥 | `detect_packers` | `packer_detect` | lief |
| 🔥 | `find_rop_gadgets` | `rop_gadgets` | capstone |
| 🔥 | `deobfuscate_strings` | `string_deobfuscate` | re |
| 🔥 | `detect_anti_analysis` | `anti_analysis` | lief |
| 🔥 | `discover_functions` | `discover_functions` | lief |
| ⭐ | `flirt_scan` | `flirt` | — |
| ⭐ | `capa_scan` | `capa_scan` | capa CLI |
| ⭐ | `yara_scan` | `yara_scan` | yara CLI |
| ⭐ | `analyze_stack_frame` | `stack_frame` | lief, capstone |
| ⭐ | `extract_dwarf` | `dwarf` | pyelftools |
| ⭐ | `hex_dump` | `hex_view` | lief |
| ⭐ | `patch_binary` | `binary_patch` | — |
| ⭐ | `execute_script` | `repl` | lief |
| ⭐ | `diff_binaries` | `bindiff` | lief, capstone |
| ⭐ | `search_binary` | `search` | re |
| ⭐ | `offset_to_vaddr` | `offset_to_vaddr` | lief |
| ⭐ | `find_files` | `mcp.server` | os, fnmatch |
