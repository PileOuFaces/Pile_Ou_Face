# AGENTS.md

This file provides guidance to Codex when working with code in this repository.

## Project Type

This repository is the **public host repo** of the product.

The product combines:

- a public VS Code extension host
- public Python static-analysis backends
- optional external plugin integrations surfaced by the host

This repo owns:

- the extension shell
- webviews and UX
- public backend orchestration
- cache / workspace behavior
- public contract surfaces exposed by the host

Do not assume every optional capability visible in the UI is implemented in this repository.

## First Read

Before making non-trivial changes, read:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Public Boundary Rule

In this public repo:

- you may document host-visible plugin capabilities
- you may edit public payloads, handlers, routing, and UX for plugin-backed features
- you must not document external implementation details, plugin internals, packaging internals, or plugin roadmap specifics

Keep documentation scoped to what the public host owns or guarantees.

## Integration Surface Rule

Treat these as public integration surfaces:

- plugin runtime command names
- MCP / capability names
- JSON payloads exchanged between the host and optional plugin integrations
- `proof_dossiers`, `confidence`, `evidence`, `needs_review`, `related`, `next_steps`
- exported dossier schemas
- support / availability semantics shown in the UI

Valid `kind` values currently rendered by the host:
- `TAINT_SIGNAL`, `TAINT_REACHABLE`, `TAINT_CONFIRMED` — taint analysis (XSYNC-002)
- `FUNC_SIMILARITY` — function similarity
- `NETWORK`, `FLIRT`, `BINDIFF` — other plugin kinds

When these change, keep docs focused on the public contract and avoid describing external implementation details here.

## What This Is

VS Code extension for binary reverse engineering (ELF/PE/Mach-O, x86/x64/ARM64). It replaces scattered tooling with an integrated hub. The product has two main layers: a Node.js extension and Python backends invoked as subprocesses.

## Commands

```bash
make install                          # venv + pip deps (backends/.venv)
make test                             # all Python + JS tests
make demo                             # compile examples/demo_analysis.c
make demo-elf                         # compile ELF via Docker (for Capa on macOS)
PYTHONPATH=. backends/.venv/bin/python3 -m unittest backends.static.tests.<module>
PYTHONPATH=. backends/.venv/bin/python3 -m unittest backends.static.tests.test_decompile -v

# Docker decompilers
make decompiler-docker-build DECOMPILER=ghidra
make decompiler-docker-list  DECOMPILER=ghidra
make decompiler-smoke-test   DECOMPILER=ghidra
make decompilers-docker-build-all
make decompilers-smoke-test-all
```

## Architecture

### Extension -> Python

The extension calls Python backends through `execFile` / `spawn` from the extension layer (`staticHandlers.js`, `hub.js`). Each tab maps to an independent Python script invoked with `--binary <path>` and returning JSON on stdout. The helper `runPython(argsWithScript)` in `staticHandlers.js` prefixes the script path using the project `cwd`.

The webview is assembled at runtime. `webview.js` reads `hub.html` plus fragment files through `fs.readFileSync` and injects them via `{{placeholder}}` tokens. Do not look for a generated frontend bundle.

### Decompile Engine (`backends/static/decompile/`)

Two-level configuration:

```text
.pile-ou-face/decompilers.json     <- host config (docker_image, docker_command, quality_bias)
docker/decompilers/<tool>/
  Dockerfile
  decompile.py                     <- tool-specific adapter
  decompilers.json                 <- config embedded in the container
  requirements.txt
```

`decompile.py` is generic. It reads `.pile-ou-face/decompilers.json`, detects local or Docker availability, parallelizes with `concurrent.futures.ThreadPoolExecutor`, and routes to the best result. Tool-specific logic stays in `docker/decompilers/<tool>/decompile.py`.

The engine can run as a module (`python -m backends.static.decompile`) or as a direct script (`decompile.py`). A `runpy` shim at the bottom supports both entry paths.

Adding a decompiler should not require editing the engine. Create `docker/decompilers/<name>/` and add an entry in `.pile-ou-face/decompilers.json`.

### Decompile Tests

Decompiler mocks in tests use neutral names such as `tool_a` and `tool_b`. Do not reintroduce concrete tool names into generic test fixtures.

### Annotations

Annotations are stored in `.pile-ou-face/annotations/<sha256(abspath+mtime)>.json`. The `hubAnnotationSaved` message triggers a disassembly rerun and invalidates CFG and callgraph cache entries.

## Key Structure

```text
extension/src/static/   - staticHandlers.js (webview handlers), hub.js (panel init)
extension/webview/      - hub.html/js/css (main shell, not generated)
backends/static/
  decompile/            - generic multi-decompiler engine
  disasm/               - disasm, cfg, call_graph, stack_frame, xrefs
  binary/               - headers, symbols, sections, entropy, imports
  analysis/             - behavior, taint, capa_scan, vuln_patterns, flirt
  annotations/          - annotations, structs, typed_struct_refs
  search/               - strings, hex_view, rop_gadgets, yara_scan
  tests/                - unittest, fixtures/, run_tests.py
docker/decompilers/     - Dockerfiles and adapters (ghidra, angr, retdec)
.pile-ou-face/          - runtime config (decompilers.json, annotations/, cache)
```

`backends/static/pof/` has been removed. Do not recreate it.

## Decompiler Status

| Decompiler | Status | Notes |
| --- | --- | --- |
| RetDec | OK | `--platform linux/amd64` is forced in `docker_extra_args` |
| Angr | OK | arm64 and amd64 |
| Ghidra | OK | Uses `analyzeHeadless -postScript` plus Jython (`docker/decompilers/ghidra/script.py`) to avoid the arm64 `decompileCompleted=False` issue |

## Git Workflow

- Active branch pattern: `feature/<name>` from `develops`
- Merge through PR only
- Do not commit directly to `develops` or `main`

## Codex Workflow

When the task is non-trivial, use the role prompts in `.codex/agents/` as a working checklist:

- `orchestrator.md`
- `planner.md`
- `architect.md`
- `worker-specialized.md`
- `tester.md`
- `security-reviewer.md`
- `reviewer.md`
- `documentation-writer.md`
- `final-summary.md`

These files are guidance artifacts for consistent execution and handoff quality. They should help scope work tightly, keep validations honest, and preserve the repo's conventions.

## Graphify

This project has a graphify knowledge graph in `graphify-out/`.

Rules:

- Before answering architecture or codebase questions, read `graphify-out/GRAPH_REPORT.md` for hubs and community structure.
- For cross-module relations, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over raw text search when graphify is available.
- After modifying code files in a session, run `graphify update .` to keep the graph current.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **Pile_Ou_Face** (19649 symbols, 33073 relationships, 268 execution flows). GitNexus is the current implementation of the preferred repository-analysis tool, when it is actually available in the session and usable for this repository.

## Availability Gate

Before requiring the preferred repository-analysis tool, explicitly verify at least one usable access path:

- its MCP tools or resources are accessible in the current session;
- a functional CLI is installed;
- the repository contains a configuration that can actually be executed with the runtimes available in the session.

A configuration or skill directory that points to a missing executable does not make the tool available. Report the availability result before relying on it.

An optional tool must not block work when it is not installed, accessible, or configured and no installation procedure has been provided. In that case, use the documented manual fallback below.

If GitNexus is available but warns that its index is stale, run `npx gitnexus analyze` in the terminal before using its results.

## When the Preferred Tool Is Available

- Before modifying a public symbol, shared function, class, contract, route, model, or schema, run upstream impact analysis and inspect its context.
- Summarize incoming and outgoing dependencies and identify affected tests.
- Warn the user before editing when the reported risk is HIGH or CRITICAL.
- Run the tool's changed-symbol or changed-flow analysis before committing when supported.
- Prefer graph-aware rename and navigation operations over blind find-and-replace.

With the current GitNexus implementation, use `gitnexus_impact`, `gitnexus_context`, `gitnexus_query`, `gitnexus_rename`, and `gitnexus_detect_changes` for those operations.

## Manual Fallback When the Preferred Tool Is Unavailable

State clearly that the preferred repository-analysis tool is unavailable. The following procedure is then mandatory:

1. Search all definitions and references with the available tools, including `rg` or `grep`, IDE search, imports, direct calls, tests, templates, URLs, configuration, and documentation.
2. For every modified symbol, document:
   - its definition file;
   - references found;
   - primary callers;
   - possible side effects;
   - existing tests;
   - tests to add or modify.
3. Run, at minimum:
   - targeted tests;
   - the complete test suite of the affected module;
   - lint;
   - format checks;
   - compilation or type checking when available.
4. If the remaining impact is ambiguous or affects a cross-cutting contract, stop before editing and request human validation.
5. Never describe this manual analysis as equivalent to the preferred repository-analysis tool. It is an explicit, documented fallback.

Before committing without the preferred tool, record the changed-symbol review and validation results in place of the tool-specific changed-flow analysis.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/Pile_Ou_Face/context` | Codebase overview, check index freshness |
| `gitnexus://repo/Pile_Ou_Face/clusters` | All functional areas |
| `gitnexus://repo/Pile_Ou_Face/processes` | All execution flows |
| `gitnexus://repo/Pile_Ou_Face/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
