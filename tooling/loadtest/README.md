# loadtest

Load-testing tool for the public backend analysis scripts in
`extension/backends/`. It generates synthetic binaries at a few sizes, runs
each backend script against them as a real subprocess, and measures peak RSS
and wall-clock time via `/usr/bin/time`. Results are reported as a summary
table and a versioned JSON file. Each fixture profile has explicit warning and
failure budgets for peak RSS and wall-clock duration. The historical RAM ratio
can still be enabled as an optional additional guard.

## Why this exists

A real incident once drove VS Code to ~40GB RAM while opening a 200MB
binary. That specific incident turned out to be caused by a UI infinite
loop, unrelated to the backend scripts, and was fixed separately. But it
pointed at a real, ongoing risk: a backend analysis script (disasm,
strings, symbols, ...) could use way more RAM than expected on a large
binary, and nothing catches that kind of regression before release. This
tool exists to catch that general class of problem — not to reproduce the
original incident.

## Usage

Run from the workspace root (`Pile_Ou_Face/`), as a module:

```bash
python3 -m tooling.loadtest
```

By default this runs every registered public-host scenario against every
fixture profile. Flags (all optional):

```bash
python3 -m tooling.loadtest --scenario disasm --size small
python3 -m tooling.loadtest --scenario strings
python3 -m tooling.loadtest --size large
python3 -m tooling.loadtest --results-dir /tmp/my-results
python3 -m tooling.loadtest --max-ratio 50
```

- `--scenario NAME` — run a single scenario. Default: run all of them.
  Current names: `disasm`, `strings`, `symbols`, `headers`, `sections`,
  `imports`, `entropy`, `hex_view`, `pe_resources`,
  `exception_handlers`, `analysis_index`, `function_radar`, `cfg`,
  `call_graph`, `xrefs_map`.
- `--size NAME` — run a single fixture profile (see `FIXTURE_PROFILES` in
  `scenarios.py` for the current names: `small`, `medium`, `large`).
  Default: run all of them.
- `--results-dir DIR` — where the JSON report is written. Default:
  `tooling/loadtest/.results/` (gitignored).
- `--max-ratio RATIO` — optional legacy peak-RSS/binary-size guard. It is
  disabled by default because fixed Python startup costs make this ratio
  misleading, especially for small files.

Default budgets:

| Profile | RSS warning | RSS failure | Duration warning | Duration failure |
|---|---:|---:|---:|---:|
| `small` (~1 MB) | 192 MB | 256 MB | 1.5 s | 3 s |
| `medium` (~20 MB) | 256 MB | 384 MB | 2 s | 5 s |
| `large` (~200 MB) | 768 MB | 1 GB | 10 s | 30 s |

Scenario-specific calibration: `entropy` on the `medium` profile uses a 4 s
duration warning and an 8 s failure limit. Its full byte-by-byte scan measured
5.85 s on the GitHub-hosted Linux runner; the other medium scenarios keep the
stricter generic 2 s / 5 s limits.

Exit code: `0` for `ok` and `warning` results, `1` for `memory_limit`,
`duration_limit`, `error`, or `timeout`, and `2` for an unknown scenario or
profile. The JSON records the exact reasons, budgets, environment metadata,
RSS ratio, and status for every result.

The JSON report (one file per run, under the results dir) and the printed
summary table both retain each result's binary size, peak RSS, elapsed
time, and status.

## Coverage

The current registry covers public host backends that can run locally from a
synthetic binary:

- Binary metadata: `headers`, `sections`, `symbols`, `imports`,
  `pe_resources`, `exception_handlers`.
- Search/byte views: `strings`, `entropy`, `hex_view`.
- Disassembly graph paths: `disasm`, `cfg`, `call_graph`, `xrefs_map`.
- Higher-level indexes: `analysis_index`, `function_radar`.

The mapping-based scenarios (`cfg`, `call_graph`, `xrefs_map`) prepare a
temporary disassembly mapping first, then measure only the target backend.
That keeps the RSS number focused on the feature being audited instead of on
the preparation step.

Plugins are not included in this public-host loadtest. Plugin scenarios need
explicit plugin entrypoints, installed plugin bundles, license/auth state if
required, and their external tool dependencies. Add those as a separate
plugin-aware registry rather than mixing them into this public host matrix.

## Known limitations

These are deliberate, known gaps — not oversights — flagged during review
and deferred rather than fixed as part of the current scope.

1. **The budgets include Python's fixed startup/import overhead.** They are
   deliberately absolute and initially generous. A future baseline system
   should compare median and p95 regressions on equivalent CI runners.

2. **Some large-profile scenarios currently expose real performance
   pressure.** On local validation, `strings` in its default auto-encoding
   mode timed out on the `large` profile even with a 300s timeout, and
   `function_radar` reached tens of GB of peak RSS. That is not hidden by
   the tool: those results should be treated as audit findings unless the
   backend behavior is intentionally changed or the scenario is deliberately
   split into a faster bounded variant.

3. **Synthetic padding controls size, not representative complexity.** A
   real 100–200 MB corpus per architecture is still required before #56 can
   claim production performance coverage.

## Adding a new scenario

Scenarios live in `scenarios.py` as `Scenario` dataclass instances in the
`SCENARIOS` tuple: `name`, `script` (path relative to `extension/`),
`build_args` (a `(binary_path, out_dir) -> list[str]` callable producing
the script's CLI args), and an optional `timeout_s` (default 120s). Add a
new `Scenario(...)` entry with a small `_xxx_args` helper function
alongside the existing ones (`_disasm_args`, `_strings_args`,
`_symbols_args`) for reference.

## Design doc

For the full rationale behind these design decisions, see the design doc
in this worktree if present: `docs/plans/2026-07-12-loadtest-tooling-design.md`.
It's a local, gitignored planning file, not a committed doc — this pointer
is only useful if you're working in the same worktree it was written in.
