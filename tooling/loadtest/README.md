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
python3 -m tooling.loadtest --memory-limit-mib 1536 --timeout-cap-s 60
python3 -m tooling.loadtest --binary /path/to/corpus.elf --size large
python3 -m tooling.loadtest --baseline tooling/loadtest/baselines/ubuntu-medium.json
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
- `--baseline FILE` — compare each scenario/profile with a promoted median
  baseline. More than +20% is a warning and more than +35% is a blocking
  `regression_limit`, even when the absolute budget still passes.
- `--memory-limit-mib` and `--timeout-cap-s` — hard per-process safety guards,
  defaulting to 1.5 GiB and 60 seconds. The memory guard watches the combined
  RSS of the complete process tree and kills its process group at the limit.
  A breach is reported as `memory_limit`, separately from `timeout` and a
  normal backend error.
- `--binary FILE` — measure an existing binary instead of generating a
  synthetic fixture. `--size` is then mandatory and selects the applicable
  budget profile. The report records the external filename and SHA-256.

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

Promote a baseline only from at least three complete reports produced by the
same machine architecture and Python minor version:

```bash
python3 -m tooling.loadtest.baseline run1.json run2.json run3.json \
  --output tooling/loadtest/baselines/ubuntu-medium.json
```

The command uses the median RSS and duration for every scenario/profile. It
rejects fewer than three samples, mixed environments, and different scenario
sets. This prevents a single noisy run or an incomplete matrix from becoming
the CI reference. Failed reports are rejected, and the loadtest refuses a
baseline whose architecture, Python minor version, or scenario coverage does
not match the current run.

The blocking Ubuntu medium job uses
`baselines/ubuntu-latest-python311-medium.json`, promoted from three successful
GitHub-hosted runner reports. Updating it requires the same three-report
promotion process; a single faster or slower run must never replace it.

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

## Large compiled corpus

The `Large Real Corpus Loadtest` workflow runs every Monday and can also be
started manually. It compiles the shared real-analysis corpus for x86_64,
ARM64, MIPS32, PowerPC 32 and RISC-V64, adds a deterministic ELF data section
until the file reaches about 100 MiB, then runs each architecture in its own
guarded job. Generated
binaries are never committed. Each job enforces the 1.5 GiB process-tree
limit, the 60 second per-scenario cap, and the absolute `large` budgets.

To build the same corpus on Ubuntu with the native and cross toolchains:

```bash
python3 -m tooling.loadtest.real_corpus \
  --arch arm64 --size-mib 100 --output /tmp/corpus-arm64.elf
python3 -m tooling.loadtest \
  --binary /tmp/corpus-arm64.elf --size large
```

## Known limitations

These are deliberate, known gaps — not oversights — flagged during review
and deferred rather than fixed as part of the current scope.

1. **The budgets include Python's fixed startup/import overhead.** They are
   deliberately absolute and initially generous. The promoted median baseline
   catches regressions on equivalent CI runners, but it does not remove that
   fixed cost from the absolute RSS values.

2. **`function_radar` on the large profile still exposes performance
   pressure.** The guarded local validation completed below the blocking
   limits, but remained above the 768 MiB warning budget. The hard 1.5 GiB
   process-tree guard prevents the historical unbounded-memory failure mode;
   the warning remains visible as an optimization target.

3. **The compiled corpus combines real code with deterministic data.** It
   covers binary format and architecture differences at 100 MiB, but does not
   reproduce the code complexity of a naturally occurring 100 MiB program.
   Curated redistributable production samples remain a useful future layer.

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
