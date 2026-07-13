# loadtest

Load-testing tool for the backend analysis scripts in `extension/backends/`
(disasm, strings, symbols). It generates synthetic binaries at a few sizes,
runs each backend script against them as a real subprocess, and measures
peak RSS and wall-clock time via `/usr/bin/time`. Results are reported as a
summary table and a JSON file, with a pass/fail threshold on the RAM ratio
(peak RSS / binary size).

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

By default this runs every scenario against every fixture profile. Flags
(all optional):

```bash
python3 -m tooling.loadtest --scenario disasm --size small
python3 -m tooling.loadtest --scenario strings
python3 -m tooling.loadtest --size large
python3 -m tooling.loadtest --results-dir /tmp/my-results
python3 -m tooling.loadtest --max-ratio 50
```

- `--scenario NAME` — run a single scenario (see `SCENARIOS` in
  `scenarios.py` for the current names: `disasm`, `strings`, `symbols`).
  Default: run all of them.
- `--size NAME` — run a single fixture profile (see `FIXTURE_PROFILES` in
  `scenarios.py` for the current names: `small`, `medium`, `large`).
  Default: run all of them.
- `--results-dir DIR` — where the JSON report is written. Default:
  `tooling/loadtest/.results/` (gitignored).
- `--max-ratio RATIO` — the peak-RSS/binary-size ratio above which a
  result is flagged as `exceeded`. Default: `500.0`.

Exit code: `0` if every result is `ok`, `1` if any scenario `exceeded` its
ratio or crashed (`returncode != 0`) or timed out, `2` for a bad
`--scenario`/`--size` name (unknown scenario/profile).

The JSON report (one file per run, under the results dir) and the printed
summary table both retain each result's binary size, peak RSS, elapsed
time, and status.

## Known limitations

These are deliberate, known gaps — not oversights — flagged during review
and deferred rather than fixed as part of the current scope.

1. **The default RAM ratio threshold is nearly blind on the `small`
   fixture profile.** `DEFAULT_MAX_RATIO = 500.0` in `__main__.py` is a pure
   ratio (peak RSS / binary size), with no baseline subtraction. A bare
   Python interpreter running any of these backend scripts has roughly
   200-230MB of fixed overhead (module imports, etc.), which dwarfs the
   `small` fixture's ~1MB size. That means a script would need to leak
   ~500MB above its already-large fixed overhead before the tool would
   ever flag it as `exceeded` on `small`. If you're relying on this tool
   to catch small regressions on the `small` profile specifically, it
   won't today — the ratio-based check is only meaningfully sensitive on
   `medium` and `large`, where the binary itself is large enough to
   dominate the interpreter's fixed overhead. A better design would
   measure the interpreter's baseline overhead once and ratio only the
   delta above that baseline; that wasn't built here.

2. **The CLI's exit code collapses two different severities into exit
   code `1`.** A scenario that genuinely crashed (`returncode != 0`) and a
   scenario that merely exceeded the RAM ratio (a softer signal) both
   produce exit code `1`. If you're wiring this into CI and only look at
   the exit code, you can't tell a real crash from a soft RAM-ratio
   warning. The distinction is preserved in the JSON report and the
   summary table via `check_threshold`'s four possible statuses — `ok`,
   `exceeded`, `error`, `timeout` — so check the JSON report (or the
   printed table) if you need to react differently to a crash than to a
   ratio warning.

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
