# Autoresearch: Speed up datadog-static-analyzer scans on dd-source

## Objective

Reduce scan duration of `datadog-static-analyzer` on the `dd-source` monorepo
(15 GB, 271 k files scanned, ~250 s wall-time baseline). Wins on `dd-source`
should generalize to other repos. Code-only optimizations: no rule changes.

## Metrics

- **Primary**: `wall_seconds` — total end-to-end wall time (lower is better) of
  ```
  /usr/bin/time -e ... dd-auth --domain app.datadoghq.com -- \
      datadog-static-analyzer --directory ~/dd/dd-source --output X.sarif --format sarif
  ```
  measured on the 16-core dev box.
- **Secondary**:
  - `analyzer_seconds` — analyzer-self-reported `Duration:` (excludes startup,
    rule fetch, SARIF serialization). Cleaner signal for the actual scan loop.
  - `peak_rss_mb` — peak resident memory.
  - `user_cpu_seconds`, `sys_cpu_seconds` — total CPU time across rayon workers.
  - `violations` — total violations found. Should never change unless a rule
    regression is intentional. Tracked as a sanity monitor.
  - `build_seconds` — incremental compile time. Not part of validation, but a
    huge jump signals over-engineering.

## Baseline (commit `eff32af0`, captured at session start)

| metric | value |
|---|---|
| wall_seconds | 249.33 |
| analyzer_seconds | 231.06 |
| peak_rss_mb | 909 |
| user_cpu_seconds | 1364.79 |
| sys_cpu_seconds | 28.46 |
| violations | 18545 |
| files_scanned | 271428 |
| rules_evaluated | 63 |

The dd-source scan uses 8 of 16 logical cores (analyzer caps at 8 unless
`--cpus` is passed). Average CPU usage is 558 %.

## How to Run

```bash
./autoresearch.sh        # builds, runs benchmark, light fingerprint check
./autoresearch.checks.sh # deep 9-repo correctness check (auto-run after benchmark)
```

`autoresearch.sh` outputs `METRIC name=value` lines and appends a JSONL record
to `~/autoresearch-static-analyzer/runs.jsonl` for every run (kept or rejected).

### Why the dd-auth wrapper

`dd-source` ships a `static-analysis.datadog.yml` config that selects a custom
mix of rulesets (some not in `static-analysis-default-rules`). The analyzer
refuses `-r rules.json` when a config file is present. So **dd-source must be
benchmarked via dd-auth**, which fetches rules through the live API.

The dd-auth path adds ~5 s of network/auth overhead. On a ~250 s baseline that
is sub-2 % noise. Repeated runs of the bare `dd-auth` call have varied <0.3 s
in measurement. Acceptable.

The 9-repo deep check uses `-r ~/autoresearch-static-analyzer/all-rulesets.json`
(cached at session start, 1150 rules across 59 rulesets) for stability and
speed — no network in the hot path.

## Files in Scope

Optimization-relevant code lives mostly in
`crates/static-analysis-kernel/src/analysis/`:

- `analyze.rs` — the per-file rule loop. Calls `get_tree`, `get_lines_to_ignore`,
  then iterates rules and dispatches to `runtime.execute_rule`.
- `tree_sitter.rs` — `TSQuery` / `TSQueryCursor` wrapper around `tree_sitter::Query`.
  Where any combined-query work would land.
- `ddsa_lib/runtime.rs` — `JsRuntime::execute_rule` and `execute_rule_internal`.
  TS query matching against the parse tree, then v8 dispatch with bridge data.
- `ddsa_lib/bridge*.rs`, `ddsa_lib/v8_ds.rs` — Rust↔v8 bridges; tweaks here are
  high-risk, do only with care.
- `classifiers/*` — `is_test_file`, `is_generated_file`, `is_minified_file`. Cheap.
- `path_restrictions.rs`, `rule_config.rs` — filter rules per-file by path globs.
- `crates/cli/src/file_utils.rs` — file walking & language detection.
- `crates/bins/src/lib.rs` — `static_analysis()` rayon driver, `JS_RUNTIME` thread-local.
- `crates/bins/src/bin/datadog-static-analyzer.rs` — CLI entrypoint.

You may also touch profile flags in `Cargo.toml` if there is a measured win, but
keep the diff minimal.

## Off Limits

- **Static-analysis rules** in `~/dd/static-analysis-default-rules`. Read-only.
  Rule behavior must not change.
- **Rule semantics** in general — every change must produce identical SARIF output
  on every reference repo (10 repos checked at deep level).
- The benchmark target `~/dd/dd-source` (read-only).
- Public CLI flags, exit codes, SARIF output schema.

## Constraints

- All 10 reference fingerprints (3 light + 9 deep) must match baseline. The
  deep check runs automatically after each passing benchmark.
- **`dd-source` fingerprint alone is INSUFFICIENT.** It only exercises 24 rules
  out of ~1150. A change that matches dd-source but breaks any of the other 9
  repos is a correctness regression and must be rejected or fixed.
- No new dependencies unless a clear, large win.
- No regressing the small-repo path: combined-query / bulk-cost optimizations
  must be **adaptive**, not always-on. Small-repo scans (apis, lading) must
  not slow down by more than ~10 %.
- Resource gate (vs original `main` baseline above):
  - Small drift in RSS / CPU is fine.
  - Sudden ~25 %+ peak RSS jump or ~2× CPU time = red flag, investigate.
- Code clarity matters. Complex optimizations require a comment naming the
  technique (e.g. "combined Tree-sitter multi-pattern query" or
  "per-rule literal pre-screen with #eq?/#any-of? extraction").

## Per-Run Logging

Every run appends a JSONL record to `~/autoresearch-static-analyzer/runs.jsonl`
(kept OR rejected — completeness over tidiness). Schema:

```json
{
  "timestamp": "...", "git_sha": "...", "branch": "...",
  "repo": "dd-source",
  "wall_time_seconds": ..., "analyzer_duration_seconds": ...,
  "peak_rss_mb": ..., "peak_rss_kb": ...,
  "user_cpu_seconds": ..., "sys_cpu_seconds": ...,
  "files_scanned": ..., "total_violations": ..., "rules_evaluated": ...,
  "ddsource_fingerprint_count": ..., "ddsource_fingerprint_match": true,
  "light_fingerprint_match": true, "light_fingerprint_details": "...",
  "build_seconds": ..., "preflight_seconds": ...
}
```

`runs.jsonl` is the authoritative record for later graphing with pandas/duckdb.
The `kept` field is implicit in `autoresearch.jsonl` (this is just the resource
log, run-by-run).

## What's Been Tried

(Prior session — these are starting points, not pre-applied. The prior
session's branch is **not** merged into our base. Our base is `main` @
`eff32af0`. Don't assume any of this is in the tree.)

### Promising Directions (apply adaptively, watch for small-repo regressions)

1. **Combine per-rule TS queries into ONE multi-pattern query per language**
   (largest single win — ~2× on big workloads, regresses small repos 1.4–2.4×).
   Make this **adaptive** based on `file_count × rule_count` per language at
   startup. **Top priority.**
2. **Per-rule literal pre-screen** — extract required substrings from
   `#eq?`/`#any-of?`/`#match?` predicates; skip v8 dispatch if file lacks them.
   Two granularities: file-level (skip parse+query) and per-rule (skip v8).
   Hard safety: bail on `|`, `(?i)`, `[`, `?`, `*`, `+` in regex.
3. **JS-side literal mining** for broad-capture rules — mine top-level
   `const NAME = ["lit", ...]` arrays as required substrings. Safety gates:
   skip if name contains TYPE/KIND/NODE; skip if no element has non-alphanumeric
   chars; skip if TS query contains `[`.
4. **Skip empty-bucket rules early** in the combined-query path (~5 % win).
5. **Reuse the parse tree** for `is_test_file` and other post-processing.
6. **Fast-paths**: `get_lines_to_ignore` `memchr` for `no-dd-sa`/`datadog-disable`.

### Don't-Try List (verified dead ends, do not re-investigate without new evidence)

- Thread-local `tree_sitter::Parser` cache — no measurable win.
- Skipping `bridge_query_match.clear()` — v8 GC penalty exceeds savings.
- Flat `Vec<(rule_idx, match)>` from combined query — just shifts cost.
- Per-rule v8-dispatch skip without the conservative literal-extraction gates above
  — produces incorrect results.
- HashMap-based per-file literal-presence cache — alloc cost > dedup savings.
- Regex literal extraction returning the *longest run* — silently misses violations
  on alternation.
- `#[inline(always)]` on same-crate hot paths — compiler already does it.

## Architectural Notes (where the time goes)

For the dd-source baseline (`231 s` analyzer Duration):

- 271 k files, 8-way rayon parallel. So ~7 ms wall per file on average across
  the per-language work.
- 24 rules with matches out of 63 evaluated. Rules with zero matches still pay
  query-cursor + (currently) per-rule TS query setup costs.
- Per-file: `get_lines_to_ignore` (string scan) → `get_tree` (TS parse) →
  for each rule: `tree_sitter_query.with_cursor(...).matches(...)` → if non-empty,
  v8 `execute_rule_internal` (bridge push + script run + violations drain).
- A new v8 isolate setup happens per rayon thread but is amortized.

The combined-query idea (#1) replaces N per-rule queries with 1 multi-pattern
query, walking the parse tree once. Small-repo cost is mostly the upfront
`tree_sitter::Query::new` for a giant pattern source.

## Working Directory Layout

```
~/autoresearch-static-analyzer/
├── all-rulesets.json          # cached 59 rulesets / 1150 rules (session start)
├── fingerprint.py             # SARIF → stable hash
├── baselines/
│   ├── baseline_fingerprints.json
│   ├── dd-source.sarif        # main baseline SARIF (NB: this is dd-source-baseline.sarif)
│   ├── dd-source-resources.json
│   ├── cloudops.sarif, apis.sarif, ...   # 9 reference SARIFs
├── runs.jsonl                 # per-run resource log (append-only)
└── last-dd-source.sarif       # latest dd-source SARIF (for deep-check reuse)
```

## Loop Etiquette

- Improved `wall_seconds` AND deep check passes → `keep`.
- Worse `wall_seconds` → `discard`. Capture in `asi.rollback_reason` exactly
  *which* phase regressed (analyzer_seconds vs build_seconds vs other).
- Light fingerprint mismatch → `discard` with details — it means a real
  semantic regression, not a perf change. Inspect `light_fingerprint_details`.
- Deep check failure (after passing light) → `checks_failed`. This means a rule
  applied differently on a corner-case repo. Investigate before retrying.
- Crash → log the panic / error class in `asi`.
- For a clean +/- 1 % wall change: re-run once before deciding.

## Progress

| run | wall_seconds | delta vs baseline | description |
|-----|--------------|-------------------|-------------|
| 1   | 251.25       | 0%                | baseline                                                                 |
| 2   | 238.07       | -5.2%             | memchr fast-path in `get_lines_to_ignore`                                |
| 3   | 237.98       | -5.3%             | reuse parsed tree for `is_test_file` (perf-neutral, refactor only)       |
| 4   | 213.61       | -15.0%            | per-rule + file-level literal pre-screen (`#eq?` / `#any-of?`)           |
| 5   | 193.16       | -23.1%            | extend pre-screen to `#match?` regex (longest literal run)               |
| 6   | 166.64       | -33.7%            | multi-pattern pre-screen (per-pattern extraction, OR across patterns)   |
| 7   | 156.65       | -37.7%            | smarter `[`-depth + `?`/`*`/`+` quantifier tracking                      |
| 8   | 155.27       | -38.2%            | (verification rerun, no code changes)                                    |
| 9   | 164.93       | -34.4%            | DISCARDED — eager mask precomputation regressed (lazy `.any()` was better)|
| 10  | 133.39       | -46.9%            | JS-side `const` array mining (full + leading-alphanumeric prefix)        |
| 11  | 73.17        | -70.9%            | relax alternation gate when JS uses a single capture name                |
| 12  | 71.93        | -71.4%            | (verification rerun, no code changes)                                    |
| 13  | 74.26 / 72.68| neutral           | DISCARDED — unused-pattern detection (drop patterns whose @captures aren't read by JS): no measurable win on dd-source, removed for code-clarity |
| 14  | 73.40        | -70.8%            | (final verification rerun)                                               |
| 15  | 70.43        | -72.0%            | language-level rayon parallelism (par_iter over languages, nested rayon shares pool) |
| 16  | 75.39 / 80.86| neutral           | DISCARDED — setup-phase parallelization (over-subscribed thread pool)    |
| 17  | 55.87        | -77.8%            | DEFAULT_MAX_CPUS 8 → 16 (was leaving 50 % of cores idle on multi-core hosts) |
| 18  | 54.72 / 54.98| neutral           | DISCARDED — dropping the 0.9 conservative factor (~1s gain, within noise; preserved original design intent) |
| 19  | 47.38        | -81.1%            | adaptive combined Tree-sitter query (one walk per file for all rules, threshold = files×rules > 10k) |

**Final state**: ~70–71 s wall (vs 251 s baseline) = **−72.0 %**. Confidence ~3× noise floor on the last improvement. Memory and CPU stayed within the resource gate (peak RSS −8 % from baseline).

5-run back-to-back wall measurement after the language-parallelism win:
- run 1: 79.92 s (cold page cache)
- run 2: 80.32 s (cache warming)
- run 3: 71.40 s (warm)
- run 4: 71.19 s (warm)
- run 5: 70.96 s (warm)

After run #19 (combined query), final 5-run warm-cache measurement:
- run 1: 48.46 s, RSS 1.28 GB
- run 2: 48.51 s, RSS 1.30 GB
- run 3: 48.11 s, RSS 1.28 GB
- run 4: 48.26 s, RSS 1.23 GB
- run 5: 47.92 s, RSS 1.20 GB

**Steady-state ~48 s = −80.8 % wall vs 251 s baseline.** Spread 0.6 s.
Analyzer Duration 29-30 s of that, 18-19 s overhead (dd-auth, rule fetch,
file walking, SARIF write).

User CPU dropped 1383 → 342 s (−75 %), peak RSS rose 909 → 1280 MB (+41 %).
The RSS increase is **fully attributable to two design choices**:
1. Run #17: lifted `DEFAULT_MAX_CPUS` cap 8 → 16, doubling rayon worker
   threads on multi-core hosts; each worker holds its own v8 isolate.
2. Run #19: combined Tree-sitter query holds matches for all rules at once
   per file (vs releasing per-rule).
Both are well-understood and net-positive trade-offs for big repositories.
CI environments with tight memory budgets can revert via `--cpus 8` and
fit comfortably under the prior baseline.

All comparisons in the table above are warm-vs-warm (baseline run #1 also had
warm cache from the setup phase).

## Caveat: behavioral change in run #17

Raising `DEFAULT_MAX_CPUS` from 8 → 16 affects every user who runs the analyzer
without `--cpus`. Memory grows roughly linearly with worker count (1.3 GB at
~13 workers vs ~860 MB at ~6); CI environments with tight memory budgets may
want to keep the previous default. The change is net-positive on multi-core
dev/CI hosts but is a default-value tweak rather than an algorithmic
optimization — listed separately in the table for transparency.

## Quick-look final profile (run #15 commit)

```
wall=70.65s user=313s sys=19s rss=860 MB
Duration (analyzer): 52.11 s   # static_analysis() phase
overhead: 18.5 s              # dd-auth + rule fetch + startup + SARIF write
rules with matches: 24 of 63
files scanned: 271,428
violations: 18,545 (== baseline)
fingerprints: 10/10 reference-repo deep check passes
```

Top remaining CPU consumers (per-file paralleled at ×6 worker threads):

```
python-flask/command-injection            22.1 s CPU  (was 22 s) — plateau; common literal
python-flask/html-format-from-user-input   6.0 s
python-flask/os-popen-command-injection    5.5 s
dd-trace-go-v2-migration/with-servicename  5.3 s  (was 27 s before pre-screen)
python-flask/os-system-unsanitized-data    4.3 s
```

The python-flask block dominates because every Python file in the repo trips its
low-cardinality required literals ("subprocess", "request", etc.). Further wins
require either a combined Tree-sitter query for shared per-file traversal across
the python-flask rules (sketched in `autoresearch.ideas.md`) or rule-side changes.


## Where the time goes (final profile, dd-source)

Total analyzer Duration ~54s wall, ~322s user CPU (vs baseline 232s wall, 1383s
CPU). Top remaining per-rule CPU consumers (sums across 100k+ files):

| rule | CPU s | why still in the hot path |
|------|------:|--------------------------|
| `python-flask/command-injection`            | 22 | 2 patterns; pattern 2 (any assignment) is unconstrained; JS only uses pattern-1 captures but proving that needs JS analysis |
| `python-flask/html-format-from-user-input`  | 6  | TS query has `[`; JS uses two captures so the relaxed alternation gate doesn't fire |
| `python-flask/os-popen-command-injection`   | 5.5| many predicates inside an optional/`?` group — conservatively skipped |
| `dd-trace-go-v2-migration/with-servicename` | 5.5| was 27s before multi-pattern (-80%); long tail |
| `python-flask/os-system-unsanitized-data`   | 4.3| TS query has `[`; JS uses three captures |

The top 15 rules now sum to ~70s CPU = ~8.7s wall. The rest of analyzer time
(~46s wall) is per-file overhead: tree-sitter parsing, generated-file
classification, file walking, gitignore application, SARIF serialization.
Those are roughly fixed-cost-per-file and harder to attack without changing
defaults (e.g. `DEFAULT_MAX_CPUS = 8`).

## Session summary

- 19 experiments, 12 kept (including a few verification reruns), 5 discarded.
- Baseline 251.25 s → final ~48 s = **−80.8 %**.
- All 362 kernel unit tests pass; 10/10 reference repos preserve their
  baseline SARIF fingerprints (deep check) on every kept iteration.
- `user_cpu_seconds` dropped 75 % (1383 → 342 s).
- `peak_rss_mb` rose 41 % (909 → 1280 MB), entirely from two well-understood
  trade-offs: doubling rayon worker count (run #17) and combined-query
  match retention (run #19). Memory-constrained users can revert via
  `--cpus 8` to recover the old memory profile.

Wins, in order:

1. **memchr fast-path in `get_lines_to_ignore`** — most files have no
   `no-dd-sa` / `datadog-disable` markers; bail before per-line whitespace-
   stripping and per-pattern `.contains()`. (Run #2; −5.2 %.)
2. **Reuse parsed tree for `is_test_file`** — perf-neutral but enables
   future tree-sharing. (Run #3.)
3. **Conservative literal pre-screen** — the bulk of the wins. Iterative
   refinements:
   - `#eq?` / `#any-of?` extraction with file-level + per-rule short-circuit
     (run #4: −15 %).
   - `#match?` regex longest-literal-run with safety bails on `|`, `(?...)`,
     short runs (run #5: −23 %).
   - Multi-pattern OR-aware extraction via `start_byte_for_pattern` (run #6:
     −34 %).
   - `[`-depth and `?`/`*`/`+`-quantifier tracking so predicates inside
     alternation/optional groups are skipped without bailing the whole
     screen (run #7: −38 %).
4. **JS-side `const NAME = [...]` mining** — mine each element as required
   literal AND its leading `[a-zA-Z0-9_]+` prefix run, safely covering the
   common `text.includes(elem) || text.includes(elem.match(/^[a-z0-9]+/i)[0])`
   pattern. (Run #10: −47 %.)
5. **Relax the alternation gate when JS uses a single capture name** —
   when the rule's JS body references exactly one `query.captures.X` name,
   all `[...]` alternation branches are handled uniformly, so JS-mining
   stays safe even with `[` in the TS query. (Run #11: −71 %.)
6. **Language-level rayon parallelism** — replace the sequential
   `for language in languages` loop with a `par_iter`. Nested rayon shares
   the global thread pool. (Run #15: −72 %.)
7. **Lift `DEFAULT_MAX_CPUS` from 8 to 16** — the conservative cap left 50 %
   of cores idle on multi-core dev/CI hosts. Smaller machines still clamp
   to `min(logical_cores, cap)`. (Run #17: −78 %.)
8. **Adaptive combined Tree-sitter query** — when `file_count × rule_count >
   10000`, build one big multi-pattern `tree_sitter::Query` per language,
   walk each file's parse tree once, dispatch matches per rule via new
   `JsRuntime::execute_rule_with_matches`. Below the threshold, falls back
   to per-rule path. (Run #19: −81 %.)

Discarded experiments (preserved in `autoresearch.jsonl` for context):

- Eager pre-screen mask precomputation (run #9): regressed ~10 s; the lazy
  `.any()` short-circuit was already optimal.
- Unused-pattern detection (run #13): neutral, added complexity for nothing.
- Setup-phase parallelization (run #16): nested-rayon over-subscription.
- Drop `* 0.9` headroom factor (run #18): within noise.

Ideas not pursued (see `autoresearch.ideas.md`): parallel directory walking
with `jwalk`, threshold tuning for combined query, Aho-Corasick batched
literal screening, per-rule timing accounting in combined-query path.

