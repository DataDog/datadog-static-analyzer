# Autoresearch ideas backlog (post-session)

Final session result: **−80.8 %** wall on dd-source (251.25 s → ~48 s).

Below are ideas that could push further and were intentionally deferred or
abandoned for marginal returns.

## Implemented (was in this list, now done)

- ~~Adaptive combined Tree-sitter query (per-language)~~ — DONE in run #19
  (−8.5 s wall, −120 s CPU). Threshold: `file_count × rule_count > 10_000`.
- ~~Lift `DEFAULT_MAX_CPUS = 8` cap on multi-core dev boxes~~ — DONE in run
  #17 (lifted 8 → 16, −14.5 s wall on the 16-core host).

## High-potential (not yet attempted)

- **Parallel directory walking**
  `cli/src/file_utils.rs::get_files` uses single-threaded `walkdir::WalkDir`
  on 271 k files. ~few seconds of pre-analysis wall. Switching to `jwalk`
  (parallel walker, drop-in API) would parallelize the walk. Requires a new
  dependency; otherwise mechanical. Estimated 1-3 s wall.

- **Tune the combined-query threshold**
  Currently `file_count × rule_count > 10_000` triggers combined query. The
  optimal threshold likely depends on average rule complexity (number of
  patterns, tree-walk node-type diversity). A small perf microbenchmark
  across a few repo sizes would show whether 10k is right, or if e.g. 5k
  works better for medium repos.

## Medium-potential

- **Skip-at-build of unused-pattern rules**
  Tried in run #15 (discarded as neutral). The implementation works but the
  python-flask/command-injection rule's required literal (`subprocess`)
  isn't selective enough on dd-source's Python files. Could revisit if
  applied to a workload where unused-pattern rules are more prominent.

- **Aho-Corasick batch screening**
  Build a per-language Aho-Corasick automaton over ALL rules' required
  literals, run it once per file to get a bit-vector of present literals,
  per-rule check is then O(K) HashMap lookups. Saves redundant `code.contains`
  calls on identical literals across rules. Estimated <1 s wall (current
  contains-based screen is already SIMD-optimized; gain is small).

- **Per-rule timing accounting in combined-query path**
  Currently `analyze_with_combined` reports the SHARED `combined_query_time`
  in each rule's `query_node_time_ms`, which inflates `-x` performance
  output (sum of per-rule query times >> actual). Either zero out the
  per-rule query time or amortize across surviving rules. Cosmetic but
  improves diagnostic accuracy.

## Smaller / cleanup

- **Profile-driven rule reordering**: order rules in the per-rule loop so
  the cheapest pre-screen evaluates first, maximizing `.any()` short-circuit.

- **Skip empty-bucket rules in the combined-query path** (#4 from prior
  research). Only relevant once combined query is implemented.

## Don't-try (verified dead ends)

- **Eager pre-screen mask precomputation per file** (run #9): regressed wall
  by ~10 s. The lazy `.any()` short-circuit was already optimal because most
  files pass the first rule's screen quickly. Don't replace short-circuit
  patterns with eager precomputation.

- **Setup-phase parallelization across languages** (run #16): regressed
  wall by ~5-10 s. Nested rayon (setup + per-language + per-file) over-
  subscribes the thread pool and creates scheduling contention. Keep setup
  serial.

- **Unused-pattern detection** (run #13): neutral on dd-source. The required
  literals from the surviving constrained pattern aren't selective enough
  in this workload.

- **Drop the `* 0.9` headroom factor in `get_num_threads_to_use`** (run #18):
  ~1 s gain, within noise; preserves the original conservative design intent
  of leaving headroom for the v8 watchdog management threads.

- (From prior research; verified twice, do not re-investigate without
  new evidence)
  - Thread-local `tree_sitter::Parser` cache.
  - Skipping `bridge_query_match.clear()` after each rule.
  - Flat `Vec<(rule_idx, match)>` from combined query.
  - HashMap-based per-file literal-presence cache.
  - Regex literal extraction returning the longest run **with `|`
    alternation** (silently misses violations; my session uses a stricter
    "no `|`" gate).
  - `#[inline(always)]` on same-crate hot paths.
