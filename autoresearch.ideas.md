# Autoresearch ideas backlog (post-session)

Final session result: **−72.0 %** wall on dd-source (251.25 s → ~70.43 s). Below
are ideas that could push further and were intentionally deferred.

## High-potential

- **Adaptive combined Tree-sitter query (per-language)**
  Build one `tree_sitter::Query` per language that concatenates all rule
  patterns (with `pattern_index → rule_idx` mapping). Walk each file once,
  bucket matches by rule, dispatch v8 per rule. Estimated ~3-5 s wall on
  dd-source (the python-flask block has many rules sharing similar Python
  parse-tree shapes; today each rule walks the tree independently).

  Implementation is non-trivial: we need a new `JsRuntime::execute_rule_with_matches`
  that bypasses the internal TS query phase, plus capture-name remapping
  (combined query merges capture indices, but JS reads captures by name so
  this Just Works as long as capture-name collisions across rules are
  disambiguated by `pattern_index`). Per prior research, threshold this on
  `file_count × rule_count` so small repos keep the per-rule path (one-time
  combined-query build cost dominates small workloads).

- **Parallel directory walking**
  `cli/src/file_utils.rs::get_files` uses single-threaded `walkdir::WalkDir`
  on 271 k files. ~few seconds of pre-analysis wall. Switching to `jwalk`
  (parallel walker, drop-in API) would parallelize the walk. Requires a new
  dependency; otherwise mechanical. Estimated 1-3 s wall.

- **Lift `DEFAULT_MAX_CPUS = 8` cap on multi-core dev boxes**
  The 16-core dev box only uses ~6 worker threads (rayon: `(8 − 1) × 0.9 = 6`).
  Raising the cap to `num_cpus::get()` would roughly halve analyzer wall on
  large repos. **Behavioral change** affecting all users; CI environments
  with shared cores might prefer the conservative default. Could be done
  adaptively (e.g. cap at 16 instead of 8, or scale with available RAM).
  Estimated 10-25 s wall on this hardware.

## Medium-potential

- **Combined query just for the long tail**: identify rules whose TS query is
  cheap-traversal-but-shared (e.g., `(call_expression)` style) and build a
  combined query for just those, leaving complex rules per-rule. Less risky
  than full combined query.

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

- **Setup-phase parallelization across languages** (run #15): regressed
  wall by ~5-10 s. Nested rayon (setup + per-language + per-file) over-
  subscribes the thread pool and creates scheduling contention. Keep setup
  serial.

- **Unused-pattern detection** (run #13): neutral on dd-source. The required
  literals from the surviving constrained pattern aren't selective enough
  in this workload.

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
