# Autoresearch ideas backlog

Ideas discovered during the scan-speed session that we did not pursue (yet).

## High-potential, complex

- **Adaptive combined Tree-sitter query (per-language, big-workload)**
  Concatenate all per-language rule queries into one multi-pattern query, walk
  the parse tree once per file, dispatch matches by `pattern_index → rule_idx`.
  Prior research estimates ~2× win on big workloads. Threshold: only enable
  when `file_count_for_lang × rule_count_for_lang > N` (e.g. 10000) — small
  repos lose to upfront `tree_sitter::Query::new` cost.
  Surgery: ~2-4hrs. Need to handle capture-name spaces correctly when a name
  appears in multiple rules' patterns (turns out it Just Works, since matches
  carry their pattern index and JS reads captures by name).
  Code touchpoints: new `combined_query.rs`, `crates/bins/src/lib.rs` driver
  branch, expose `execute_rule_with_matches` on `JsRuntime` to bypass the
  internal TS-query phase.

- **JS-side `const NAME = [...]` array mining with prefix transform**
  For broad-capture rules whose JS body declares a const array of strings and
  checks them against a captured string (e.g. `no-hardcoded-cluster`,
  `no-hardcoded-datacenter`), mine the **leading [a-zA-Z0-9_]+ run** of each
  array element as a required-literal OR-group. This safely covers both
  `match.includes(elem)` and `match.includes(elem.match(/^[a-z0-9]+/i)[0])`
  patterns (which the cluster rule uses).
  Safety gates per prior research:
  - top-level `const` (brace depth 0)
  - name doesn't contain TYPE/KIND/NODE
  - all elements have a non-alphanumeric character
  - TS query has no `[` (now: TS query's pre-screen could add the JS literals
    as a global AND-group)
  - additional: skip if JS body uses `<arrname>.replace(`, complex string
    operations that could transform elements unpredictably.
  Targets dd-source's biggest single rule: no-hardcoded-cluster (Go) at ~88s
  CPU = ~11s wall. Estimated wall: 5-12s.

## Medium-potential

- **Multi-pattern with one unconstrained: bail or analyze JS**
  Rules like `python-flask/command-injection` have one selective pattern
  (`subprocess`) and one auxiliary pattern (any assignment). The JS may
  ignore the auxiliary pattern's matches. If we could detect that
  `query.captures["assignment"]` is never read, skip pattern 2 entirely.
  Risky — JS analysis is fragile.

- **Combine multi-rule `#match?` regex extraction with regex-syntax crate**
  Use the `regex-syntax` crate to compute richer "required literal" sets,
  including alternation branches when each branch has its own literal.
  Skip our home-grown `extract_required_literal_from_regex` complexity.
  Adds a dependency though.

## Smaller / cleanup

- **Profile-driven rule reordering**: put screen-cheap rules first in the
  per-rule loop so we exit early on the all-screen-fail path.
  (Currently the ordering is whatever the input ruleset provided.)

- **Skip empty-bucket rules in the combined-query path** (#4 from prior
  research) — only relevant once combined query is implemented.
