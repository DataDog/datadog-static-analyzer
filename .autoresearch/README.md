# Autoresearch artifacts (scan-speed-20260502)

Working files from the autoresearch session that took the dd-source scan from
**251.25 s → 23.44 s wall (-90.7%)**. Committed here so the experiment can be
investigated from another machine.

## Layout

| path | what it is |
|---|---|
| `runs.jsonl` | per-run benchmark log (resources, fingerprints, timings). Append-only across the whole session. |
| `last-dd-source.sarif` | SARIF output of the most recent dd-source run on this branch's HEAD. Used for fingerprint diffing. |
| `all-rulesets.json` | cached snapshot of 1150 rules / 59 rulesets, used by `autoresearch.checks.sh` so the deep correctness check doesn't depend on the live API. Captured at session start. |
| `fingerprint.py` | SARIF → stable SHA-256 hasher (drops noise like analyzer Duration). Used by both the deep check and the per-run check. |
| `baselines/` | frozen reference SARIF + sha-256 fingerprint per repo. **THESE ARE THE SOURCE OF TRUTH** for "did we break a rule?". |
| `baselines/baseline_fingerprints.json` | `{ repo: { sha256, files, total_violations } }` — what every change must match. |
| `baselines/dd-source-resources.json` | resource baseline (peak RSS, user CPU, etc.) on commit `eff32af0`. |

## Reproducing

The artifacts at `~/autoresearch-static-analyzer/` are normally outside the
repo. To reproduce the loop on another machine:

```bash
# clone + check out this branch
git checkout autoresearch/scan-speed-20260502

# materialise the working dir (the loop expects it at ~/autoresearch-static-analyzer)
mkdir -p ~/autoresearch-static-analyzer
cp -r .autoresearch/* ~/autoresearch-static-analyzer/

# build
cargo build --profile release-dev

# run a single benchmark + correctness check
./autoresearch.sh
./autoresearch.checks.sh   # auto-runs after a passing benchmark; can also run standalone
```

`autoresearch.sh` benchmarks dd-source via `dd-auth` (needs DD credentials).
`autoresearch.checks.sh` validates the 10 reference repos against the frozen
fingerprints and is fully offline (uses cached `all-rulesets.json`).

## Reference repos in the deep check

`cloudops apis dd-git-hooks datacenter-config cloud-inventory datastores
devtools saluki lading` — plus dd-source itself = 10 / 10. Each has a frozen
SARIF and a SHA-256 in `baselines/baseline_fingerprints.json`.

## See also

- `../autoresearch.md` — experiment rules and constraints (objective, off-limits, metrics).
- `../autoresearch.jsonl` — full experiment log (every run, kept or rejected, with ASI).
- `../autoresearch.ideas.md` — backlog of deferred ideas + verified dead-ends.
- `../autoresearch.sh` / `../autoresearch.checks.sh` — the two scripts above.
