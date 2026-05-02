#!/bin/bash
#
# Benchmark + light correctness check for the static analyzer.
# Primary metric: end-to-end wall time on dd-source.
# Secondary metrics: analyzer-reported scan duration, peak RSS, CPU time, findings count.
# Light fingerprint check: 3 small repos with cached rules (cloudops, apis, dd-git-hooks).
#
# Heavier 9-repo deep-check lives in autoresearch.checks.sh; that runs only on passing benchmarks.
#
# Outputs structured `METRIC name=value` lines and appends a JSONL record to
# ~/autoresearch-static-analyzer/runs.jsonl for every run (kept OR rejected).
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$HOME/autoresearch-static-analyzer"
ANALYZER="$REPO_ROOT/target/release-dev/datadog-static-analyzer"
RULES="$WORK_DIR/all-rulesets.json"
BASELINES_DIR="$WORK_DIR/baselines"
RUNS_LOG="$WORK_DIR/runs.jsonl"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# --- Fast preflight: cargo check (syntax/types) -----------------------------
# This catches obvious mistakes before we spend ~4min on a benchmark.
preflight_start=$(date +%s.%N)
if ! cargo check --profile release-dev --quiet 2>"$TMP_DIR/cargo-check.log"; then
    echo "PREFLIGHT FAILED: cargo check errors:" >&2
    tail -40 "$TMP_DIR/cargo-check.log" >&2
    exit 2
fi
preflight_end=$(date +%s.%N)
preflight_secs=$(awk "BEGIN{printf \"%.2f\", $preflight_end - $preflight_start}")

# --- Build ------------------------------------------------------------------
build_start=$(date +%s.%N)
cargo build --profile release-dev --quiet 2>"$TMP_DIR/build.log" || {
    echo "BUILD FAILED:" >&2
    tail -40 "$TMP_DIR/build.log" >&2
    exit 3
}
build_end=$(date +%s.%N)
build_secs=$(awk "BEGIN{printf \"%.2f\", $build_end - $build_start}")

# --- Light correctness fingerprint (3 small repos, cached rules) ------------
# These are FAST (~1.5–4s each) and exist to catch obvious correctness regressions
# before we spend minutes on the dd-source benchmark.
# IMPORTANT: dd-source's fingerprint alone is INSUFFICIENT — it covers very few
# rule categories. The deeper 9-repo check runs in autoresearch.checks.sh.
LIGHT_REPOS=(cloudops apis dd-git-hooks)
fingerprint_match=true
fingerprint_details=""
for repo in "${LIGHT_REPOS[@]}"; do
    sarif="$TMP_DIR/${repo}.sarif"
    if ! "$ANALYZER" \
            --directory "$HOME/dd/$repo" \
            -r "$RULES" \
            --output "$sarif" \
            --format sarif >/dev/null 2>"$TMP_DIR/${repo}.err"; then
        echo "FINGERPRINT FAILED: analyzer crashed on $repo" >&2
        cat "$TMP_DIR/${repo}.err" >&2
        exit 4
    fi
    actual=$(python3 "$WORK_DIR/fingerprint.py" "$sarif" | python3 -c 'import sys,json; print(json.load(sys.stdin)["sha256"])')
    expected=$(python3 -c "import json; print(json.load(open('$BASELINES_DIR/baseline_fingerprints.json'))['$repo']['sha256'])")
    if [ "$actual" != "$expected" ]; then
        fingerprint_match=false
        # Collect a small diff summary for the agent.
        diff_summary=$(python3 "$WORK_DIR/fingerprint.py" --diff "$BASELINES_DIR/${repo}.sarif" "$sarif" || true)
        fingerprint_details="${fingerprint_details}REPO ${repo} MISMATCH: ${diff_summary}; "
        echo "FINGERPRINT MISMATCH on $repo: expected=$expected actual=$actual" >&2
        echo "  diff: $diff_summary" >&2
    fi
done

# --- Primary benchmark: dd-source via dd-auth -------------------------------
# Use the user-specified end-to-end command. 16-core machine; analyzer defaults
# to min(num_cores, 8) so behavior matches the spec.
DD_SARIF="$TMP_DIR/dd-source-result.sarif"
TIME_FILE="$TMP_DIR/time.txt"
ANALYZER_OUT="$TMP_DIR/analyzer-out.txt"

# /usr/bin/time -v gives wall, user, sys, and peak RSS in kbytes.
# Format string is laid out so simple grep/awk can parse it.
/usr/bin/time -o "$TIME_FILE" -f "WALL=%e USER=%U SYS=%S RSS_KB=%M CPU_PCT=%P EXIT=%x" \
    dd-auth --domain app.datadoghq.com -- \
        "$ANALYZER" \
        --directory "$HOME/dd/dd-source" \
        --output "$DD_SARIF" \
        --format sarif \
    >"$ANALYZER_OUT" 2>&1 || {
        echo "BENCHMARK FAILED:" >&2
        tail -40 "$ANALYZER_OUT" >&2
        cat "$TIME_FILE" >&2
        exit 5
    }

# Parse /usr/bin/time output
wall_secs=$(awk -F'WALL=' '/WALL=/{print $2}' "$TIME_FILE" | awk '{print $1}')
user_secs=$(awk -F'USER=' '/USER=/{print $2}' "$TIME_FILE" | awk '{print $1}')
sys_secs=$(awk -F'SYS=' '/SYS=/{print $2}' "$TIME_FILE" | awk '{print $1}')
rss_kb=$(awk -F'RSS_KB=' '/RSS_KB=/{print $2}' "$TIME_FILE" | awk '{print $1}')
rss_mb=$(awk "BEGIN{printf \"%.0f\", $rss_kb / 1024}")

# Parse analyzer self-reported numbers
analyzer_duration=$(grep -oE 'Duration: [0-9.]+s' "$ANALYZER_OUT" | tail -1 | grep -oE '[0-9.]+')
files_scanned=$(grep -oE 'Files scanned: [0-9]+' "$ANALYZER_OUT" | tail -1 | grep -oE '[0-9]+')
total_violations=$(grep -oE 'Total violations: [0-9]+' "$ANALYZER_OUT" | tail -1 | grep -oE '[0-9]+')
rules_evaluated=$(grep -oE 'Rules evaluated: [0-9]+' "$ANALYZER_OUT" | tail -1 | grep -oE '[0-9]+')

# Sanity-defaults if parsing failed
analyzer_duration=${analyzer_duration:-0}
files_scanned=${files_scanned:-0}
total_violations=${total_violations:-0}
rules_evaluated=${rules_evaluated:-0}

# Fingerprint dd-source result too (informational; deep-check is authoritative).
ddsource_fp=$(python3 "$WORK_DIR/fingerprint.py" "$DD_SARIF" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["sha256"], d["count"])')
ddsource_sha=$(echo "$ddsource_fp" | awk '{print $1}')
ddsource_count=$(echo "$ddsource_fp" | awk '{print $2}')
ddsource_baseline_sha=$(python3 -c "import json; print(json.load(open('$BASELINES_DIR/baseline_fingerprints.json'))['dd-source']['sha256'])")
ddsource_match=$([ "$ddsource_sha" = "$ddsource_baseline_sha" ] && echo true || echo false)

# Stash the dd-source SARIF for the deep-check script to reuse (avoid re-running it).
cp "$DD_SARIF" "$WORK_DIR/last-dd-source.sarif"

# --- Append JSONL record (always, even on rejection) ------------------------
# We don't know `kept` here — autoresearch.jsonl will record that. We append
# per-run resource data unconditionally so the file is the source of truth.
git_sha=$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - <<PY >> "$RUNS_LOG"
import json, sys
rec = {
    "timestamp": "$ts",
    "git_sha": "$git_sha",
    "branch": "$(cd "$REPO_ROOT" && git branch --show-current 2>/dev/null || echo unknown)",
    "repo": "dd-source",
    "wall_time_seconds": float("$wall_secs"),
    "analyzer_duration_seconds": float("$analyzer_duration"),
    "peak_rss_mb": int("$rss_mb"),
    "peak_rss_kb": int("$rss_kb"),
    "user_cpu_seconds": float("$user_secs"),
    "sys_cpu_seconds": float("$sys_secs"),
    "files_scanned": int("$files_scanned"),
    "total_violations": int("$total_violations"),
    "rules_evaluated": int("$rules_evaluated"),
    "ddsource_fingerprint_count": int("$ddsource_count"),
    "ddsource_fingerprint_match": "$ddsource_match" == "true",
    "light_fingerprint_match": "$fingerprint_match" == "true",
    "light_fingerprint_details": "$fingerprint_details",
    "build_seconds": float("$build_secs"),
    "preflight_seconds": float("$preflight_secs"),
}
print(json.dumps(rec))
PY

# --- Emit METRIC lines for autoresearch -------------------------------------
echo ""
echo "=== Benchmark summary ==="
echo "  wall:           ${wall_secs}s"
echo "  analyzer dur.:  ${analyzer_duration}s"
echo "  peak RSS:       ${rss_mb} MB"
echo "  user CPU:       ${user_secs}s"
echo "  sys CPU:        ${sys_secs}s"
echo "  files scanned:  ${files_scanned}"
echo "  violations:     ${total_violations}"
echo "  rules:          ${rules_evaluated}"
echo "  ddsource fp:    count=${ddsource_count} match=${ddsource_match}"
echo "  light fp:       match=${fingerprint_match} ${fingerprint_details}"
echo "  build time:     ${build_secs}s"
echo ""

# Primary metric (must match init_experiment metric_name)
echo "METRIC wall_seconds=${wall_secs}"
# Secondary metrics
echo "METRIC analyzer_seconds=${analyzer_duration}"
echo "METRIC peak_rss_mb=${rss_mb}"
echo "METRIC user_cpu_seconds=${user_secs}"
echo "METRIC sys_cpu_seconds=${sys_secs}"
echo "METRIC violations=${total_violations}"
echo "METRIC build_seconds=${build_secs}"

# Hard-fail if light fingerprint mismatched — caller must investigate.
# (We still emit metrics first so the rejected run is observable.)
if [ "$fingerprint_match" != "true" ]; then
    echo "FINGERPRINT_MISMATCH: $fingerprint_details" >&2
    exit 6
fi
