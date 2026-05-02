#!/bin/bash
#
# Deep correctness check across 9 reference repos.
# Runs ONLY when autoresearch.sh exits 0 (i.e. benchmark passed and light
# fingerprints matched). Used as a backpressure gate before keeping a result.
#
# Reuses the dd-source SARIF produced by autoresearch.sh (saved to
# last-dd-source.sarif) — no need to re-run that 4-minute scan.
#
# This script is INTENTIONALLY quiet: only prints a final summary unless a
# repo regresses. The agent's context window is precious.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$HOME/autoresearch-static-analyzer"
ANALYZER="$REPO_ROOT/target/release-dev/datadog-static-analyzer"
RULES="$WORK_DIR/all-rulesets.json"
BASELINES_DIR="$WORK_DIR/baselines"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# All 9 reference repos. dd-source is checked via the SARIF that autoresearch.sh
# already produced. The 8 others run with cached rules (no dd-auth — fast & stable),
# EXCEPT saluki which ships its own static-analysis.datadog.yml — that one needs
# dd-auth so the analyzer respects the config file.
REFERENCE_REPOS=(cloudops apis dd-git-hooks datacenter-config cloud-inventory datastores devtools saluki lading)
# Space-separated string so it survives `export` into xargs subshells.
export NEEDS_DD_AUTH_LIST=" saluki "

needs_dd_auth() {
    [[ "$NEEDS_DD_AUTH_LIST" == *" $1 "* ]]
}

mismatches=()

# 1. Verify dd-source from the saved SARIF (~free).
ddsource_sarif="$WORK_DIR/last-dd-source.sarif"
if [ ! -f "$ddsource_sarif" ]; then
    echo "DEEP CHECK ERROR: $ddsource_sarif missing — autoresearch.sh did not run or did not finish." >&2
    exit 1
fi
ddsource_actual=$(python3 "$WORK_DIR/fingerprint.py" "$ddsource_sarif" | python3 -c 'import sys,json; print(json.load(sys.stdin)["sha256"])')
ddsource_expected=$(python3 -c "import json; print(json.load(open('$BASELINES_DIR/baseline_fingerprints.json'))['dd-source']['sha256'])")
if [ "$ddsource_actual" != "$ddsource_expected" ]; then
    diff_summary=$(python3 "$WORK_DIR/fingerprint.py" --diff "$BASELINES_DIR/dd-source.sarif" "$ddsource_sarif" 2>/dev/null || echo "(no baseline sarif on disk)")
    mismatches+=("dd-source: $diff_summary")
fi

# 2. Run the 8 reference repos in parallel for speed (small repos, ~1-3s each).
#    Each writes a one-line status to $TMP_DIR/<repo>.status.
run_one() {
    local repo="$1"
    local sarif="$TMP_DIR/${repo}.sarif"
    local rc=0
    if needs_dd_auth "$repo"; then
        dd-auth --domain app.datadoghq.com -- "$ANALYZER" \
            --directory "$HOME/dd/$repo" \
            --output "$sarif" \
            --format sarif >/dev/null 2>"$TMP_DIR/${repo}.err" || rc=$?
    else
        "$ANALYZER" \
            --directory "$HOME/dd/$repo" \
            -r "$RULES" \
            --output "$sarif" \
            --format sarif >/dev/null 2>"$TMP_DIR/${repo}.err" || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        echo "CRASH" > "$TMP_DIR/${repo}.status"
        return 0
    fi
    local actual expected
    actual=$(python3 "$WORK_DIR/fingerprint.py" "$sarif" | python3 -c 'import sys,json; print(json.load(sys.stdin)["sha256"])')
    expected=$(python3 -c "import json; print(json.load(open('$BASELINES_DIR/baseline_fingerprints.json'))['$repo']['sha256'])")
    if [ "$actual" = "$expected" ]; then
        echo "OK" > "$TMP_DIR/${repo}.status"
    else
        local diff_summary
        diff_summary=$(python3 "$WORK_DIR/fingerprint.py" --diff "$BASELINES_DIR/${repo}.sarif" "$sarif" 2>/dev/null || echo "{}")
        echo "MISMATCH $diff_summary" > "$TMP_DIR/${repo}.status"
    fi
}
export -f run_one needs_dd_auth
export ANALYZER RULES WORK_DIR BASELINES_DIR TMP_DIR

# Use xargs -P for parallelism. Cap at 4 to avoid stomping on the just-finished
# benchmark's CPU thermals / page cache (most are <3s anyway).
printf '%s\n' "${REFERENCE_REPOS[@]}" | xargs -I {} -P 4 -n 1 bash -c 'run_one "$@"' _ {}

# Collect statuses
ok_count=0
for repo in "${REFERENCE_REPOS[@]}"; do
    status=$(cat "$TMP_DIR/${repo}.status" 2>/dev/null || echo "MISSING")
    case "$status" in
        OK)        ok_count=$((ok_count+1)) ;;
        CRASH)     mismatches+=("${repo}: analyzer CRASHED ($(tail -3 "$TMP_DIR/${repo}.err" 2>/dev/null | tr '\n' ' '))") ;;
        MISMATCH*) mismatches+=("${repo}: ${status#MISMATCH }") ;;
        *)         mismatches+=("${repo}: $status") ;;
    esac
done

if [ ${#mismatches[@]} -eq 0 ]; then
    echo "DEEP CHECK PASSED (10/10 repos including dd-source)"
    exit 0
fi

echo "DEEP CHECK FAILED:"
for m in "${mismatches[@]}"; do
    echo "  - $m"
done
exit 1
