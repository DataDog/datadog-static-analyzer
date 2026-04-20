#!/bin/bash

# Integration test: verify that method names are populated in SARIF logicalLocations
# for Java, which is the first language with enclosing-function detection.
#
# Each language block added here as support is implemented.

set -euo pipefail

ANALYZER="./target/release-dev/datadog-static-analyzer"

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

# ---------------------------------------------------------------------------
# Helper: count results that carry at least one logicalLocations entry.
# ---------------------------------------------------------------------------
count_with_method() {
    local results_file="$1"
    jq '[.runs[0].results[] |
        select(any(.locations[]?; (.logicalLocations // []) | length > 0))
       ] | length' "${results_file}"
}

# ---------------------------------------------------------------------------
# Java – OWASP Benchmark
# ---------------------------------------------------------------------------
echo "=== Java: method-name detection ==="
JAVA_DIR=$(mktemp -d)
git clone --depth=1 https://github.com/OWASP-Benchmark/BenchmarkJava.git "${JAVA_DIR}"

cat > "${JAVA_DIR}/code-security.datadog.yaml" <<'YAML'
schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - java-security
    - java-best-practices
YAML

"${ANALYZER}" --directory "${JAVA_DIR}" -o "${JAVA_DIR}/results.json" -f sarif

TOTAL=$(jq '.runs[0].results | length' "${JAVA_DIR}/results.json")
WITH_METHOD=$(count_with_method "${JAVA_DIR}/results.json")

echo "Java: ${WITH_METHOD}/${TOTAL} violations have a method name"

if [ "${TOTAL}" -lt 1 ]; then
    echo "FAIL: no Java violations found – ruleset may be empty or repo changed"
    exit 1
fi
if [ "${WITH_METHOD}" -lt 1 ]; then
    echo "FAIL: no Java violations carry a logicalLocations/method name"
    exit 1
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo "All method-name integration tests passed"
exit 0
