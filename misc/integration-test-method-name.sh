#!/bin/bash

# Integration test: verify that method names are populated in SARIF logicalLocations
# for languages that implement enclosing-function detection.
#
# Each language block:
#   1. Clones a representative repo
#   2. Runs the analyzer with relevant rulesets
#   3. Asserts that at least one violation has a logicalLocations entry (i.e. method_name was resolved)
#
# If this test fails for a previously-passing language, it means enclosing-function
# detection broke for that language.  If a newly-supported language never appears here,
# add it so that coverage is enforced going forward.

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
# Python – django-realworld-example-app
# ---------------------------------------------------------------------------
echo "=== Python: method-name detection ==="
PY_DIR=$(mktemp -d)
git clone --depth=1 https://github.com/gothinkster/django-realworld-example-app.git "${PY_DIR}"

cat > "${PY_DIR}/code-security.datadog.yaml" <<'YAML'
schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - python-security
    - python-best-practices
    - python-django
YAML

"${ANALYZER}" --directory "${PY_DIR}" -o "${PY_DIR}/results.json" -f sarif

TOTAL=$(jq '.runs[0].results | length' "${PY_DIR}/results.json")
WITH_METHOD=$(count_with_method "${PY_DIR}/results.json")

echo "Python: ${WITH_METHOD}/${TOTAL} violations have a method name"

if [ "${TOTAL}" -lt 1 ]; then
    echo "FAIL: no Python violations found – ruleset may be empty or repo changed"
    exit 1
fi
if [ "${WITH_METHOD}" -lt 1 ]; then
    echo "FAIL: no Python violations carry a logicalLocations/method name"
    exit 1
fi

# ---------------------------------------------------------------------------
# JavaScript / TypeScript – juice-shop
# ---------------------------------------------------------------------------
echo "=== JavaScript/TypeScript: method-name detection ==="
JS_DIR=$(mktemp -d)
git clone --depth=1 https://github.com/juice-shop/juice-shop.git "${JS_DIR}"

cat > "${JS_DIR}/code-security.datadog.yaml" <<'YAML'
schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - javascript-best-practices
    - typescript-best-practices
    - javascript-common-security
    - typescript-common-security
    - javascript-node-security
    - typescript-node-security
YAML

"${ANALYZER}" --directory "${JS_DIR}" -o "${JS_DIR}/results.json" -f sarif

TOTAL=$(jq '.runs[0].results | length' "${JS_DIR}/results.json")
WITH_METHOD=$(count_with_method "${JS_DIR}/results.json")

echo "JS/TS: ${WITH_METHOD}/${TOTAL} violations have a method name"

if [ "${TOTAL}" -lt 1 ]; then
    echo "FAIL: no JS/TS violations found – ruleset may be empty or repo changed"
    exit 1
fi
if [ "${WITH_METHOD}" -lt 1 ]; then
    echo "FAIL: no JS/TS violations carry a logicalLocations/method name"
    exit 1
fi

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
# Go – github-mcp-server
# ---------------------------------------------------------------------------
echo "=== Go: method-name detection ==="
GO_DIR=$(mktemp -d)
git clone --depth=1 https://github.com/github/github-mcp-server.git "${GO_DIR}"

cat > "${GO_DIR}/code-security.datadog.yaml" <<'YAML'
schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - go-security
    - go-best-practices
YAML

"${ANALYZER}" --directory "${GO_DIR}" -o "${GO_DIR}/results.json" -f sarif

TOTAL=$(jq '.runs[0].results | length' "${GO_DIR}/results.json")
WITH_METHOD=$(count_with_method "${GO_DIR}/results.json")

echo "Go: ${WITH_METHOD}/${TOTAL} violations have a method name"

if [ "${TOTAL}" -lt 1 ]; then
    echo "FAIL: no Go violations found – ruleset may be empty or repo changed"
    exit 1
fi
if [ "${WITH_METHOD}" -lt 1 ]; then
    echo "FAIL: no Go violations carry a logicalLocations/method name"
    exit 1
fi

# ---------------------------------------------------------------------------
# C# – unity-mcp
# ---------------------------------------------------------------------------
echo "=== C#: method-name detection ==="
CS_DIR=$(mktemp -d)
git clone --depth=1 https://github.com/CoplayDev/unity-mcp.git "${CS_DIR}"

cat > "${CS_DIR}/code-security.datadog.yaml" <<'YAML'
schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - csharp-security
    - csharp-best-practices
YAML

"${ANALYZER}" --directory "${CS_DIR}" -o "${CS_DIR}/results.json" -f sarif

TOTAL=$(jq '.runs[0].results | length' "${CS_DIR}/results.json")
WITH_METHOD=$(count_with_method "${CS_DIR}/results.json")

echo "C#: ${WITH_METHOD}/${TOTAL} violations have a method name"

if [ "${TOTAL}" -lt 1 ]; then
    echo "FAIL: no C# violations found – ruleset may be empty or repo changed"
    exit 1
fi
if [ "${WITH_METHOD}" -lt 1 ]; then
    echo "FAIL: no C# violations carry a logicalLocations/method name"
    exit 1
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo "All method-name integration tests passed"
exit 0
