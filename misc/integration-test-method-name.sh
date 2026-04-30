#!/bin/bash

# Integration test: verify that enclosing method names are populated in SARIF
# logicalLocations when a violation falls inside a named method.
#
# Uses a self-contained dummy rule so the test does not depend on external
# rulesets or repositories.

set -euo pipefail

ANALYZER="./target/release-dev/datadog-static-analyzer"

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

# ---------------------------------------------------------------------------
# Source file: one class with one method containing one local variable.
# ---------------------------------------------------------------------------
cat > "${WORK_DIR}/Sample.java" << 'EOF'
class Sample {
    public void doWork() {
        int x = 1;
    }
}
EOF

# ---------------------------------------------------------------------------
# Rule: flag every local_variable_declaration.
#
# code (base64 of):
#   function visit(node, filename, code) {
#     const n = node.captures["decl"];
#     addError(buildError(n.start.line, n.start.col, n.end.line, n.end.col,
#                         "test violation", "WARNING", "BEST_PRACTICES"));
#   }
#
# tree_sitter_query (base64 of):
#   (local_variable_declaration) @decl
# ---------------------------------------------------------------------------
cat > "${WORK_DIR}/rules.json" << 'EOF'
[{
  "name": "test-ruleset",
  "description": "dGVzdA==",
  "rules": [{
    "name": "test-ruleset/flag-local-var",
    "short_description": "dGVzdA==",
    "description": "dGVzdA==",
    "category": "BEST_PRACTICES",
    "severity": "WARNING",
    "language": "JAVA",
    "rule_type": "TREE_SITTER_QUERY",
    "entity_checked": null,
    "code": "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICBjb25zdCBuID0gbm9kZS5jYXB0dXJlc1siZGVjbCJdOwogIGFkZEVycm9yKGJ1aWxkRXJyb3Iobi5zdGFydC5saW5lLCBuLnN0YXJ0LmNvbCwgbi5lbmQubGluZSwgbi5lbmQuY29sLCAidGVzdCB2aW9sYXRpb24iLCAiV0FSTklORyIsICJCRVNUX1BSQUNUSUNFUyIpKTsKfQo=",
    "checksum": "ed0928bb71c63712480323e22437d5e955e998e7658d3bb24ba9ed89eebc9723",
    "pattern": null,
    "tree_sitter_query": "KGxvY2FsX3ZhcmlhYmxlX2RlY2xhcmF0aW9uKSBAZGVjbAo=",
    "tests": [],
    "is_testing": false
  }]
}]
EOF

"${ANALYZER}" \
    --directory "${WORK_DIR}" \
    -r "${WORK_DIR}/rules.json" \
    -o "${WORK_DIR}/results.json" \
    -f sarif \
    -b

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------
TOTAL=$(jq '.runs[0].results | length' "${WORK_DIR}/results.json")
if [ "${TOTAL}" -ne 1 ]; then
    echo "FAIL: expected 1 violation, got ${TOTAL}"
    exit 1
fi

METHOD_NAME=$(jq -r '.runs[0].results[0].locations[0].logicalLocations[0].name // empty' "${WORK_DIR}/results.json")
KIND=$(jq -r '.runs[0].results[0].locations[0].logicalLocations[0].kind // empty' "${WORK_DIR}/results.json")

if [ "${METHOD_NAME}" != "doWork" ]; then
    echo "FAIL: expected logicalLocations name 'doWork', got '${METHOD_NAME}'"
    exit 1
fi

if [ "${KIND}" != "function" ]; then
    echo "FAIL: expected logicalLocations kind 'function', got '${KIND}'"
    exit 1
fi

echo "PASS: logicalLocations name=${METHOD_NAME}, kind=${KIND}"
exit 0
