#!/bin/bash

# This integration test:
# 1. Creates a file without text that would trigger a (currently hardcoded) detection rule and runs a scan.
# 2. Confirms that no violation appears in the SARIF output.
# 3. Adds text that will trigger the detection rule and re-runs the scan.
# 4. Confirms that a violation appears in the SARIF output.

cargo build -r --features datadog-static-analyzer/secrets --bin datadog-static-analyzer

TEMP_DIR=$(mktemp -d)
TEMP_FILE=$(mktemp "$TEMP_DIR"/tmp-file.XXXXXXXX)
echo "The quick brown fox jumps over the lazy dog" > "$TEMP_FILE"
# Use a stub config with an (arbitrary) small ruleset
echo $'rulesets:\n  - typescript-common-security' > "$TEMP_DIR/static-analysis.datadog.yml"


./target/release/datadog-static-analyzer --test-secrets --directory "${TEMP_DIR}" -o "${TEMP_DIR}/results.json" -f sarif &>/dev/null
if [ $? -ne 0 ]; then echo "scan failed"; exit 1; fi

FIRST_SCAN=$(jq '.runs[0].results[0]' "${TEMP_DIR}/results.json")
if [ "${FIRST_SCAN}" != "null" ]; then echo "secret scan results should be empty"; exit 1; fi

rm "${TEMP_DIR}/results.json" &&
  perl -pi -e 's/(quick)/$1 DD_API_KEY=/' $TEMP_FILE &&
  perl -pi -e 's/(over)/$1 a0ef3594e77b5346791b02bdb1b2ea20c9057d61/' $TEMP_FILE

./target/release/datadog-static-analyzer --test-secrets --directory "${TEMP_DIR}" -o "${TEMP_DIR}/results.json" -f sarif &>/dev/null

RULE_ID=$(jq '.runs[0].results[0].ruleId' "${TEMP_DIR}/results.json")
if [ "${RULE_ID}" != "\"datadog-app-key\"" ]; then echo "expected violation for secret detection rule"; exit 1; fi

echo "All tests passed"

exit 0
