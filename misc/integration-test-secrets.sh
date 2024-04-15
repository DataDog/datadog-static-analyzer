#!/bin/bash

# This integration test:
# 1. Creates a rule that has inverted logic: marking invalid secrets as valid (so a true secret is not used in this test)
# 2. Scans a string that should trigger the `datadog-api-key` secrets detection matcher and validator
# 3. Confirms that the SARIF output contains a detection with `VALID` status

cargo build -r --features datadog-static-analyzer/secrets --bin datadog-static-analyzer

TEMP_DIR=$(mktemp -d)
TEMP_FILE=$(mktemp "$TEMP_DIR"/tmp-file.XXXXXXXX)
echo 'The quick DD_API_KEY fox jumps over the "deadbeef00002b66248e3bceeb15334c" dog' > "$TEMP_FILE"
# Use a stub config with an (arbitrary) small ruleset
echo $'rulesets:\n  - typescript-common-security' > "$TEMP_DIR/static-analysis.datadog.yml"

# This is a rule with inverted logic for test purposes. Because we don't use a real secret, the
# Datadog API will return a 403, saying the key is invalid. However, for this rule, we mark that
# as "VALID". If we don't receive a 403, or some other error (API unreachable, etc), the rule
# will default to "INCONCLUSIVE". We then confirm that the SARIF has a "VALID" determination.
echo $'datadog-api-key:
        schema-version: v1
        id: datadog-api-key
        matcher:
          hyperscan:
            pattern: "[[:xdigit:]]{32}"
            proximity:
              keywords: ["dd", "datadog"]
        validator:
          http:
            extension: simple-request
            config:
              request:
                url: https://api.datadoghq.com/api/v1/validate
                method: GET
                headers:
                  DD-API-KEY: ${{ candidate }}
              response-handler:
                handler-list:
                  - on-match:
                      equals:
                        input: ${{ http.response.code }}
                        value: 403
                    action:
                      return:
                        secret: VALID
                        severity: ERROR
                default-result:
                  secret: INCONCLUSIVE
                  severity: ERROR' > "$TEMP_DIR/secrets-rules.yml"

./target/release/datadog-static-analyzer --secrets-scan --secrets-validate --secrets-rules "${TEMP_DIR}/secrets-rules.yml" --directory "${TEMP_DIR}" -o "${TEMP_DIR}/results.json" -f sarif  &>/dev/null
if [ $? -ne 0 ]; then echo "scan failed"; exit 1; fi

RULE_ID=$(jq '.runs[0].results[0].ruleId' "${TEMP_DIR}/results.json")
if [[ $RULE_ID != "\"datadog-api-key\"" ]]; then echo "expected violation for secret detection rule"; exit 1; fi
TAGS=$(jq '.runs[0].results[0].properties.tags' "${TEMP_DIR}/results.json")
if [[ $TAGS != *"\"DATADOG_VALIDATION_STATUS:VALID\""* ]]; then echo 'expected status `VALID` for detection'; exit 1; fi

echo "All tests passed"

exit 0
