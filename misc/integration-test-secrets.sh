#!/bin/bash

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

## A Python repository
echo "Checking secrets-tests repository"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/muh-nee/secrets-tests.git "${REPO_DIR}"

# Test without the static-analysis.datadog.yml file
rm -f "${REPO_DIR}/static-analysis.datadog.yml"
./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results1.json" -f sarif --enable-secrets true --enable-static-analysis false

if [ $? -ne 0 ]; then
  echo "fail to analyze secrets-tests repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results1.json"`

echo "Found $RES errors on first run"

EXPECTING=5

if [ "$RES" -ne "$EXPECTING" ]; then
  echo "incorrect number of errors found, found $RES, expected $EXPECTING"
  exit 1
fi

read -r -d '' JQ_QUERY <<'EOF'
[.runs[].results[] | select(.locations[0].physicalLocation.artifactLocation.uri == $uri)][ $idx ]
| .properties.tags[]?
| select(startswith("DATADOG_SECRET_VALIDATION_STATUS:"))
EOF

status1=$(jq --arg uri "datadog-keys.sh" --argjson idx 0 "$JQ_QUERY" "${REPO_DIR}/results1.json")

if [ "$status1" != "\"DATADOG_SECRET_VALIDATION_STATUS:INVALID\"" ]; then
  echo "status1: did not find DATADOG_SECRET_VALIDATION_STATUS:INVALID in properties, found $status1"
  exit 1
fi

status2=$(jq --arg uri "plop/foo_test.py" --argjson idx 0 "$JQ_QUERY" "${REPO_DIR}/results1.json")

if [ "$status2" != "\"DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED\"" ]; then
  echo "status2: did not find DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED in properties, found $status2"
  exit 1
fi

status3=$(jq --arg uri "plop/foo_test.py" --argjson idx 1 "$JQ_QUERY" "${REPO_DIR}/results1.json")

if [ "$status3" != "\"DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED\"" ]; then
  echo "status3: did not find DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED in properties, found $status3"
  exit 1
fi

## Make sure the SDS ID is added to the SARIF file
status4=`jq '.runs[0].tool.driver.rules[0].properties.tags[] | select(startswith("DATADOG_SDS_ID:"))' "${REPO_DIR}/results1.json"`

if [ -z "$status4" ]; then
  echo "did not find DATADOG_SDS_ID in tags"
  exit 1
fi

echo "All tests passed"

exit 0
