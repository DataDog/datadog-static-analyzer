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
./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results1.json" -f sarif -x --enable-secrets true

if [ $? -ne 0 ]; then
  echo "fail to analyze secrets-tests repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results1.json"`

echo "Found $RES errors on first run"

if [ "$RES" -ne "3" ]; then
  echo "incorrect number of errors found"
  exit 1
fi

status1=`jq '.runs[0].results[0].properties.tags[1]' "${REPO_DIR}/results1.json"`

if [ "$status1" != "\"DATADOG_SECRET_VALIDATION_STATUS:INVALID\"" ]; then
  echo "status1: did not find DATADOG_SECRET_VALIDATION_STATUS:INVALID in properties, found $status1"
  exit 1
fi

status2=`jq '.runs[0].results[1].properties.tags[1]' "${REPO_DIR}/results1.json"`

if [ "$status2" != "\"DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED\"" ]; then
  echo "status2: did not find DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED in properties, found $status2"
  exit 1
fi

status3=`jq '.runs[0].results[2].properties.tags[1]' "${REPO_DIR}/results1.json"`

if [ "$status3" != "\"DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED\"" ]; then
  echo "status3: did not find DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED in properties, found $status3"
  exit 1
fi

echo "All tests passed"

exit 0
