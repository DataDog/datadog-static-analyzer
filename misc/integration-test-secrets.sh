#!/bin/bash

cargo build --profile release-dev --bin datadog-static-analyzer

## A Python repository
echo "Checking secrets-tests repository"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/muh-nee/secrets-tests.git "${REPO_DIR}"

# Test without the static-analysis.datadog.yml file
rm -f "${REPO_DIR}/static-analysis.datadog.yml"
./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results1.json" -f sarif -x --secrets

if [ $? -ne 0 ]; then
  echo "fail to analyze secrets-tests repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results1.json"`

echo "Found $RES errors on first run"

if [ "$RES" -ne "2" ]; then
  echo "incorrect number of errors found"
  exit 1
fi

echo "All tests passed"

exit 0
