#!/bin/bash

## Test that we find errors on repositories with different encoding.
## The repository https://github.com/muh-nee/sast-files-encoding.git contains
## code with different encodings.

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

## An R repository
echo "Checking muh-nee/sast-files-encoding"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/muh-nee/sast-files-encoding.git "${REPO_DIR}"

echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-security" >> "${REPO_DIR}/static-analysis.datadog.yml"

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "failed to analyze muh-nee/sast-files-encoding"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results.json"`

echo "Found $RES errors"

if [ "$RES" -lt "2" ]; then
  echo "not enough errors found"
  exit 1
fi

echo "All tests passed"

exit 0
