#!/bin/bash

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

## A Python repository
echo "Checking docker repository"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/juli1/dd-sa-dockerfile.git "${REPO_DIR}"

echo "schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - docker-best-practices
" > "${REPO_DIR}/code-security.datadog.yaml"

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif

if [ $? -ne 0 ]; then
  echo "fail to analyze docker repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results.json"`

echo "Found $RES errors on first run"

if [ "$RES" -lt "1" ]; then
  echo "test invariant: expected at least 1 violation"
  exit 1
fi

echo "All tests passed"

exit 0
