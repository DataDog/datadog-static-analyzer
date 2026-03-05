#!/bin/bash

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

echo "Checking juice shop"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/juice-shop/juice-shop.git "${REPO_DIR}"
echo "schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - javascript-best-practices
    - typescript-best-practices
    - javascript-common-security
    - typescript-common-security
    - javascript-inclusive
    - typescript-inclusive
    - javascript-code-style
    - jsx-react
    - tsx-react
    - javascript-node-security
    - typescript-node-security
" > "${REPO_DIR}/code-security.datadog.yaml"

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif

if [ $? -ne 0 ]; then
  echo "fail to analyze juice-shop"
  exit 1
fi

FINDINGS=`jq '.runs[0].results|length' ${REPO_DIR}/results.json`
echo "Found $FINDINGS violations"
if [ $FINDINGS -lt 1 ]; then
  echo "test invariant: expected at least 1 violation"
  exit 1
fi

echo "All tests passed"

exit 0
