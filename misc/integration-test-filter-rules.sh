#!/bin/bash

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

echo "Checking juice shop"
REPO_DIR="$(mktemp -d)"
UNFILTERED_OUTPUT="${REPO_DIR}/results-unfiltered.csv"
FILTERED_OUTPUT="${REPO_DIR}/results-filtered.csv"
EXPECTED_FILTERED_OUT='^test/server/verifySpec.ts,typescript-node-security/|^routes.login.ts,typescript-node-security/sql-injection'
git clone --depth=1 https://github.com/juice-shop/juice-shop.git "${REPO_DIR}"

echo "schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - typescript-node-security
" > "${REPO_DIR}/code-security.datadog.yaml"

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${UNFILTERED_OUTPUT}" -f csv

if [ $? -ne 0 ]; then
  echo "failed to analyze juice-shop (without rule filters)"
  exit 1
fi

if ! grep -E -q "${EXPECTED_FILTERED_OUT}" "${UNFILTERED_OUTPUT}" ; then
  echo "output of no-filters run doesn't contain expected findings"
  exit 1
fi

echo "schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - typescript-node-security
  ruleset-configs:
    typescript-node-security:
      ignore-paths:
        - \"test/*/verifySpec.ts\"
      rule-configs:
        sql-injection:
          only-paths:
            - \"data/static\"
" > "${REPO_DIR}/code-security.datadog.yaml"

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${FILTERED_OUTPUT}" -f csv

if [ $? -ne 0 ]; then
  echo "failed to analyze juice-shop (with rule filters)"
  exit 1
fi

if grep -E -q "${EXPECTED_FILTERED_OUT}" "${FILTERED_OUTPUT}" ; then
  echo "output of run with filters contains findings that should have been excluded"
  exit 1
fi

echo "All tests passed"

exit 0
