#!/bin/bash

cargo build -r --bin datadog-static-analyzer

if [ "$USE_DDSA" = "true" ]; then
    runtime_flag="--ddsa-runtime"
else
    runtime_flag=""
fi

echo "Checking juice shop"
REPO_DIR="$(mktemp -d)"
UNFILTERED_OUTPUT="${REPO_DIR}/results-unfiltered.csv"
FILTERED_OUTPUT="${REPO_DIR}/results-filtered.csv"
EXPECTED_FILTERED_OUT='^test/server/verifySpec.ts,typescript-node-security/|^routes.login.ts,typescript-node-security/sql-injection'
git clone --depth=1 https://github.com/juice-shop/juice-shop.git "${REPO_DIR}"

cat << EOT > "${REPO_DIR}/static-analysis.datadog.yml"
rulesets:
  - typescript-node-security
EOT

./target/release/datadog-static-analyzer "${runtime_flag}" --directory "${REPO_DIR}" -o "${UNFILTERED_OUTPUT}" -f csv

if [ $? -ne 0 ]; then
  echo "failed to analyze juice-shop (without rule filters)"
  exit 1
fi

if ! grep -E -q "${EXPECTED_FILTERED_OUT}" "${UNFILTERED_OUTPUT}" ; then
  echo "output of no-filters run doesn't contain expected findings"
  exit 1
fi

cat << EOT > "${REPO_DIR}/static-analysis.datadog.yml"
rulesets:
  - typescript-node-security:
    ignore:
      - "test/*/verifySpec.ts"
    rules:
      sql-injection:
        only:
          - "data/static"
EOT

./target/release/datadog-static-analyzer "${runtime_flag}" --directory "${REPO_DIR}" -o "${FILTERED_OUTPUT}" -f csv

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
