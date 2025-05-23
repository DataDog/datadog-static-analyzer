#!/bin/bash

# This integration test for datadog-static-analyzer
# 1. Check out a basic repo
# 2. Run the latest version of the analyzer on it
# 3. Check that we get the SHA of the commit and the category in the output SARIF file.

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

## First, test a repository to check that the commit that indicates the repo information for a violation
echo "Checking rosie tests"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone https://github.com/juli1/rosie-tests.git "${REPO_DIR}" \
     && git -C "${REPO_DIR}" checkout 37874bd2fcb1d39a9ce4a614e6a07826e04d0cb1 -q

echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif -g
if [ $? -ne 0 ]; then
  echo "fail to analyze rosie-tests"
  exit 1
fi

# Getting the SHA of the violation detected by the rule python-security/subprocess-shell-true
FIRST_SHA=$(jq '.runs[0].results[] | select( .ruleId | contains("python-security/subprocess-shell-true")).partialFingerprints["SHA"]' "${REPO_DIR}/results.json")

# Getting the SHA of the violation detected by the rule python-security/yaml-load
SECOND_SHA=$(jq '.runs[0].results[] | select( .ruleId | contains("python-security/yaml-load")).partialFingerprints["SHA"]' "${REPO_DIR}/results.json")

if [ "${FIRST_SHA}" != "\"5509900dc490cedbe2bb64afaf43478e24ad144b\"" ]; then
  echo "invalid first SHA ${FIRST_SHA}"
  exit 1
fi


if [ "${SECOND_SHA}" != "\"8c5080ff058d5d34961b9941ef498fc238be1caf\"" ]; then
  echo "invalid second SHA ${SECOND_SHA}"
  exit 1
fi

echo "All tests passed"

exit 0
