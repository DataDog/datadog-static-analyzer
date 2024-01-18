#!/bin/bash

# This integration test for datadog-static-analyzer
# 1. Check out a basic repo
# 2. Run the latest version of the analyzer on it
# 3. Check that we get the SHA of the commit and the category in the output SARIF file.

## First, test a repository to check that the commit that indicates the repo information for a violation
echo "Checking rosie tests"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone https://github.com/juli1/rosie-tests.git "${REPO_DIR}"
./target/release/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif -x -g
if [ $? -ne 0 ]; then
  echo "fail to analyze rosie-tests"
  exit 1
fi

# Getting the category of the fist violation detected (all violations in this report are security)
CATEGORY=$(jq '.runs[0].results[0].properties.tags[0]' "${REPO_DIR}/results.json")

# Getting the SHA of the violation detected by the rule python-security/subprocess-shell-true
FIRST_SHA=$(jq '.runs[0].results[] | select( .ruleId | contains("python-security/subprocess-shell-true")).partialFingerprints["SHA"]' "${REPO_DIR}/results.json")

# Getting the SHA of the violation detected by the rule python-security/yaml-load
SECOND_SHA=$(jq '.runs[0].results[] | select( .ruleId | contains("python-security/yaml-load")).partialFingerprints["SHA"]' "${REPO_DIR}/results.json")

if [ "${CATEGORY}" != "\"DATADOG_CATEGORY:SECURITY\"" ]; then
  echo "invalid category ${CATEGORY}"
  exit 1
fi

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
