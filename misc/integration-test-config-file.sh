#!/bin/bash

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

# (An arbitrary repository that contains at least one file with an extension supported by datadog-static-analyzer)
#
# Note that we override the repo name to be `datadog-static-analyzer-test-repo` (which is set up to have a repo-specific
# configuration to ensure a stable test setup)
REPO_DIR=$(mktemp -d)
git clone https://github.com/juli1/rosie-tests.git "${REPO_DIR}" \
    && git -C "${REPO_DIR}" checkout 37874bd2fcb1d39a9ce4a614e6a07826e04d0cb1 -q \
    && git -C "${REPO_DIR}" remote set-url origin https://github.com/DataDog/datadog-static-analyzer-test-repo

echo "schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - python-security
    - python-best-practices
  ignore-rulesets:
    - python-security
" > "${REPO_DIR}/code-security.datadog.yaml"

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif

if [ $? -ne 0 ]; then
  echo "failed to analyze repository"
  exit 1
fi

# Resulting SARIF should only have run python-best-practices:

ignored_rule_count=$(jq '[.runs[0].tool.driver.rules[].id | select(startswith("python-security/"))] | length' "${REPO_DIR}/results.json")
if [ "${ignored_rule_count}" -ne 0 ]; then
  echo "expected python-security ruleset to have been ignored"
  exit 1
fi

included_rule_count=$(jq '[.runs[0].tool.driver.rules[].id | select(startswith("python-best-practices/"))] | length' "${REPO_DIR}/results.json")
if [ "${included_rule_count}" -eq 0 ]; then
  echo "expected python-best-practices ruleset to have been used"
  exit 1
fi

echo "All tests passed"
exit 0
