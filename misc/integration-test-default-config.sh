#!/bin/bash

# This test ensures that an invocation of the analyzer fetches a default configuration (if it exists and credentials are valid).

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

SARIF_FILENAME="results.json"

rm -f "${REPO_DIR}/static-analysis.datadog.yml"
./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/${SARIF_FILENAME}" -f sarif

sarif_ruleset_count=$(jq '[.runs[0].tool.driver.rules[].id | split("/") | .[0]] | unique | length' "${REPO_DIR}/${SARIF_FILENAME}") \
    || { echo "failed to parse SARIF ruleset count" >&2; exit 1; }

if ! [[ "${sarif_ruleset_count}" =~ ^[0-9]+$ ]]; then
  echo "expected jq to output an integer for sarif_ruleset_count, got \`${sarif_ruleset_count}\`" >&2
  exit 1
fi

if [[ "${sarif_ruleset_count}" -le 1 ]]; then
  echo "expected at least one ruleset to have been fetched" >&2
  exit 1
fi

echo "All tests passed"
exit 0
