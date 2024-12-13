#!/bin/bash

# This tests the `datadog-static-analyzer` binary to ensure test file classification is output correctly.
# See `./helpers/test-classification.sh` for test logic.

REPO_DIR=$(mktemp -d)
RESULTS_FILE="${REPO_DIR}/results.json"

cargo build --profile release-dev --bin datadog-static-analyzer

ANALYSIS_CMD='cargo run --profile release-dev --bin datadog-static-analyzer -- --directory "${REPO_DIR}" -o "${RESULTS_FILE}" -f sarif'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${SCRIPT_DIR}/helpers/test-classification.sh" "${ANALYSIS_CMD}" "${REPO_DIR}" "${RESULTS_FILE}" || {
    rm -rf $(mktemp -d)
    echo "Test failed"
    exit 1
}

rm -rf $(mktemp -d)

echo "All tests passed"
exit 0
