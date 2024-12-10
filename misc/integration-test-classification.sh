#!/bin/bash

# This integration test clones a repo that has intentional violations in every single `js` file.
# It tests that:
# * Each `js` file has exactly one detection.
# * The SARIF `artifacts` array contains exactly one object for each file.
# * A file name that starts with "should_be_t_file" should have its SARIF artifact tagged as a test file
#   (Note that the analyzer itself does not use this specific name as a detection -- this naming schema
#   is used as a way to declaratively and robustly define the test corpus).
# * A file name not starting with that string should not have its SARIF artifact tagged as a test file.

# The SARIF property bag tag that a test file artifact should have.
TEST_FILE_TAG="DATADOG_ARTIFACT_IS_TEST_FILE"

REPO_DIR=$(mktemp -d)
git clone --depth=1 https://github.com/muh-nee/classification-tests.git "${REPO_DIR}" || {
    echo "Unable to clone repository"
    exit 1
}

# Gather paths for all "js" files.
js_files=()
while IFS= read -r -d $'\0' file; do
    relative_path="${file#$REPO_DIR/}"
    js_files+=("$relative_path")
done < <(find "${REPO_DIR}" -type f -name "*.js" -print0)
IFS=$'\n' sorted_js_files=($(sort <<<"${js_files[*]}"))
unset IFS

cargo build --profile release-dev --bin datadog-static-analyzer

RESULTS_FILE="${REPO_DIR}/results.json"
cargo run --profile release-dev --bin datadog-static-analyzer -- --directory "${REPO_DIR}" -o "${RESULTS_FILE}" -f sarif || {
    echo "Analysis failed"
    exit 1
}

violation_paths=($(jq -r '.runs[0].results[] | .locations[0].physicalLocation.artifactLocation.uri' "${RESULTS_FILE}"))
artifact_paths=($(jq -r '.runs[0].artifacts[] | .location.uri' "${RESULTS_FILE}"))
IFS=$'\n' sorted_violation_paths=($(sort <<<"${violation_paths[*]}"))
IFS=$'\n' sorted_artifact_paths=($(sort <<<"${artifact_paths[*]}"))
unset IFS

# Test invariant: each JavaScript file will have exactly 1 violation.
# The most straightforward way to do this is compare a (sorted) list of paths from the violations and artifacts with
# the (sorted) list of paths we discovered earlier with the `find` command.
for i in "${!sorted_js_files[@]}"; do
    if [[ "${sorted_js_files[i]}" != "${sorted_violation_paths[i]}" ]]; then
        echo "Test invariant broken: each js file must have exactly 1 violation. missing one for \"${sorted_js_files[i]}\""
        exit 1
    fi
    if [[ "${sorted_js_files[i]}" != "${sorted_artifact_paths[i]}" ]]; then
        echo "Test invariant broken: each js file should be a SARIF artifact. missing one for \"${sorted_js_files[i]}\""
        exit 1
    fi
done

file_count=${#sorted_js_files[@]}
for ((i = 0; i < file_count; i++)); do
    uri=$(jq -r ".runs[0].artifacts[${i}].location.uri" ${RESULTS_FILE})
    filename=$(basename "${uri}")

    has_tag=false
    if jq -e --arg expected_tag "${TEST_FILE_TAG}" ".runs[0].artifacts[${i}].properties.tags | index(\$expected_tag) != null" ${RESULTS_FILE} >/dev/null; then
        has_tag=true
    fi

    # Test invariant: files starting with "should_be_t_file" are expected to have a "test file" classification.
    # Others should not.
    if [[ "${filename}" == should_be_t_file* ]]; then
        if [[ "${has_tag}" == false ]]; then
            echo "${uri} should have \`${TEST_FILE_TAG}\` property tag"
            exit 1
        fi
    else
        if [[ "${has_tag}" == true ]]; then
            echo "${uri} should not have \`${TEST_FILE_TAG}\` property tag"
            exit 1
        fi
    fi
done

echo "All tests passed"
exit 0
