#!/bin/bash


cargo build -r
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone https://github.com/juli1/rosie-tests.git "${REPO_DIR}"
./target/release/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" --debug yes -b -f sarif -x -g
CATEGORY=$(jq '.runs[0].results[0].properties.tags[0]' "${REPO_DIR}/results.json")
FIRST_SHA=$(jq '.runs[0].results[] | select( .ruleId | contains("python-security/subprocess-shell-true")).properties.tags[1]' "${REPO_DIR}/results.json")
SECOND_SHA=$(jq '.runs[0].results[] | select( .ruleId | contains("python-security/yaml-load")).properties.tags[1]' "${REPO_DIR}/results.json")

if [ "${CATEGORY}" != "\"DATADOG_CATEGORY:SECURITY\"" ]; then
  echo "invalid category ${CATEGORY}"
  exit 1
fi

if [ "${FIRST_SHA}" != "\"SHA:5509900dc490cedbe2bb64afaf43478e24ad144b\"" ]; then
  echo "invalid first SHA ${FIRST_SHA}"
  exit 1
fi


if [ "${SECOND_SHA}" != "\"SHA:8c5080ff058d5d34961b9941ef498fc238be1caf\"" ]; then
  echo "invalid second SHA ${SECOND_SHA}"
  exit 1
fi

exit 0
