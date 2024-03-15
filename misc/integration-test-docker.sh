#!/bin/bash

cargo build -r --bin datadog-static-analyzer

## A Python repository
echo "Checking docker repository"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/juli1/dd-sa-dockerfile.git "${REPO_DIR}"

echo "Try without the static-analysis.datadog.yml file"
rm -f "${REPO_DIR}/static-analysis.datadog.yml"
./target/release/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results1.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze docker repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results1.json"`

echo "Found $RES errors on first run"

if [ "$RES" -lt "12" ]; then
  echo "not enough errors found without the static-analysis.datadog.yml file"
  exit 1
fi

echo "Try with the static-analysis.datadog.yml file"

echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - docker-best-practices" >> "${REPO_DIR}/static-analysis.datadog.yml"

./target/release/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results2.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze docker repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results2.json"`

echo "Found $RES errors on first run"

if [ "$RES" -lt "8" ]; then
  echo "not enough errors found with the static-analysis.datadog.yml file"
  exit 1
fi

echo "All tests passed"

exit 0
