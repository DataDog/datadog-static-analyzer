#!/bin/bash

cargo build -r --bin datadog-static-analyzer

if [ "$USE_DDSA" = "true" ]; then
    runtime_flag="--ddsa-runtime"
else
    runtime_flag=""
fi

## A Python repository
echo "Checking django repository"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/gothinkster/django-realworld-example-app.git "${REPO_DIR}"

# Test without the static-analysis.datadog.yml file
rm -f "${REPO_DIR}/static-analysis.datadog.yml"
./target/release/datadog-static-analyzer "${runtime_flag}" --directory "${REPO_DIR}" -o "${REPO_DIR}/results1.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze django repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results1.json"`

echo "Found $RES errors on first run"

if [ "$RES" -lt "18" ]; then
  echo "not enough errors found"
  exit 1
fi

# Test with the static-analysis.datadog.yml file
echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-best-practices" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-django" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-inclusive" >> "${REPO_DIR}/static-analysis.datadog.yml"

./target/release/datadog-static-analyzer "${runtime_flag}" --directory "${REPO_DIR}" -o "${REPO_DIR}/results2.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze django repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results2.json"`

echo "Found $RES errors on second run"

if [ "$RES" -lt "18" ]; then
  echo "not enough errors found"
  exit 1
fi

# Test that --fail-on-any-violation returns a non-zero return code
./target/release/datadog-static-analyzer "${runtime_flag}" --directory "${REPO_DIR}" -o "${REPO_DIR}/results2.json" -f sarif -x --fail-on-any-violation=none,notice,warning,error

if [ $? -eq 0 ]; then
  echo "static analyzer reports 0 when it should not"
  exit 1
fi

echo "All tests passed"

exit 0
