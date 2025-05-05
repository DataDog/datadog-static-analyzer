#!/bin/bash

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

## A Python repository
echo "Checking django repository"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/gothinkster/django-realworld-example-app.git "${REPO_DIR}"


echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-best-practices" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-django" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-inclusive" >> "${REPO_DIR}/static-analysis.datadog.yml"

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif

cat "${REPO_DIR}/results.json"

if [ $? -ne 0 ]; then
  echo "fail to analyze django repository"
  exit 1
fi

RES=`jq '.runs[0].results | length ' "${REPO_DIR}/results.json"`

echo "Found $RES errors"

if [ "$RES" -lt "1" ]; then
  echo "test invariant: expected at least 1 violation"
  exit 1
fi

# Test that --fail-on-any-violation returns a non-zero return code
./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif --fail-on-any-violation=none,notice,warning,error

if [ $? -eq 0 ]; then
  echo "static analyzer reports 0 when it should not"
  exit 1
fi

echo "All tests passed"

exit 0
