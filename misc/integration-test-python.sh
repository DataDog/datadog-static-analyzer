#!/bin/bash

cargo build -r

## A Python repository
echo "Checking django repository"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone https://github.com/gothinkster/django-realworld-example-app.git "${REPO_DIR}"

# Test without the static-analysis.datadog.yml file
rm -f "${REPO_DIR}/static-analysis.datadog.yml"
./target/release/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze django repository"
  exit 1
fi

# Test with the static-analysis.datadog.yml file

echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-best-practices" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-django" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-inclusive" >> "${REPO_DIR}/static-analysis.datadog.yml"

./target/release/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze django repository"
  exit 1
fi

echo "All tests passed"

exit 0
