#!/bin/bash

echo "Checking juice shop"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone https://github.com/juice-shop/juice-shop.git "${REPO_DIR}"
echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - javascript-best-practices" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - typescript-best-practices" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - javascript-common-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - typescript-common-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - javascript-inclusive" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - typescript-inclusive" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - javascript-code-style" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - jsx-react" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - tsx-react" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - javascript-node-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - typescript-node-security" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - javascript-best-practices" >> "${REPO_DIR}/static-analysis.datadog.yml"

./target/release/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze juice-shop"
  exit 1
fi

echo "All tests passed"

exit 0
