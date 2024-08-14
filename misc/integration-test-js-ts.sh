#!/bin/bash

cargo build --profile release-dev --bin datadog-static-analyzer

echo "Checking juice shop"
REPO_DIR=$(mktemp -d)
export REPO_DIR
git clone --depth=1 https://github.com/juice-shop/juice-shop.git "${REPO_DIR}"
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

./target/release-dev/datadog-static-analyzer --directory "${REPO_DIR}" -o "${REPO_DIR}/results.json" -f sarif -x

if [ $? -ne 0 ]; then
  echo "fail to analyze juice-shop"
  exit 1
fi

FINDINGS=`jq '.runs[0].results|length' ${REPO_DIR}/results.json`
echo "Found $FINDINGS violations"
if [ $FINDINGS -lt 10 ]; then
  echo "only $FINDINGS found, expecting at least 10 findings"
  exit 1
fi

echo "All tests passed"

exit 0
