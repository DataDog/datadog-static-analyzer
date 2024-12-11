#!/bin/bash

cargo build --profile release-dev --bin datadog-static-analyzer-git-hook

## A Python repository
REPO_DIR=$(mktemp -d)
echo "Creating a new repository in ${REPO_DIR}"
export REPO_DIR
git init --initial-branch=main "${REPO_DIR}"
touch "${REPO_DIR}/README.md"
(cd "${REPO_DIR}" && git add README.md)
(cd "${REPO_DIR}" && git config user.email "you@example.com")
(cd "${REPO_DIR}" && git config user.name "Your Name")
(cd "${REPO_DIR}" && git commit -m"initial commit")
SHA1=$(cd $REPO_DIR && git rev-parse HEAD)

## Creating a new branch and adding a new file with a secret
(cd "${REPO_DIR}" && git checkout -b new-branch)
echo "rulesets:"> "${REPO_DIR}/static-analysis.datadog.yml"
echo " - python-code-style" >> "${REPO_DIR}/static-analysis.datadog.yml"
echo "aws_access_key_id AKIAIOSFODNN7EXAMPLE" > "${REPO_DIR}/foobar"
(cd "${REPO_DIR}" && git add foobar)
(cd "${REPO_DIR}" && git add static-analysis.datadog.yml)
(cd "${REPO_DIR}" && git commit -a -m"add foobar")
SHA2=$(cd $REPO_DIR && git rev-parse HEAD)

########################################################
# TEST: Secrets should be found using the default branch
########################################################

echo "Starting test: secrets should be found using the default branch"

./target/release-dev/datadog-static-analyzer-git-hook --repository "${REPO_DIR}" --secrets --debug yes --default-branch main --output /tmp/git-hook.sarif >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  cat /tmp/plop
  echo "secrets should have been found"
  exit 1
fi

## Print output
cat /tmp/plop

NB_OCCURRENCES=$(grep "secret found on file foobar" /tmp/plop | wc -l)
echo "Found ${NB_OCCURRENCES} secret"
if [ "${NB_OCCURRENCES}" -ne "1" ]; then
  cat /tmp/plop
  echo "secrets should have been found"
  exit 1
fi

NB_ERRORS_IN_SARIF_FILE=`jq '.runs[0].results | length' /tmp/test.sarif`
if [ "${NB_ERRORS_IN_SARIF_FILE}" -ne "1" ]; then
    echo "secrets not found in SARIF file"
    exit 1
fi

#############################################################
# TEST: Secrets should be found using two sha (start and end)
#############################################################
echo "Starting test: secrets should be found using two sha"

./target/release-dev/datadog-static-analyzer-git-hook --repository "${REPO_DIR}" --secrets --debug yes --sha-start $SHA1 --sha-end $SHA2 >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  cat /tmp/plop
  echo "secrets should have been found"
  exit 1
fi

## Print output
cat /tmp/plop

NB_OCCURRENCES=$(grep "secret found on file foobar" /tmp/plop | wc -l)
echo "Found ${NB_OCCURRENCES} secret"
if [ "${NB_OCCURRENCES}" -ne "1" ]; then
  echo "secrets should have been found"
  cat /tmp/plop
  exit 1
fi


###################################
# TEST: Find static analysis issues
###################################
echo "Starting test: static analysis errors found"

# Add code with a violation

echo "def apiProduct_add():" > "${REPO_DIR}/mycode.py"
echo "  pass" >> "${REPO_DIR}/mycode.py"
(cd "${REPO_DIR}" && git add mycode.py )
(cd "${REPO_DIR}" && git commit -a -m"add static analysis violation")
SHA3=$(cd $REPO_DIR && git rev-parse HEAD)

echo "starting analyzer between $SHA2 and $SHA3"

./target/release-dev/datadog-static-analyzer-git-hook --repository "${REPO_DIR}" --static-analysis --secrets --debug yes --sha-start $SHA2 --sha-end $SHA3 >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  echo "static analysis issues should have been found"
  cat /tmp/plop
  exit 1
fi

## Print output
cat /tmp/plop

NB_OCCURRENCES=$(grep "type: python-code-style/function-naming" /tmp/plop | wc -l)
echo "Found ${NB_OCCURRENCES} violations for python-code-style/function-naming"
if [ "${NB_OCCURRENCES}" -ne "1" ]; then
  echo "violations should have been found"
  exit 1
fi

################################################
# TEST: Test error when a branch does not exists
################################################

echo "Starting test: error when a branch does not exists"

./target/release-dev/datadog-static-analyzer-git-hook --repository "${REPO_DIR}" --secrets --debug yes --default-branch mainwefwef >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  echo "branch cannot be found"
  exit 1
fi

## Print output
cat /tmp/plop

NB_OCCURRENCES=$(grep "cannot locate local branch" /tmp/plop | wc -l)
if [ "${NB_OCCURRENCES}" -ne "1" ]; then
  echo "cannot locate local branch is not found in tool output"
  cat /tmp/plop
  exit 1
fi

###############################################################
# TEST: Do not pass --static-analysis or --secrets and it fails
###############################################################

echo "Starting test: error when not specifying --static-analysis or --secret"

./target/release-dev/datadog-static-analyzer-git-hook --repository "${REPO_DIR}" --debug yes --default-branch mainwefwef >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  cat /tmp/plop
  echo "program should return an error if --static-analysis or --secrets are not passed"
  exit 1
fi

echo "All secrets tests passed"
rm -rf "${REPO_DIR}"

################################################
## TEST: Artifact classification works correctly
################################################
REPO_DIR=$(mktemp -d)
RESULTS_FILE="${REPO_DIR}/results.json"
ANALYSIS_CMD='\
(
    cd "${REPO_DIR}"
    git config user.email "user@example.com"
    git config user.name "User Name"
    find "${REPO_DIR}" -type f -name "*.js" | while read -r file; do
      printf "\nconst violation = new Date;\n" >> "$file"
    done
    git checkout -b some_unused_branch_name --quiet
    git add .
    git commit -m "Add violations" --quiet
) && \
cargo run --profile release-dev --bin \
datadog-static-analyzer-git-hook -- \
--static-analysis --default-branch main --repository "${REPO_DIR}" --output "${RESULTS_FILE}"'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${SCRIPT_DIR}/_test-classification.sh" "${ANALYSIS_CMD}" "${REPO_DIR}" "${RESULTS_FILE}" || {
    rm -rf "${REPO_DIR}"
    echo "Test failed"
    exit 1
}

rm -rf "${REPO_DIR}"

echo "All artifact classification tests passed"

echo "All tests passed"
exit 0
