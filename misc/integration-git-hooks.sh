#!/bin/bash

cargo build --profile release-dev --bin datadog-static-analyzer-git-hooks

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
echo "AKIAIOSFODNN7EXAMPLE" > "${REPO_DIR}/foobar"
(cd "${REPO_DIR}" && git add foobar )
(cd "${REPO_DIR}" && git commit -a -m"add foobar")
SHA2=$(cd $REPO_DIR && git rev-parse HEAD)

########################################################
# TEST: Secrets should be found using the default branch
########################################################

echo "Starting test: secrets should be found using the default branch"

./target/release-dev/datadog-static-analyzer-git-hooks --repository "${REPO_DIR}" --secrets --debug yes --default-branch main >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  echo "secrets should have been found"
  exit 1
fi

## Print output
cat /tmp/plop

NB_OCCURRENCES=$(grep "secret found on file foobar" /tmp/plop | wc -l)
echo "Found ${NB_OCCURRENCES} secret"
if [ "${NB_OCCURRENCES}" -ne "1" ]; then
  echo "secrets should have been found"
  exit 1
fi

#############################################################
# TEST: Secrets should be found using two sha (start and end)
#############################################################
echo "Starting test: secrets should be found using two sha"

./target/release-dev/datadog-static-analyzer-git-hooks --repository "${REPO_DIR}" --secrets --debug yes --sha-start $SHA1 --sha-end $SHA2 >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  echo "secrets should have been found"
  exit 1
fi

## Print output
cat /tmp/plop

NB_OCCURRENCES=$(grep "secret found on file foobar" /tmp/plop | wc -l)
echo "Found ${NB_OCCURRENCES} secret"
if [ "${NB_OCCURRENCES}" -ne "1" ]; then
  echo "secrets should have been found"
  exit 1
fi

################################################
# TEST: Test error when a branch does not exists
################################################

echo "Starting test: error when a branch does not exists"

./target/release-dev/datadog-static-analyzer-git-hooks --repository "${REPO_DIR}" --secrets --debug yes --default-branch mainwefwef >/tmp/plop 2>&1

if [ $? -ne 1 ]; then
  echo "branch cannot be found"
  exit 1
fi

## Print output
cat /tmp/plop

NB_OCCURRENCES=$(grep "cannot locate local branch" /tmp/plop | wc -l)
if [ "${NB_OCCURRENCES}" -ne "1" ]; then
  echo "cannot locate local branch is not found in tool output"
  exit 1
fi

echo "All tests passed"
rm -rf "${REPO_DIR}"
exit 0
