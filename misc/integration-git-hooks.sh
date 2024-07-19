#!/bin/bash

cargo build --profile release-dev --bin datadog-static-analyzer-git-hooks

## A Python repository
REPO_DIR=$(mktemp -d)
echo "Creating a new repository in ${REPO_DIR}"
export REPO_DIR
git init --initial-branch=main "${REPO_DIR}"
touch "${REPO_DIR}/README.md"
(cd "${REPO_DIR}" && git add README.md)
(cd "${REPO_DIR}" && git commit -m"initial commit")

## Creating a new branch and adding a new file with a secret
(cd "${REPO_DIR}" && git checkout -b new-branch)
echo "AKIAIOSFODNN7EXAMPLE" > "${REPO_DIR}/foobar"
(cd "${REPO_DIR}" && git add foobar )
(cd "${REPO_DIR}" && git commit -a -m"add foobar")


## Secrets should be found
./target/release-dev/datadog-static-analyzer-git-hooks --repository "${REPO_DIR}" --secrets --staging --debug yes --default-branch main >/tmp/plop 2>&1

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

rm -rf "${REPO_DIR}"

echo "All tests passed"

exit 0
