#!/bin/bash

cargo build -r --bin datadog-static-analyzer-test-config

exit_code=0

for file in schema/examples/valid/*
do
  if ! ./target/release/datadog-static-analyzer-test-config -c "${file}" -e valid
  then
    exit_code=1
  fi
done

for file in schema/examples/invalid/*
do
  if ! ./target/release/datadog-static-analyzer-test-config -c "${file}" -e invalid
  then
    exit_code=1
  fi
done

exit "${exit_code}"
