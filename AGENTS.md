## Overview

This project is Datadog's static analyzer and secret detection tool, used to find code patterns, detect violations, and identify secrets.

The static code analysis part relies heavily on tree-sitter.

Secret detection relies on Datadog SDS.

## Code Structure

- `crates/bin` contains all the binaries
- `crates/cli` contains all code for the command-line features (creating CSV, manipulating files, etc)
- `crates/common` contains all code common to the CLI and the server
- `crates/secrets` contains the code specific to the secrets scanning product
- `crates/static-analysis-kernel` contains the code specific to the static analyzer
- `crates/static-analysis-server` contains the code specific to the static analyzer server (used in IDE)

## Testing

1. Always add a test when adding code.
2. NEVER write table tests.
3. Always run tests (e.g. `cargo test`)
4. Always run the format checker `cargo fmt -- --check`
5. Always run clippy `cargo clippy -- -D warnings`

## How to release a new version?

Invoke the script `./misc/release.sh`
