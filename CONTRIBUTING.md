# Contributing

## Code Organization

The code is organized into four crates:

 - `static-analysis-kernel`: the core of the analyzer that is used either by the server or the command-line
 - `cli`: code only for the command-line interface (e.g. get rules from API/json)
 - `static-analysis-server`: code only for the server (e.g. receiving requests and send back response)
 - `bins`: code for the binaries that references code in `cli` or `static-analysis-erver`

## Code Quality

There is a git hook set up with [cargo husky](https://lib.rs/crates/cargo-husky)
that checks your code complies with good coding guidelines.

It runs clippy, rust-fmt and tests before commit and pushing code.

There is also a [GitHub action](.github/workflows/rust.yaml) set up to
enforce code quality rules once the code is committed.

## Contribute

Please contribute any way you want. It may be by submitting new issues,
making a pull request.

Some rules to contribute to the project:

 - any code change or new feature must have a change
 - always enforce the rule of least requirement. In other words, do not put in `static-analysis-kernel` code that is related only to the `cli`
 - all tests and checks must pass
 - please be respectful of other projects contributors
 - if you add a new dependency, add the relevant information in the file `LICENSE-3rdparty.csv`