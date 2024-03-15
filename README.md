# Datadog Static Analyzer

> [!TIP]
> Datadog supports open source projects. Learn more on [Datadog for Open Source Projects](https://www.datadoghq.com/partner/open-source/).

datadog-static-analyzer is the static analyzer engine for Datadog [static analysis](https://www.datadoghq.com/code-analysis/).

## How to use Datadog Static Analysis Tool


### Quick Start

1. Download the binary from the [releases](https://github.com/DataDog/datadog-static-analyzer/releases)
2. Run the analyzer on your repository (as shown below)
3. It will run the analyzer with the default rules available for the support languages

```shell
datadog-static-analyzer --directory /path/to/directory --output report.csv --format csv
```

If you encounter an issue, read the [Frequently Asked Questions](FAQ.md) first, it may contain
the solution to your problem.

### Advanced Usage

You can choose the rules to use to scan your repository by creating a `static-analysis.datadog.yml` file.

First, make sure you follow the [documentation](https://docs.datadoghq.com/code_analysis/static_analysis)
and create a `static-analysis.datadog.yml` file at the root of your project with the rulesets you want to use.

All the rules can be found on the [Datadog documentation](https://docs.datadoghq.com/code_analysis/static_analysis_rules). Your `static-analysis.datadog.yml` may only contain rulesets available from the [Datadog documentation](https://docs.datadoghq.com/code_analysis/static_analysis_rules)

Example of YAML file

```yaml
schema-version: v1
rulesets:
  - python-code-style
  - python-best-practices
  - python-inclusive
ignore-paths:
  - tests
```


### CI/CD Integration

You can use it in your CI/CD pipeline using our integration:
- [GitHub Action](https://github.com/DataDog/datadog-static-analyzer-github-action)
- [CircleCI ORB](https://circleci.com/developer/orbs/orb/datadog/datadog-static-analyzer-circleci-orb)

If you use it in your own CI/CD pipeline, you can integrate the tool directly: see the [Datadog documentation for more information](https://docs.datadoghq.com/code_analysis/static_analysis/setup).


### IntelliJ JetBrains products

The [Datadog IntelliJ extension](https://plugins.jetbrains.com/plugin/19495-datadog) allows you to use the static analyzer directly from all JetBrains products.
Create a `static-analysis.datadog.yml` file, download the extension and you can start using it. You can see below an example of a suggestion to add a timeout
when fetching data with Python with the requests module.

![Datadog Static Analysis JetBrains](misc/imgs/jetbrains.gif)


### VS Code

The [Datadog VS Code extension](https://marketplace.visualstudio.com/items?itemName=Datadog.datadog-vscode) allows you to use the static analyzer directly from VS Code.
Create a `static-analysis.datadog.yml` file, download the extension and you can start using it.

![Datadog Static Analysis JetBrains](misc/imgs/vscode.gif)

## List of rulesets

When you onboard on the Datadog product, you can select the ruleset you want/need. If you are not using Datadog directly, 
there is the list of common used rulesets available in the Datadog static analysis product per language.

The complete list is available in [our documentation](https://docs.datadoghq.com/code_analysis/static_analysis/setup/).

The list of rulesets is available in [RULESETS.md](RULESETS.md).

## Download

Download the latest release for your system and architecture from the [release page](https://github.com/DataDog/datadog-static-analyzer/releases/latest).

To get the static analyzer via shell:

```shell
curl -L -O https://www.github.com/DataDog/datadog-static-analyzer/releases/latest/download/datadog-static-analyzer-<target>.zip
```

Example to get the x86_64 binary for Linux:

```shell
curl -L -O https://www.github.com/DataDog/datadog-static-analyzer/releases/latest/download/datadog-static-analyzer-x86_64-unknown-linux-gnu.zip
```

## Usage

```shell
datadog-static-analyzer -i <directory> -o <output-file>
```

For the tool to work, you must have a `<directory>/static-analysis.datadog.yml` file that defines the configuration of the analyzer. This file will indicate the rules you will use for your project.

You can get more information about the configuration on [Datadog documentation](https://docs.datadoghq.com/code_analysis/static_analysis/setup/).

### Mac OS X users

The binary cannot be executed as is. You need to flag the binary as safe to execute using the following command.

```shell
xattr -dr com.apple.quarantine datadog-static-analyzer
```

## Options

 - `-f` or `--format`: format of the output file. `-f sarif` produces a [SARIF-compliant file](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif)
 - `-r` or `--rules`: provides a file that contains all rules (rules can be put in a file using `datadog-export-rulesets`)
 - `-c` or `--cpus`: number of cores used to analyze (count about 1GB of RAM usage per core)
 - `-o` or `--output`: output file
 - `-p` or `--ignore-path`: path (pattern/glob) to ignore; accepts multiple
 - `-x` or `--performance-statistics`: show performance statistics for the analyzer
 - `-g` or `--add-git-info`: add Git-related information (sha, etc) into the SARIF report when using -f sarif
 - `--fail-on-any-violation`: make the program exit a non-zero exit code if there is at least one violation of a given severity.

## Configuration

Set the following variables to configure an analysis:

 - `DD_SITE`: the Datadog site parameter used to fetch rules ([view list](https://docs.datadoghq.com/getting_started/site/)) (default: `datadoghq.com`)

## Configuration file

The static analyzer can be configured using a `static-analysis.datadog.yml` file
at the root directory of the repository. This is a YAML file with the following entries:

- `rulesets`: (required) a list with all the rulesets to use for this repository (see [Datadog Documentation](https://docs.datadoghq.com/code_analysis/static_analysis_rules) for a full list). The elements of this list must be strings or maps containing a configuration for a ruleset (described below.)
- `ignore`: (optional) a list of path prefixes and glob patterns to ignore. A file that matches any of its entries will not be analyzed.
- `only`: (optional) a list of path prefixes and glob patterns to analyze. If `only` is specified, only files that match one of its entries will be analyzed.
- `ignore-gitignore`: (optional) if true, the entries found in the `.gitignore` file will be added to the `ignore` list.
- `max-file-size-kb`: (optional) files larger than this size, in kilobytes, will be ignored. The default value is 200 kB.
- `schema-version`: (optional) the version of the schema that this configuration file follows. If specified, it must be `v1`.

The entries of the `rulesets` list must be strings that contain the name of a ruleset to enable, or a map that contains the configuration for a ruleset. This map contains the following fields:

- the first field (required) gives the ruleset name as its key, with an empty value.
- `ignore`: (optional) a list of path prefixes and glob patterns to ignore _for this ruleset_. Rules in this ruleset will not be evaluated for any files that match any of the entries in the `ignore` list.
- `only`: (optional) a list of path prefixes and glob patterns to analyze _for this ruleset_. If `only` is specified, rules in this ruleset will only be evaluated for files that match one of the entries.
- `rules`: (optional) a map of rule configurations. Rules not specified in this map will still be evaluated, but with their default configuration.

The map in the `rules` field uses the rule's name as its key, and the values are maps with the following fields:

- `ignore` (optional) a list of path prefixes and glob patterns to ignore _for this rule_. This rule will not be evaluated for any files that match any of the entries in the `ignore` list.
- `only`: (optional) a list of path prefixes and glob patterns to analyze _for this rule_. If `only` is specified, this rule will only be evaluated for files that match one of the entries.

An annotated example of a configuration file:

```yaml
# This is a "v1" configuration file.
schema-version: v1
# The list of rulesets to enable for this repository.
rulesets:
  # Enable the `python-code-style ruleset` with the default configuration.
  - python-code-style
  # Enable the `python-best-practices` ruleset with a custom configuration.
  - python-best-practices:
    # Do not apply any of the rules in this ruleset to files that match `src/**/*.generated.py`.
    ignore:
      - src/**/*.generated.py
    rules:
      # Special configuration for the `python-best-practices/no-generic-exception` rule.
      no-generic-exception:
        # Only apply this rule to files under the `src/new-code` subtree.
        only:
          - src/new-code
  # Enable the `python-inclusive` ruleset with the default configuration.
  - python-inclusive
# Analyze only files in the `src` and `imported` subtrees.
only:
  - src
  - imported
# Do not analyze any files in the `src/tests` subtree.
ignore:
  - src/tests
# Do not add the content of the `.gitignore` file to the `ignore` list.
ignore-gitignore: false
# Do not analyze files larger than 100 kB.
max-file-size-kb: 100
```

Another example that shows every option being used:

```yaml
schema-version: v1
rulesets:
  - python-code-style
  - python-best-practices:
    ignore:
      - src/generated
      - src/**/*_test.py
    only:
      - src
      - imported/**/new/**
    rules:
      no-generic-exception:
        ignore:
          - src/new-code
          - src/new/*.gen.py
        only:
          - src/new
          - src/**/new-code/**
ignore:
  - dist
  - lib/**/*.py
only:
  - src
  - imported/**/*.py
ignore-gitignore: true
max-file-size-kb: 256
```

## Configuration file schema

There is a JSON Schema definition for the `static-analysis.datadog.yml` in the `schema` subdirectory.

You can use it to check the syntax of your configuration file:

1. Install https://www.npmjs.com/package/pajv (`npm install -g pajv`)
2. Execute `pajv validate -s schema/schema.json -d path/to/your/static-analysis.datadog.yml`

There are some examples of valid and invalid configuration files in the [`schema/examples/valid`](schema/examples/valid)
and [`schema/examples/invalid`](schema/examples/invalid) subdirectories, respectively. If you make changes to the JSON
Schema, you can test them against our examples:

1. Install https://www.npmjs.com/package/pajv (`npm install -g pajv`)
2. Execute `make -C schema`

## Other Tools

### datadog-export-rulesets

Export rulesets from the API into a file

```shell
cargo run --bin datadog-export-rulesets -- -r <ruleset> -o <file-to-export>
```

## Contribute

See file [CONTRIBUTING.md](CONTRIBUTING.md) for more information as well as [DEVELOPMENT.md](DEVELOPMENT.md)
for all details about testing and coding guidelines.

## More information

 - [Datadog Static Analysis](https://docs.datadoghq.com/code_analysis/static_analysis)
