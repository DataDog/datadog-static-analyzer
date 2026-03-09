# Legacy Configuration File
The static analyzer has backwards-compatible support for the legacy `static-analysis.datadog.yml` configuration file,
which has a different schema and semantics than the current configuration schema (See: [Configuration file](https://github.com/DataDog/datadog-static-analyzer?tab=readme-ov-file#configuration-file)).

Users may continue to use their `static-analysis.datadog.yml` configuration file with no disruptions or behavior
changes. A migration tool will be provided in the future.

Documentation for this format has been saved below for reference:

---

## Legacy Schema Reference

The static analyzer can be configured using a `static-analysis.datadog.yml` file
at the root directory of the repository. This is a YAML file with the following entries:

- `rulesets`: (required) a list with all the rulesets to use for this repository (see [Datadog Documentation](https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/) for a full list). The elements of this list must be strings or maps containing a configuration for a ruleset (described below.)
- `ignore`: (optional) a list of path prefixes and glob patterns to ignore. A file that matches any of its entries will not be analyzed.
- `only`: (optional) a list of path prefixes and glob patterns to analyze. If `only` is specified, only files that match one of its entries will be analyzed.
- `ignore-gitignore`: (optional) by default, any entries found in the `.gitignore` file are added to the `ignore` list. If the `ignore-gitignore` option is true, the `.gitignore` file is not read.
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
- `severity`: (optional) if provided, override the severity of violations produced by this rule. The valid severities are `ERROR`, `WARNING`, `NOTICE`, and `NONE`.
- `category`: (optional) if provided, override this rule's category. The valid categories are `BEST_PRACTICES`, `CODE_STYLE`, `ERROR_PRONE`, `PERFORMANCE`, and `SECURITY`.
- `arguments`: (optional) a map of values for the rule's arguments.

The map in the `arguments` field uses an argument's name as its key, and the values are either strings or maps:

- if you want to set a value for the whole repository, you can specify it as a string;
- if you want to set different values for different subtrees in the repository, you can specify them as a map from a subtree prefix to the value that the argument will have within that subtree. See the example for more details.

An annotated example of a configuration file:

```yaml
# The list of rulesets to enable for this repository.
rulesets:
  # Enable the `python-inclusive` ruleset with the default configuration.
  - python-inclusive
  # Enable the `python-best-practices` ruleset with a custom configuration.
  - python-best-practices:
    # Do not apply any of the rules in this ruleset to files that match `src/**/*.generated.py`.
    ignore:
      - src/**/*.generated.py
    rules:
      # Special configuration for the `python-best-practices/no-generic-exception` rule.
      no-generic-exception:
        # Treat violations of this rule as errors (normally "notice").
        severity: ERROR
        # Classify violations of this rule under the "code style" category.
        category: CODE_STYLE
        # Only apply this rule to files under the `src/new-code` subtree.
        only:
          - src/new-code
  # Enable the `python-code-style ruleset` with a custom configuration.
  - python-code-style:
    rules:
      max-function-lines:
        # Set arguments for the `python-code-style/max-function-lines` rule.
        arguments:
          # Set the `max-lines` argument to 150 in the whole repository.
          max-lines: 150
      max-class-lines:
        # Set arguments for the `python-code-style/max-class-lines` rule.
        arguments:
          # Set different values for the `max-lines` argument in different subtrees.
          max-lines:
            # Set the `max-lines` argument to 100 by default
            /: 100
            # Set the `max-lines` argument to 75 under the `src/new-code` subtree.
            src/new-code: 75
# Analyze only files in the `src` and `imported` subtrees.
only:
  - src
  - imported
# Do not analyze any files in the `src/tests` subtree.
ignore:
  - src/tests
# Do not add the content of the `.gitignore` file to the `ignore` list.
ignore-gitignore: true
# Do not analyze files larger than 100 kB.
max-file-size-kb: 100
```

Another example that shows every option being used:

```yaml
schema-version: v1
rulesets:
  - python-best-practices
  - python-code-style:
    ignore:
      - src/generated
      - src/**/*_test.py
    only:
      - src
      - imported/**/new/**
    rules:
      max-function-lines:
        severity: WARNING
        category: PERFORMANCE
        ignore:
          - src/new-code
          - src/new/*.gen.py
        only:
          - src/new
          - src/**/new-code/**
        arguments:
          max-lines: 150
          min-lines:
            /: 10
            src/new-code: 0
ignore:
  - dist
  - lib/**/*.py
only:
  - src
  - imported/**/*.py
ignore-gitignore: true
max-file-size-kb: 256
```
