## Report an issue

This document outlines how to report an issue for the static analyzer and
ensure that your bug report is complete with all required information.

> [!TIP]
> If you are a Datadog customer, send the bug report with all information
> to your customer success manager.

### What to send with your report

When sending a bug report, make sure to include
 - your `static-analysis.datadog.yml` file
 - the output of the tool (e.g. CLI) when running either locally or in your CI/CD pipeline
 - the SARIF file being produced (if any and available)
 - the URL of your repository (even if private, it helps to troubleshoot)
 - the exact command line used to run the analyzer

### Performance issues

If you are experiencing performance issues, enable the flag `--performance-statistics` when
running the tool from the command line.

When sending the report, make sure to include:
 - your `static-analysis.datadog.yml`
 - the output of the tool
 - the URL of your repository

> [!IMPORTANT]
> If you are using the [GitHub Action](https://github.com/DataDog/datadog-static-analyzer-github-action)
> just turn on the option `enable_performance_statistics` to `true`.

### Blocking issues

If the static analyzer fails to exit or you have a major issue that is not related to performance,
run the analyzer with the following flags: `--debug true --performance-statistics`.

