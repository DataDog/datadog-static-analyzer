## Diff-Aware Scanning

> [!WARNING]
> Diff-Aware Scanning if a feature available to Datadog users.
> Learn more on [Datadog Static Analysis](https://docs.datadoghq.com/code_analysis/static_analysis/setup/).


The static analyzer provides a way to perform diff-aware scans, which means
that a run only scans the files that have been changed. Instead of scanning
the full repository, you only scan the files that have been changed since
the last scan.


### Principles

Imagine you have a repository with 15000 files that takes 10 minutes to analyze.
Your initial analysis is done at a time T1 and the analysis takes 10 minutes. A few hours later, 
you create a feature a branch, edit 10 files, commit and push. When the analysis
runs on your feature branch at time T2, it analyzes the changes being done between
your feature branch and the default branch, detects only 10 files have been added/modified/deleted
and analyzes only these files. By analyzing 10 files, the analysis lasts less than 5 seconds
instead of 10 minutes.



```
           ______________________
         /       ^           feature branch
        /        T2
 ------------------------------------------>
     ^                               main
    T1                  
```

### How it works?

When the flag `--diff-aware` (or `-w` for the short option) is passed to the analyzer,
the analyzer queries Datadog backend to check if previous scans results can be used.
If previous results are found, the backend returns the list of files to analyze
and the static analyzer only analyzes those files. If previous results cannot be found,
the analyzer does a full scan.

By only analyzing the files that changed, the duration of the scan is drastically reduced,
resulting in shorter time to feedback (faster pull requests comments) and infrastructure
savings.

### Constraints

To use diff-aware scanning, you must be a Datadog user and configure the 
following environment variables

 - `DD_APP_KEY`: your Datadog Application Key
 - `DD_API_KEY`: your Datadog API key
 - `DD_SITE`: your Datadog site (see [here](https://docs.datadoghq.com/getting_started/site/) for more information)


Before a scan, your git metadata must be sent to Datadog servers by using the 
[datadog-ci](https://github.com/DataDog/datadog-ci) program and invoking the following command:


```shell
datadog-ci git-metadata upload
```

Once the metadata are uploaded, run `datadog-static-analyzer` and make sure you are using
the flag `--diff-aware`. The analyzer will then show if a diff-aware scan is used (or not).


### Run Example

Below is the trace of a successful diff-aware scan.

```shell
$ datadog-static-analyzer --directory /path/to/scan --diff-aware --output /path/to/report.sarif --format sarif
[...]
diff-aware enabled, based sha 6d4781e6c7ddaadae123cc92a38b9c1bfa148574, scanning only 24/4251 files
[...]
```

### Troubleshooting

> [!NOTE]
> Diff-Aware Scanning must find a scan with a similar configuration. If a new ruleset is used or a new rule
> has been published, a full scan will be performed.

If the `--diff-aware` option is specified and diff-aware is not possible, the static analyzer will produce similar to
the trace below.

```shell
$ datadog-static-analyzer --directory /path/to/scan --diff-aware --output /path/to/report.sarif --format sarif
[...]
diff aware not enabled (error when receiving diff-aware data from Datadog with config hash XX, sha XXX), proceeding with full scan.
```

Common causes are:
 - there was no first scan performed with this configuration
 - environment variables `DD_API_KEY`, `DD_APP_KEY` or `DD_SITE` are not specified or invalid
 - new rulesets are being used
