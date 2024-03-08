## Generating the SARIF output file is slow
 
This can occur is you are using the option `-g` and generate a SARIF file. The `-g` option
attempts to get the last commit for a file/line. In some case, git can be very slow and the
generation of the file can take a long time.

If you try to generate a SARIF file with the `-g` and have a slow file generation, consider
trying without the `-g` flag.

## How to make the analyzer exit if there is at least one violation?

Use the `--fail-on-any-violation` option.

To make the analyzer exit if there is at least one violation at any level, use the following command

```shell
datadog-static-analyzer --directory /path/to/code -o results.json -f sarif --fail-on-any-violation=none,notice,warning,error
```

To exit only if you have a violation with error, use:

```shell
datadog-static-analyzer --directory /path/to/code -o results.json -f sarif --fail-on-any-violation=error
```

## Do you support Alpine Linux/musl libc?

If you tried to run the analyzer on Alpine and/or got the following error:

```
Error relocating /lib/ld-linux-x86-64.so.2: unsupported relocation
```

it means you are not using glibc. Unfortunately, we do not support Alpine Linux
at this time. We plan to support it in the future, the issue is tracked [here](https://github.com/DataDog/datadog-static-analyzer/issues/245).


## How to produce a CSV file?

Use the `--format csv` option like this

```shell
datadog-static-analyzer --directory /path/to/code -o results.csv -f csv
```

## I do not see an answer to my question

Please ask your question in the [discussions section](https://github.com/DataDog/datadog-static-analyzer/discussions).
